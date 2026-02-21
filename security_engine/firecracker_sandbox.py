"""
security_engine/firecracker_sandbox.py

FirecrackerSandbox — Firecracker microVM lifecycle manager.
───────────────────────────────────────────────────────────
Encapsulates all interactions with the Firecracker hypervisor:

  1. Spawn the `firecracker` process with a Unix API socket.
  2. Configure the VM (kernel, rootfs, machine resources) via REST API.
  3. Start the VM instance.
  4. Execute arbitrary commands inside the VM over SSH.
  5. Terminate the VM and clean up all artefacts.

This class is used by `DeepScanVerifier` to install packages inside an
isolated microVM and observe their behaviour before allowing them on the
host machine.

Usage:
    with FirecrackerSandbox(vm_ip="172.16.0.2") as sandbox:
        sandbox.start()
        stdout, stderr, code = sandbox.run_command("pip install requests")
        result = sandbox.run_install_test("requests", "pip")
"""

import json
import logging
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Install command templates per package manager
# ─────────────────────────────────────────────────────────────────────────────
_INSTALL_COMMANDS: dict[str, str] = {
    "pip":   "pip3 install --target /tmp/pkg_test {pkg}",
    "npm":   "npm install --prefix /tmp/pkg_test {pkg}",
    "yarn":  "yarn add --modules-folder /tmp/pkg_test {pkg}",
    "cargo": "cargo install {pkg} --root /tmp/pkg_test",
    "go":    "GOPATH=/tmp/pkg_test go get {pkg}",
    "brew":  "brew install {pkg}",
}

# Paths inside the VM to watch for suspicious writes after install
_SUSPICIOUS_PATHS = [
    "/root/.ssh",
    "/etc/cron.d",
    "/etc/crontab",
    "/tmp/.hidden",
    "/var/spool/cron",
]


@dataclass
class SandboxResult:
    """
    Result of running a package install test inside the Firecracker VM.

    Attributes:
        install_exit_code  : Exit code of the install command (0 = success).
        install_stdout     : Standard output from the install.
        install_stderr     : Standard error from the install.
        suspicious_files   : List of files written to suspicious locations.
        virustotal_output  : Raw output from check_virustotal run on installed files.
        is_suspicious      : True if any red flags were found.
    """
    install_exit_code: int = -1
    install_stdout: str = ""
    install_stderr: str = ""
    suspicious_files: list[str] = field(default_factory=list)
    virustotal_output: str = ""
    is_suspicious: bool = False


class FirecrackerSandbox:
    """
    Manages the full lifecycle of a Firecracker microVM for package sandboxing.

    Args:
        socket_path   : Path for the Firecracker API Unix socket.
        kernel_path   : Path to the vmlinux kernel image on the host.
        rootfs_path   : Path to the rootfs.ext4 image on the host.
        vm_ip         : IP address assigned to the VM (for SSH access).
        ssh_key_path  : Path to the SSH private key for root@vm.
        vcpu_count    : Number of virtual CPUs for the VM.
        mem_size_mib  : Memory allocation in MiB.
        boot_args     : Kernel boot arguments.
        startup_wait  : Seconds to wait after starting Firecracker before
                        sending API calls.
        ssh_timeout   : Timeout in seconds for SSH commands.
    """

    def __init__(
        self,
        socket_path: str = "/tmp/firecracker.socket",
        kernel_path: str = "./vmlinux",
        rootfs_path: str = "./rootfs.ext4",
        vm_ip: str = "172.16.0.2",
        ssh_key_path: Optional[str] = None,
        vcpu_count: int = 1,
        mem_size_mib: int = 256,
        boot_args: str = "console=ttyS0 reboot=k panic=1 pci=off",
        startup_wait: float = 1.0,
        ssh_timeout: int = 60,
    ) -> None:
        self._socket_path = socket_path
        self._kernel_path = kernel_path
        self._rootfs_path = rootfs_path
        self._vm_ip = vm_ip
        self._ssh_key_path = ssh_key_path
        self._vcpu_count = vcpu_count
        self._mem_size_mib = mem_size_mib
        self._boot_args = boot_args
        self._startup_wait = startup_wait
        self._ssh_timeout = ssh_timeout

        self._process: Optional[subprocess.Popen] = None
        self._log_file: Optional[object] = None

    # ── Context manager ───────────────────────────────────────────────────────

    def __enter__(self) -> "FirecrackerSandbox":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self) -> None:
        """
        Launch the Firecracker process and configure the microVM.

        Steps:
          1. Remove any stale API socket.
          2. Spawn the `firecracker` binary with --api-sock.
          3. Wait for the process to initialise.
          4. Configure boot source (kernel), root drive, and machine config
             via PUT requests to the Unix socket API.
          5. Send InstanceStart action.
          6. Wait for the VM to boot and become SSH-accessible.
        """
        # ── Step 1: Clean up stale socket ─────────────────────────────────────
        if os.path.exists(self._socket_path):
            os.remove(self._socket_path)
            logger.debug("Removed stale socket: %s", self._socket_path)

        # ── Step 2: Start firecracker process ─────────────────────────────────
        self._log_file = open("vm.log", "w")
        self._process = subprocess.Popen(
            ["firecracker", "--api-sock", self._socket_path],
            stdout=self._log_file,
            stderr=subprocess.STDOUT,
        )
        logger.info(
            "Firecracker started (PID %d), socket: %s",
            self._process.pid, self._socket_path,
        )

        # ── Step 3: Wait for API socket to appear ─────────────────────────────
        time.sleep(self._startup_wait)

        # ── Step 4: Configure VM via API ──────────────────────────────────────
        self._configure_boot_source()
        self._configure_root_drive()
        self._configure_machine()

        # ── Step 5: Start the VM instance ─────────────────────────────────────
        self._api_put("/actions", {"action_type": "InstanceStart"})
        logger.info("Firecracker VM instance started")

        # ── Step 6: Wait for SSH to become available ──────────────────────────
        self._wait_for_ssh()

    def run_command(self, cmd: str) -> Tuple[str, str, int]:
        """
        Execute a command inside the Firecracker VM via SSH.

        Args:
            cmd : Shell command to execute inside the VM.

        Returns:
            Tuple of (stdout, stderr, exit_code).
        """
        ssh_args = self._build_ssh_args(cmd)
        logger.debug("SSH command: %s", " ".join(ssh_args))

        try:
            result = subprocess.run(
                ssh_args,
                capture_output=True,
                text=True,
                timeout=self._ssh_timeout,
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            logger.error("SSH command timed out after %ds: %s", self._ssh_timeout, cmd)
            return "", "SSH command timed out", -1

    def run_install_test(
        self,
        package_name: str,
        package_manager: str,
    ) -> SandboxResult:
        """
        Install a package inside the VM and analyse the results.

        Steps:
          1. Snapshot suspicious filesystem paths (before install).
          2. Run the install command for the given package manager.
          3. Snapshot suspicious paths again (after install) and diff.
          4. Run check_virustotal on any newly created files.
          5. Return aggregated SandboxResult.

        Args:
            package_name    : The package to test-install.
            package_manager : Normalised manager string (pip, npm, etc.).

        Returns:
            SandboxResult with install output and analysis findings.
        """
        result = SandboxResult()

        # ── Step 1: Pre-install snapshot ──────────────────────────────────────
        pre_snapshot = self._snapshot_suspicious_paths()

        # ── Step 2: Run the install ───────────────────────────────────────────
        install_cmd = self._build_install_command(package_name, package_manager)
        if install_cmd is None:
            result.install_stderr = f"Unsupported package manager: {package_manager}"
            result.install_exit_code = 1
            result.is_suspicious = True
            return result

        logger.info("Running install test: %s", install_cmd)
        stdout, stderr, exit_code = self.run_command(install_cmd)
        result.install_stdout = stdout
        result.install_stderr = stderr
        result.install_exit_code = exit_code

        # ── Step 3: Post-install diff ─────────────────────────────────────────
        post_snapshot = self._snapshot_suspicious_paths()
        new_suspicious = set(post_snapshot) - set(pre_snapshot)
        result.suspicious_files = list(new_suspicious)

        if new_suspicious:
            logger.warning(
                "Suspicious files created during install: %s", new_suspicious
            )
            result.is_suspicious = True

        # ── Step 4: VirusTotal scan on installed files ────────────────────────
        vt_output = self._run_virustotal_scan(package_name, package_manager)
        result.virustotal_output = vt_output

        if "malicious" in vt_output.lower() or "suspicious" in vt_output.lower():
            result.is_suspicious = True

        logger.info(
            "Install test complete: pkg=%s exit_code=%d suspicious=%s",
            package_name, exit_code, result.is_suspicious,
        )
        return result

    def stop(self) -> None:
        """
        Terminate the Firecracker process and clean up resources.
        """
        if self._process is not None:
            try:
                self._process.terminate()
                self._process.wait(timeout=5)
                logger.info("Firecracker process terminated (PID %d)", self._process.pid)
            except subprocess.TimeoutExpired:
                self._process.kill()
                logger.warning("Firecracker process killed (PID %d)", self._process.pid)
            except ProcessLookupError:
                logger.debug("Firecracker process already exited")
            finally:
                self._process = None

        if self._log_file is not None:
            try:
                self._log_file.close()
            except Exception:
                pass
            self._log_file = None

        if os.path.exists(self._socket_path):
            os.remove(self._socket_path)
            logger.debug("Cleaned up socket: %s", self._socket_path)

    # ── Private: Firecracker API ──────────────────────────────────────────────

    def _api_put(self, endpoint: str, payload: dict) -> dict:
        """
        Send a PUT request to the Firecracker API via the Unix socket.

        Uses curl as a subprocess to talk to the Unix socket, avoiding the
        need for requests-unixsocket as a dependency.
        """
        url = f"http://localhost{endpoint}"
        json_data = json.dumps(payload)

        try:
            result = subprocess.run(
                [
                    "curl", "--silent", "--show-error",
                    "--unix-socket", self._socket_path,
                    "-X", "PUT",
                    "-H", "Content-Type: application/json",
                    "-d", json_data,
                    url,
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            logger.debug(
                "API PUT %s → status=%d, response=%s",
                endpoint, result.returncode, result.stdout[:200],
            )
            if result.stdout:
                try:
                    return json.loads(result.stdout)
                except json.JSONDecodeError:
                    return {"raw": result.stdout}
            return {}
        except subprocess.TimeoutExpired:
            logger.error("API call timed out: PUT %s", endpoint)
            return {"error": "timeout"}

    def _configure_boot_source(self) -> None:
        """Configure the VM kernel via the Firecracker API."""
        self._api_put("/boot-source", {
            "kernel_image_path": self._kernel_path,
            "boot_args": self._boot_args,
        })
        logger.debug("Boot source configured: %s", self._kernel_path)

    def _configure_root_drive(self) -> None:
        """Configure the rootfs drive via the Firecracker API."""
        self._api_put("/drives/rootfs", {
            "drive_id": "rootfs",
            "path_on_host": self._rootfs_path,
            "is_root_device": True,
            "is_read_only": False,
        })
        logger.debug("Root drive configured: %s", self._rootfs_path)

    def _configure_machine(self) -> None:
        """Configure the VM machine resources via the Firecracker API."""
        self._api_put("/machine-config", {
            "vcpu_count": self._vcpu_count,
            "mem_size_mib": self._mem_size_mib,
            "ht_enabled": False,
        })
        logger.debug(
            "Machine config: %d vCPU, %d MiB RAM",
            self._vcpu_count, self._mem_size_mib,
        )

    # ── Private: SSH helpers ──────────────────────────────────────────────────

    def _build_ssh_args(self, cmd: str) -> list[str]:
        """Build the SSH command-line arguments for executing a command in the VM."""
        args = [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", f"ConnectTimeout={min(self._ssh_timeout, 10)}",
            "-o", "LogLevel=ERROR",
        ]
        if self._ssh_key_path:
            args.extend(["-i", self._ssh_key_path])

        args.extend([f"root@{self._vm_ip}", cmd])
        return args

    def _wait_for_ssh(self, max_retries: int = 10, delay: float = 2.0) -> None:
        """
        Poll until the VM's SSH port is reachable, with exponential backoff.
        """
        for attempt in range(1, max_retries + 1):
            stdout, stderr, code = self.run_command("echo ready")
            if code == 0 and "ready" in stdout:
                logger.info("VM SSH is ready (attempt %d/%d)", attempt, max_retries)
                return
            logger.debug(
                "SSH not ready (attempt %d/%d), retrying in %.1fs…",
                attempt, max_retries, delay,
            )
            time.sleep(delay)

        logger.warning("SSH did not become ready after %d retries", max_retries)

    # ── Private: Analysis helpers ─────────────────────────────────────────────

    def _snapshot_suspicious_paths(self) -> list[str]:
        """
        List all files under suspicious paths inside the VM.
        Returns a list of absolute file paths found.
        """
        all_files: list[str] = []
        for path in _SUSPICIOUS_PATHS:
            stdout, _, code = self.run_command(
                f"find {path} -type f 2>/dev/null || true"
            )
            if code == 0 and stdout.strip():
                all_files.extend(stdout.strip().splitlines())
        return all_files

    @staticmethod
    def _build_install_command(
        package_name: str,
        package_manager: str,
    ) -> Optional[str]:
        """Build the install command for the given package manager."""
        template = _INSTALL_COMMANDS.get(package_manager.lower())
        if template is None:
            return None
        return template.format(pkg=package_name)

    def _run_virustotal_scan(
        self,
        package_name: str,
        package_manager: str,
    ) -> str:
        """
        Run check_virustotal inside the VM against the installed package files.

        Looks for newly installed files in /tmp/pkg_test and submits them
        to the VirusTotal scanner that's pre-deployed in the rootfs.
        """
        # List files installed into the test directory
        stdout, _, code = self.run_command(
            "find /tmp/pkg_test -type f 2>/dev/null | head -20"
        )
        if code != 0 or not stdout.strip():
            logger.debug("No installed files found for VirusTotal scan")
            return ""

        files = stdout.strip().splitlines()
        vt_results: list[str] = []

        for filepath in files[:10]:  # Scan up to 10 files to stay within API limits
            scan_stdout, scan_stderr, scan_code = self.run_command(
                f"python3 /usr/local/bin/check_virustotal.py {filepath}"
            )
            if scan_stdout.strip():
                vt_results.append(scan_stdout.strip())

        combined = "\n".join(vt_results)
        logger.debug("VirusTotal scan results: %s", combined[:500])
        return combined
