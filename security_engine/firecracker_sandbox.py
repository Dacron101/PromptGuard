"""
security_engine/firecracker_sandbox.py

FirecrackerSandbox — Firecracker microVM lifecycle manager.
───────────────────────────────────────────────────────────
Encapsulates all interactions with the Firecracker hypervisor:

  1. Spawn the `firecracker` process with a unique Unix API socket.
  2. Configure the VM (kernel, rootfs, network interface, machine resources)
     via REST API calls over the Unix socket.
  3. Start the VM instance.
  4. Execute arbitrary commands inside the VM over SSH.
  5. Terminate the VM and clean up all artefacts.

This class is used by `DeepScanVerifier` to install packages inside an
isolated microVM and observe their behaviour before allowing them on the
host machine.

Host prerequisites
──────────────────
Firecracker VMs need a TAP network device on the host. Run once per host:

    sudo ip tuntap add tap0 mode tap
    sudo ip addr add 172.16.0.1/24 dev tap0
    sudo ip link set tap0 up

This sets up the host-side networking that the VM bridges to. ClaudeGuard
does NOT do this automatically because it requires root privileges.

Usage:
    with FirecrackerSandbox(vm_ip="172.16.0.2", virustotal_key="...") as vm:
        vm.start()
        result = vm.run_install_test("requests", "pip")
"""

import io
import json
import logging
import os
import shlex
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from typing import IO, Optional, Tuple

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Install command templates per package manager
# Files are installed into /tmp/pkg_test so they can be found for VT scanning.
# ─────────────────────────────────────────────────────────────────────────────
_INSTALL_COMMANDS: dict[str, str] = {
    "pip":   "pip3 install --target /tmp/pkg_test {pkg}",
    "npm":   "npm install --prefix /tmp/pkg_test {pkg}",
    "yarn":  "yarn add --modules-folder /tmp/pkg_test {pkg}",
    "cargo": "cargo install {pkg} --root /tmp/pkg_test",
    "go":    "GOPATH=/tmp/pkg_test go get {pkg}",
    "brew":  "brew install {pkg}",
}

# Paths inside the VM to watch for suspicious writes *after* install.
# A legitimate package should never touch these locations.
_SUSPICIOUS_PATHS = [
    "/root/.ssh",
    "/etc/cron.d",
    "/etc/crontab",
    "/tmp/.hidden",
    "/var/spool/cron",
    "/etc/profile.d",
    "/etc/rc.local",
]

# How long to wait for the Firecracker API socket to appear after process spawn
_SOCKET_WAIT_TIMEOUT = 5.0   # seconds
_SOCKET_POLL_INTERVAL = 0.1  # seconds


@dataclass
class SandboxResult:
    """
    Result of running a package install test inside the Firecracker VM.

    Attributes:
        install_exit_code  : Exit code of the install command (0 = success).
        install_stdout     : Standard output from the install.
        install_stderr     : Standard error from the install.
        suspicious_files   : List of files written to suspicious locations.
        virustotal_output  : Raw JSON output from check_virustotal.py.
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
        kernel_path   : Path to the vmlinux kernel image on the host.
        rootfs_path   : Path to the rootfs.ext4 image on the host.
        vm_ip         : IP address assigned to the VM guest (e.g. 172.16.0.2).
        host_ip       : IP address of the TAP device on the host (e.g. 172.16.0.1).
        tap_device    : Name of the host-side TAP network device (e.g. tap0).
        guest_mac     : MAC address to assign to the VM's eth0 interface.
        ssh_key_path  : Path to the SSH private key for root@ login.
        virustotal_key: VirusTotal API v3 key. Injected into the VM environment
                        so check_virustotal.py can submit files.
        vcpu_count    : Number of virtual CPUs for the VM.
        mem_size_mib  : Memory allocation in MiB.
        startup_wait  : Maximum seconds to wait for the Firecracker API socket
                        to appear after spawning the process.
        ssh_timeout   : Timeout in seconds for individual SSH commands.
        socket_path   : Override for the API socket path. Defaults to a unique
                        path under /tmp to prevent conflicts when multiple
                        sandbox instances run concurrently.
    """

    def __init__(
        self,
        kernel_path: str = "./vmlinux",
        rootfs_path: str = "./rootfs.ext4",
        vm_ip: str = "172.16.0.2",
        host_ip: str = "172.16.0.1",
        tap_device: str = "tap0",
        guest_mac: str = "AA:FC:00:00:00:01",
        ssh_key_path: Optional[str] = None,
        virustotal_key: Optional[str] = None,
        vcpu_count: int = 1,
        mem_size_mib: int = 256,
        startup_wait: float = _SOCKET_WAIT_TIMEOUT,
        ssh_timeout: int = 60,
        socket_path: Optional[str] = None,
    ) -> None:
        # Use a unique socket path per instance to prevent conflicts
        self._socket_path = socket_path or f"/tmp/firecracker-{uuid.uuid4().hex[:8]}.socket"
        self._kernel_path = kernel_path
        self._rootfs_path = rootfs_path
        self._vm_ip = vm_ip
        self._host_ip = host_ip
        self._tap_device = tap_device
        self._guest_mac = guest_mac
        self._ssh_key_path = ssh_key_path
        self._virustotal_key = virustotal_key
        self._vcpu_count = vcpu_count
        self._mem_size_mib = mem_size_mib
        self._startup_wait = startup_wait
        self._ssh_timeout = ssh_timeout

        # Boot args configure the VM kernel with static IP directly —
        # no DHCP client needed in the rootfs.
        self._boot_args = (
            f"console=ttyS0 reboot=k panic=1 pci=off "
            f"ip={vm_ip}::{host_ip}:255.255.255.0::eth0:off"
        )

        self._process: Optional[subprocess.Popen] = None
        self._log_file: Optional[IO[str]] = None

    # ── Context manager ───────────────────────────────────────────────────────

    def __enter__(self) -> "FirecrackerSandbox":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self) -> None:
        """
        Launch the Firecracker process and boot the microVM.

        Steps:
          1. Remove any stale API socket from a previous run.
          2. Spawn the `firecracker` binary with --api-sock.
          3. Poll until the socket file appears (not a blind sleep).
          4. Configure boot source (kernel + boot args with static IP).
          5. Configure root drive (rootfs).
          6. Configure network interface (TAP device → VM eth0).
          7. Configure machine resources (vCPUs, RAM).
          8. Send InstanceStart action.
          9. Wait for the VM to boot and SSH to become available.

        Raises:
            FileNotFoundError  : If the `firecracker` binary is not on PATH.
            RuntimeError       : If the Firecracker API rejects any config call,
                                 or if the VM doesn't boot within the timeout.
        """
        # ── Step 1: Clean up stale socket ─────────────────────────────────────
        if os.path.exists(self._socket_path):
            os.remove(self._socket_path)
            logger.debug("Removed stale socket: %s", self._socket_path)

        # ── Step 2: Spawn firecracker process ─────────────────────────────────
        # FileNotFoundError propagates to the caller (DeepScanVerifier) if the
        # `firecracker` binary is not installed.
        log_path = f"/tmp/firecracker-{os.path.basename(self._socket_path)}.log"
        self._log_file = open(log_path, "w")
        self._process = subprocess.Popen(
            ["firecracker", "--api-sock", self._socket_path],
            stdout=self._log_file,
            stderr=subprocess.STDOUT,
        )
        logger.info(
            "Firecracker started (PID %d) | socket=%s log=%s",
            self._process.pid, self._socket_path, log_path,
        )

        # ── Step 3: Poll for socket file instead of blind sleep ───────────────
        # The original implementation used time.sleep(startup_wait) which is
        # unreliable — the socket may appear in <100ms or take several seconds
        # depending on host load. Polling is more reliable and faster.
        self._wait_for_socket()

        # ── Steps 4–7: Configure VM via REST API ──────────────────────────────
        self._configure_boot_source()
        self._configure_root_drive()
        self._configure_network()   # ← Was missing — VM has no network without this
        self._configure_machine()

        # ── Step 8: Start the VM instance ─────────────────────────────────────
        self._api_put("/actions", {"action_type": "InstanceStart"})
        logger.info("Firecracker VM instance started")

        # ── Step 9: Wait for SSH to become available ───────────────────────────
        self._wait_for_ssh()

    def run_command(self, cmd: str) -> Tuple[str, str, int]:
        """
        Execute a command inside the Firecracker VM via SSH.

        Args:
            cmd : Shell command to run inside the VM.

        Returns:
            Tuple of (stdout, stderr, exit_code).
            On SSH timeout, returns ("", "SSH command timed out", -1).
        """
        ssh_args = self._build_ssh_args(cmd)
        logger.debug("SSH exec: %s", cmd)

        try:
            result = subprocess.run(
                ssh_args,
                capture_output=True,
                text=True,
                timeout=self._ssh_timeout,
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            logger.error("SSH timed out after %ds: %s", self._ssh_timeout, cmd)
            return "", "SSH command timed out", -1

    def run_install_test(
        self,
        package_name: str,
        package_manager: str,
    ) -> SandboxResult:
        """
        Install a package inside the VM and analyse the results.

        Pipeline:
          1. Snapshot suspicious filesystem paths (before install).
          2. Run the install command for the given package manager.
          3. Snapshot suspicious paths again (after install) and diff.
          4. Run check_virustotal.py on newly installed files.
          5. Return aggregated SandboxResult.

        Args:
            package_name    : The package to test-install.
            package_manager : Normalised manager string (pip, npm, etc.).

        Returns:
            SandboxResult with install output and analysis findings.
        """
        result = SandboxResult()

        # ── Step 1: Pre-install filesystem snapshot ────────────────────────────
        pre_snapshot = self._snapshot_suspicious_paths()

        # ── Step 2: Run the install command ───────────────────────────────────
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

        # ── Step 3: Post-install snapshot + diff ──────────────────────────────
        post_snapshot = self._snapshot_suspicious_paths()
        new_suspicious = set(post_snapshot) - set(pre_snapshot)
        result.suspicious_files = sorted(new_suspicious)

        if new_suspicious:
            logger.warning(
                "Package '%s' wrote to suspicious paths: %s",
                package_name, new_suspicious,
            )
            result.is_suspicious = True

        # ── Step 4: VirusTotal scan on installed files ────────────────────────
        vt_output = self._run_virustotal_scan()
        result.virustotal_output = vt_output

        if "malicious" in vt_output.lower() or "suspicious" in vt_output.lower():
            result.is_suspicious = True

        logger.info(
            "Install test done | pkg=%s exit=%d suspicious=%s",
            package_name, exit_code, result.is_suspicious,
        )
        return result

    def stop(self) -> None:
        """Terminate the Firecracker process and clean up all resources."""
        if self._process is not None:
            try:
                self._process.terminate()
                self._process.wait(timeout=5)
                logger.info("Firecracker terminated (PID %d)", self._process.pid)
            except subprocess.TimeoutExpired:
                self._process.kill()
                logger.warning("Firecracker killed (PID %d)", self._process.pid)
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

        Uses `curl --unix-socket` to avoid adding `requests-unixsocket` as a
        dependency. The `--fail` flag causes curl to exit with code 22 on any
        HTTP 4xx/5xx response, which we convert into a RuntimeError so config
        errors are never silently swallowed.

        Returns:
            Parsed JSON response body (empty dict on HTTP 204 No Content).

        Raises:
            RuntimeError : If the Firecracker API returns a non-2xx status.
            RuntimeError : If the curl call times out.
        """
        url = f"http://localhost{endpoint}"
        json_data = json.dumps(payload)

        try:
            result = subprocess.run(
                [
                    "curl", "--silent", "--show-error", "--fail",
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
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Firecracker API call timed out: PUT {endpoint}")

        if result.returncode != 0:
            raise RuntimeError(
                f"Firecracker API PUT {endpoint} failed "
                f"(curl exit {result.returncode}): "
                f"{result.stderr.strip() or result.stdout.strip()}"
            )

        logger.debug("API PUT %s ← %s", endpoint, result.stdout[:200] or "204 No Content")

        if result.stdout.strip():
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                return {"raw": result.stdout}
        return {}

    def _configure_boot_source(self) -> None:
        """Configure the VM kernel and boot arguments via the Firecracker API."""
        self._api_put("/boot-source", {
            "kernel_image_path": self._kernel_path,
            "boot_args": self._boot_args,
        })
        logger.debug("Boot source configured: kernel=%s", self._kernel_path)

    def _configure_root_drive(self) -> None:
        """Configure the rootfs block device via the Firecracker API."""
        self._api_put("/drives/rootfs", {
            "drive_id": "rootfs",
            "path_on_host": self._rootfs_path,
            "is_root_device": True,
            "is_read_only": False,
        })
        logger.debug("Root drive configured: %s", self._rootfs_path)

    def _configure_network(self) -> None:
        """
        Configure the VM's network interface via the Firecracker API.

        This bridges the VM's eth0 to the host TAP device, enabling SSH access.
        Without this call, the VM boots with NO network — SSH will never work.

        The host must have the TAP device set up beforehand:
            sudo ip tuntap add tap0 mode tap
            sudo ip addr add 172.16.0.1/24 dev tap0
            sudo ip link set tap0 up
        """
        self._api_put("/network-interfaces/eth0", {
            "iface_id": "eth0",
            "host_dev_name": self._tap_device,
            "guest_mac": self._guest_mac,
        })
        logger.debug(
            "Network configured: tap=%s guest_mac=%s vm_ip=%s",
            self._tap_device, self._guest_mac, self._vm_ip,
        )

    def _configure_machine(self) -> None:
        """Configure the VM machine resources via the Firecracker API."""
        self._api_put("/machine-config", {
            "vcpu_count": self._vcpu_count,
            "mem_size_mib": self._mem_size_mib,
            "ht_enabled": False,
        })
        logger.debug(
            "Machine config: vcpus=%d mem=%dMiB",
            self._vcpu_count, self._mem_size_mib,
        )

    # ── Private: startup helpers ──────────────────────────────────────────────

    def _wait_for_socket(self) -> None:
        """
        Poll until the Firecracker API socket file appears.

        This replaces the original blind `time.sleep(startup_wait)` which was
        both too slow on fast hosts and potentially too fast on loaded ones.

        Raises:
            RuntimeError : If the socket does not appear within the timeout.
        """
        deadline = time.monotonic() + self._startup_wait
        while not os.path.exists(self._socket_path):
            if time.monotonic() > deadline:
                raise RuntimeError(
                    f"Firecracker API socket did not appear at "
                    f"'{self._socket_path}' within {self._startup_wait}s. "
                    "Check vm.log for Firecracker errors."
                )
            time.sleep(_SOCKET_POLL_INTERVAL)
        logger.debug("Firecracker API socket is ready: %s", self._socket_path)

    def _wait_for_ssh(
        self,
        max_retries: int = 15,
        initial_delay: float = 0.5,
        max_delay: float = 8.0,
    ) -> None:
        """
        Poll until the VM's SSH port is reachable, using exponential backoff.

        The original implementation used a fixed 2s delay (10 × 2s = 20s worst
        case). Exponential backoff from 0.5s lets fast boots through in ~1s
        while still waiting up to ~2 minutes for slow ones.

        Args:
            max_retries   : Number of SSH attempts before giving up.
            initial_delay : Starting sleep duration in seconds.
            max_delay     : Maximum sleep duration (backoff cap).
        """
        delay = initial_delay
        for attempt in range(1, max_retries + 1):
            stdout, _, code = self.run_command("echo ready")
            if code == 0 and "ready" in stdout:
                logger.info("VM SSH ready (attempt %d/%d)", attempt, max_retries)
                return
            logger.debug(
                "SSH not ready (attempt %d/%d), retrying in %.1fs…",
                attempt, max_retries, delay,
            )
            time.sleep(delay)
            delay = min(delay * 2, max_delay)  # exponential backoff with cap

        logger.warning(
            "SSH did not become ready after %d attempts. "
            "Proceeding anyway — commands may fail.",
            max_retries,
        )

    # ── Private: SSH helpers ──────────────────────────────────────────────────

    def _build_ssh_args(self, cmd: str) -> list[str]:
        """
        Build the SSH command-line arguments for executing a command in the VM.

        Uses -o BatchMode=yes to prevent SSH from prompting for passwords, and
        -o ConnectTimeout to keep each attempt bounded.
        """
        args = [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "BatchMode=yes",
            "-o", f"ConnectTimeout={min(self._ssh_timeout, 10)}",
            "-o", "LogLevel=ERROR",
        ]
        if self._ssh_key_path:
            args.extend(["-i", self._ssh_key_path])
        args.extend([f"root@{self._vm_ip}", cmd])
        return args

    # ── Private: analysis helpers ─────────────────────────────────────────────

    def _snapshot_suspicious_paths(self) -> list[str]:
        """
        List all files under suspicious paths inside the VM.
        Returns a sorted list of absolute file paths.
        """
        all_files: list[str] = []
        for path in _SUSPICIOUS_PATHS:
            stdout, _, code = self.run_command(
                f"find {shlex.quote(path)} -type f 2>/dev/null || true"
            )
            if code == 0 and stdout.strip():
                all_files.extend(stdout.strip().splitlines())
        return sorted(all_files)

    @staticmethod
    def _build_install_command(package_name: str, package_manager: str) -> Optional[str]:
        """Build the sandboxed install command for the given package manager."""
        template = _INSTALL_COMMANDS.get(package_manager.lower())
        if template is None:
            return None
        return template.format(pkg=shlex.quote(package_name))

    def _run_virustotal_scan(self) -> str:
        """
        Run check_virustotal.py inside the VM against installed package files.

        Scans up to 10 files from /tmp/pkg_test. The VirusTotal API key is
        injected as an environment variable inline in the SSH command so it
        is available to the script without persisting it in the rootfs.

        Returns the combined stdout from all VT scan calls (JSON lines), or
        an empty string if no files were found or VT key is not configured.
        """
        if not self._virustotal_key:
            logger.debug("No VT API key configured — skipping VirusTotal scan")
            return ""

        stdout, _, code = self.run_command(
            "find /tmp/pkg_test -type f 2>/dev/null | head -20"
        )
        if code != 0 or not stdout.strip():
            logger.debug("No installed files found for VirusTotal scan")
            return ""

        files = stdout.strip().splitlines()
        vt_results: list[str] = []
        # Sanitise the VT key: it should only contain alphanumeric chars
        safe_key = shlex.quote(self._virustotal_key)

        for filepath in files[:10]:  # Cap at 10 to stay within API rate limits
            safe_path = shlex.quote(filepath.strip())
            scan_cmd = (
                f"VT_API_KEY={safe_key} "
                f"python3 /usr/local/bin/check_virustotal.py {safe_path}"
            )
            scan_stdout, _, scan_code = self.run_command(scan_cmd)
            if scan_stdout.strip():
                vt_results.append(scan_stdout.strip())
                logger.debug("VT result for %s: %s", filepath, scan_stdout[:200])

        combined = "\n".join(vt_results)
        return combined
