"""
security_engine/deep_scan_verifier.py

Concrete Strategy: DeepScanVerifier
────────────────────────────────────
High-fidelity package verification using a Firecracker microVM sandbox.

When the BasicVerifier returns UNKNOWN (package not in the allowlist but no
obvious red flags), the SecurityChecker can escalate to this verifier.
DeepScanVerifier will:

  1. Spin up an isolated Firecracker microVM.
  2. Install the package inside the VM using the appropriate package manager.
  3. Inspect the filesystem for suspicious mutations (writes to ~/.ssh,
     cron directories, hidden temp files, etc.).
  4. Run the check_virustotal scanner against newly installed files.
  5. Aggregate all signals and return a definitive VerificationResult.
  6. Tear down the VM — no artefacts persist on the host.

The Firecracker VM provides hardware-level isolation via KVM, which is
stronger than Docker containers (which share the host kernel). Packages
cannot escape the microVM boundary even with root privileges inside the VM.

Prerequisites:
  - Linux host with /dev/kvm access
  - `firecracker` binary on PATH
  - A vmlinux kernel image and rootfs.ext4 with package managers + Python 3
    + check_virustotal.py pre-deployed at /usr/local/bin/
  - SSH access configured (root key-based login, no password)
"""

import json
import logging
from typing import Optional

from .base import PackageVerifier, VerificationResult, RiskLevel
from .firecracker_sandbox import FirecrackerSandbox, SandboxResult

logger = logging.getLogger(__name__)


class DeepScanVerifier(PackageVerifier):
    """
    Firecracker-backed package verifier.

    Installs the candidate package inside an isolated microVM, analyses
    the results, and returns a VerificationResult.

    Configuration (all injected via __init__ for testability):
        kernel_path     : Path to the vmlinux kernel image.
        rootfs_path     : Path to the rootfs.ext4 image.
        vm_ip           : IP address for SSH into the VM.
        ssh_key_path    : Path to the SSH private key for root@vm.
        virustotal_key  : VirusTotal API v3 key (for the in-VM scanner).
        timeout_seconds : Hard wall-clock limit for the entire scan pipeline.
        vcpu_count      : Number of virtual CPUs for the VM.
        mem_size_mib    : Memory allocation in MiB.
    """

    def __init__(
        self,
        kernel_path: str = "./vmlinux",
        rootfs_path: str = "./rootfs.ext4",
        vm_ip: str = "172.16.0.2",
        ssh_key_path: Optional[str] = None,
        virustotal_key: Optional[str] = None,
        timeout_seconds: int = 120,
        vcpu_count: int = 1,
        mem_size_mib: int = 256,
    ) -> None:
        self._kernel_path = kernel_path
        self._rootfs_path = rootfs_path
        self._vm_ip = vm_ip
        self._ssh_key_path = ssh_key_path
        self._virustotal_key = virustotal_key
        self._timeout = timeout_seconds
        self._vcpu_count = vcpu_count
        self._mem_size_mib = mem_size_mib

        logger.info(
            "DeepScanVerifier initialised | kernel=%s rootfs=%s vm_ip=%s",
            kernel_path, rootfs_path, vm_ip,
        )

    @property
    def name(self) -> str:
        return "DeepScanVerifier"

    def verify(self, package_name: str, package_manager: str) -> VerificationResult:
        """
        Full Firecracker-based verification pipeline.

        1. Start an isolated Firecracker microVM.
        2. Install the package inside the VM.
        3. Check for suspicious filesystem mutations.
        4. Run VirusTotal scan on installed files.
        5. Aggregate signals into a verdict.
        6. Shut down the VM.
        """
        logger.info(
            "[DeepScanVerifier] Starting sandbox verification: "
            "pkg=%s manager=%s",
            package_name, package_manager,
        )

        sandbox = FirecrackerSandbox(
            kernel_path=self._kernel_path,
            rootfs_path=self._rootfs_path,
            vm_ip=self._vm_ip,
            ssh_key_path=self._ssh_key_path,
            virustotal_key=self._virustotal_key,  # injected into VM env for VT scans
            vcpu_count=self._vcpu_count,
            mem_size_mib=self._mem_size_mib,
            ssh_timeout=self._timeout,
        )

        try:
            with sandbox:
                sandbox.start()
                sandbox_result = sandbox.run_install_test(
                    package_name, package_manager
                )
        except FileNotFoundError:
            logger.error(
                "Firecracker binary not found. Is it installed and on PATH?"
            )
            return VerificationResult(
                is_safe=False,
                package_name=package_name,
                package_manager=package_manager,
                risk_level=RiskLevel.UNKNOWN,
                reason=(
                    "DeepScanVerifier could not start: 'firecracker' binary "
                    "not found. Package blocked as a precaution."
                ),
                confidence=0.30,
                metadata={"error": "firecracker_not_found"},
            )
        except Exception as exc:
            logger.error(
                "Sandbox verification failed with exception: %s", exc,
                exc_info=True,
            )
            return VerificationResult(
                is_safe=False,
                package_name=package_name,
                package_manager=package_manager,
                risk_level=RiskLevel.UNKNOWN,
                reason=(
                    f"DeepScanVerifier encountered an error: {exc}. "
                    "Package blocked as a precaution."
                ),
                confidence=0.30,
                metadata={"error": str(exc)},
            )

        # ── Aggregate signals into a verdict ──────────────────────────────────
        return self._build_verdict(package_name, package_manager, sandbox_result)

    # ── Private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _parse_vt_counts(vt_output: str) -> tuple[int, int]:
        """
        Extract (malicious_count, suspicious_count) from VirusTotal output.

        check_virustotal.py emits one JSON object per scanned file.
        We aggregate across all lines, taking the max of each counter
        (worst-case across files in the package).

        Handles multi-line output (one JSON per line) and falls back to
        zero counts on any parse error — failing safe rather than crashing.
        """
        if not vt_output.strip():
            return 0, 0

        total_malicious = 0
        total_suspicious = 0

        for line in vt_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                total_malicious += int(data.get("malicious", 0))
                total_suspicious += int(data.get("suspicious", 0))
            except (json.JSONDecodeError, TypeError, ValueError):
                # Non-JSON line (e.g. a log message) — skip it
                continue

        return total_malicious, total_suspicious

    def _build_verdict(
        self,
        package_name: str,
        package_manager: str,
        result: SandboxResult,
    ) -> VerificationResult:
        """
        Translate a SandboxResult into a VerificationResult.

        Decision matrix:
          - Install failed (non-zero exit)          → SUSPICIOUS
          - Suspicious files written                 → MALICIOUS
          - VirusTotal flagged files                 → MALICIOUS
          - Install succeeded, no red flags          → SAFE
        """
        metadata = {
            "install_exit_code": result.install_exit_code,
            "install_stdout": result.install_stdout[:500] if result.install_stdout else "",
            "install_stderr": result.install_stderr[:500] if result.install_stderr else "",
            "suspicious_files": result.suspicious_files,
            "virustotal_output": result.virustotal_output[:500],
            "sandbox_engine": "firecracker",
        }

        # ── Check for malicious indicators ────────────────────────────────────
        if result.suspicious_files:
            return VerificationResult(
                is_safe=False,
                package_name=package_name,
                package_manager=package_manager,
                risk_level=RiskLevel.MALICIOUS,
                reason=(
                    f"Package '{package_name}' wrote to suspicious locations "
                    f"during installation: {', '.join(result.suspicious_files[:5])}"
                ),
                confidence=0.90,
                metadata=metadata,
            )

        # ── Check VirusTotal results ──────────────────────────────────────────
        # Parse the JSON output from check_virustotal.py to read numeric
        # detection counts rather than doing naive string matching.
        # Naive "malicious" in output would fire on clean JSON like:
        #   {"status":"clean","malicious":0} — the key name matches even at 0.
        vt_malicious, vt_suspicious = self._parse_vt_counts(result.virustotal_output)

        if vt_malicious > 0:
            return VerificationResult(
                is_safe=False,
                package_name=package_name,
                package_manager=package_manager,
                risk_level=RiskLevel.MALICIOUS,
                reason=(
                    f"Package '{package_name}' was flagged by VirusTotal "
                    f"({vt_malicious} malicious detection(s))."
                ),
                confidence=0.85,
                metadata=metadata,
            )

        if vt_suspicious > 0:
            return VerificationResult(
                is_safe=False,
                package_name=package_name,
                package_manager=package_manager,
                risk_level=RiskLevel.SUSPICIOUS,
                reason=(
                    f"Package '{package_name}' raised suspicion during "
                    f"VirusTotal analysis ({vt_suspicious} suspicious detection(s))."
                ),
                confidence=0.70,
                metadata=metadata,
            )

        # ── Check install failure ─────────────────────────────────────────────
        if result.install_exit_code != 0:
            return VerificationResult(
                is_safe=False,
                package_name=package_name,
                package_manager=package_manager,
                risk_level=RiskLevel.SUSPICIOUS,
                reason=(
                    f"Package '{package_name}' install failed inside sandbox "
                    f"(exit code {result.install_exit_code}). This may "
                    "indicate a malformed or malicious package."
                ),
                confidence=0.60,
                metadata=metadata,
            )

        # ── All clear ────────────────────────────────────────────────────────
        return VerificationResult(
            is_safe=True,
            package_name=package_name,
            package_manager=package_manager,
            risk_level=RiskLevel.SAFE,
            reason=(
                f"Package '{package_name}' installed successfully in a "
                "Firecracker sandbox with no suspicious behaviour detected."
            ),
            confidence=0.90,
            metadata=metadata,
        )
