"""
tests/integration/pipeline_scenarios.py

Realistic end-to-end pipeline test scenarios for ClaudeGuard.
─────────────────────────────────────────────────────────────
These tests exercise the full stack:

    Claude Code output text
        → CommandDetector   (regex)
        → SecurityChecker   (strategy chain)
        → BasicVerifier     (allowlist + heuristics)
        → DeepScanVerifier  (Firecracker mock)
        → VerificationResult (verdict)

No real Firecracker VM or network is needed. FirecrackerSandbox is mocked
at the boundary so the rest of the pipeline runs for real.

Run with:
    python -m pytest tests/integration/pipeline_scenarios.py -v

Or run a single scenario:
    python tests/integration/pipeline_scenarios.py
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from interceptor.command_detector import CommandDetector
from security_engine.base import RiskLevel
from security_engine.basic_verifier import BasicVerifier
from security_engine.checker import SecurityChecker
from security_engine.deep_scan_verifier import DeepScanVerifier
from security_engine.firecracker_sandbox import SandboxResult


# ─────────────────────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_deep_scan_verifier(sandbox_result: SandboxResult) -> DeepScanVerifier:
    """
    Build a DeepScanVerifier whose FirecrackerSandbox is fully mocked.
    The sandbox will return `sandbox_result` from run_install_test().
    """
    mock_instance = MagicMock()
    mock_instance.run_install_test.return_value = sandbox_result
    mock_instance.__enter__ = MagicMock(return_value=mock_instance)
    mock_instance.__exit__ = MagicMock(return_value=False)

    verifier = DeepScanVerifier(virustotal_key="test-vt-key")
    # Patch the class so any FirecrackerSandbox() construction returns our mock
    verifier._sandbox_factory = lambda **_: mock_instance
    return verifier, mock_instance


def _run_pipeline(
    pty_output: str,
    deep_scan_result: SandboxResult | None = None,
) -> list[dict]:
    """
    Simulate the full ClaudeGuard pipeline for a chunk of PTY output.

    Args:
        pty_output        : Raw text as it would arrive from Claude Code's PTY.
        deep_scan_result  : If provided, a DeepScanVerifier backed by this
                            mocked sandbox result is added as fallback.

    Returns:
        List of result dicts, one per detected package:
            {
                "manager":   str,
                "package":   str,
                "is_safe":   bool,
                "risk":      str,
                "reason":    str,
                "verifier":  str,   # which verifier produced the verdict
            }
    """
    detector = CommandDetector()
    detected = detector.detect(pty_output)

    if not detected:
        return []

    if deep_scan_result is not None:
        # Patch FirecrackerSandbox at the class level for this call
        mock_sb = MagicMock()
        mock_sb.run_install_test.return_value = deep_scan_result
        mock_sb.__enter__ = MagicMock(return_value=mock_sb)
        mock_sb.__exit__ = MagicMock(return_value=False)

        with patch("security_engine.deep_scan_verifier.FirecrackerSandbox", return_value=mock_sb):
            fallback = DeepScanVerifier(virustotal_key="test-vt-key")
            checker = SecurityChecker(
                primary_verifier=BasicVerifier(),
                fallback_verifier=fallback,
            )
            results = []
            for cmd in detected:
                r = checker.check(cmd.package_name, cmd.manager)
                results.append({
                    "manager":  cmd.manager,
                    "package":  cmd.package_name,
                    "is_safe":  r.is_safe,
                    "risk":     r.risk_level.value,
                    "reason":   r.reason,
                    "metadata": r.metadata,
                })
    else:
        checker = SecurityChecker(primary_verifier=BasicVerifier())
        results = []
        for cmd in detected:
            r = checker.check(cmd.package_name, cmd.manager)
            results.append({
                "manager":  cmd.manager,
                "package":  cmd.package_name,
                "is_safe":  r.is_safe,
                "risk":     r.risk_level.value,
                "reason":   r.reason,
                "metadata": r.metadata,
            })

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 1 — Trusted package: should pass immediately
# ─────────────────────────────────────────────────────────────────────────────

class ScenarioTrustedPackage(unittest.TestCase):
    """
    Claude Code installs a well-known, trusted package.
    Expected: BasicVerifier allowlist hit → SAFE, no deep scan needed.
    """

    PTY_OUTPUT = (
        "\x1b[32m✔\x1b[0m Running bash command\n"
        "  $ pip install requests\n"
        "\x1b[2mExecuting…\x1b[0m\n"
    )

    def test_requests_is_allowed(self):
        results = _run_pipeline(self.PTY_OUTPUT)

        self.assertEqual(len(results), 1)
        pkg = results[0]
        self.assertEqual(pkg["package"], "requests")
        self.assertEqual(pkg["manager"], "pip")
        self.assertTrue(pkg["is_safe"])
        self.assertEqual(pkg["risk"], RiskLevel.SAFE.value)

    def test_npm_react_is_allowed(self):
        output = "  $ npm install react react-dom\n"
        results = _run_pipeline(output)

        self.assertEqual(len(results), 2)
        for r in results:
            self.assertTrue(r["is_safe"], f"Expected {r['package']} to be safe")
            self.assertEqual(r["risk"], RiskLevel.SAFE.value)

    def test_multi_package_pip_all_trusted(self):
        output = "  $ pip install flask sqlalchemy pydantic\n"
        results = _run_pipeline(output)

        self.assertEqual(len(results), 3)
        packages = {r["package"] for r in results}
        self.assertEqual(packages, {"flask", "sqlalchemy", "pydantic"})
        for r in results:
            self.assertTrue(r["is_safe"])


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 2 — Typosquatted package: blocked by BasicVerifier heuristics
# ─────────────────────────────────────────────────────────────────────────────

class ScenarioTyposquattedPackage(unittest.TestCase):
    """
    Claude Code hallucinates a typo'd package name (classic supply-chain attack).
    Expected: BasicVerifier heuristic match → SUSPICIOUS, blocked immediately.
    """

    def test_reqqests_typosquat_blocked(self):
        output = "  $ pip install reqqests\n"
        results = _run_pipeline(output)

        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertFalse(r["is_safe"])
        self.assertEqual(r["risk"], RiskLevel.SUSPICIOUS.value)
        self.assertIn("typosquat", r["reason"].lower())

    def test_lo0dash_typosquat_blocked(self):
        output = "  $ npm install lo0dash\n"
        results = _run_pipeline(output)

        r = results[0]
        self.assertFalse(r["is_safe"])
        self.assertEqual(r["risk"], RiskLevel.SUSPICIOUS.value)

    def test_malware_keyword_blocked(self):
        """Package names containing malware-family keywords are blocked."""
        output = "  $ pip install pycryptominer\n"
        results = _run_pipeline(output)

        r = results[0]
        self.assertFalse(r["is_safe"])
        self.assertEqual(r["risk"], RiskLevel.SUSPICIOUS.value)

    def test_very_short_name_blocked(self):
        """Single-letter or two-letter names are high-risk (common attack vector)."""
        output = "  $ npm install xy\n"
        results = _run_pipeline(output)

        r = results[0]
        self.assertFalse(r["is_safe"])
        self.assertEqual(r["risk"], RiskLevel.SUSPICIOUS.value)


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 3 — Unknown package escalated to deep scan → clean
# ─────────────────────────────────────────────────────────────────────────────

class ScenarioUnknownPackageDeepScanClean(unittest.TestCase):
    """
    Claude Code installs a real but niche package not in the allowlist.
    BasicVerifier returns UNKNOWN; DeepScanVerifier (mocked Firecracker)
    installs it in a sandbox, finds no issues → SAFE.
    """

    CLEAN_SANDBOX_RESULT = SandboxResult(
        install_exit_code=0,
        install_stdout="Successfully installed httpie-3.2.2\n",
        install_stderr="",
        suspicious_files=[],
        virustotal_output='{"status": "clean", "malicious": 0, "undetected": 68}',
        is_suspicious=False,
    )

    def test_unknown_package_passes_deep_scan(self):
        output = "  $ pip install httpie\n"
        results = _run_pipeline(output, deep_scan_result=self.CLEAN_SANDBOX_RESULT)

        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertTrue(r["is_safe"], f"Expected SAFE but got: {r['reason']}")
        self.assertEqual(r["risk"], RiskLevel.SAFE.value)
        self.assertEqual(r["metadata"].get("sandbox_engine"), "firecracker")

    def test_unknown_npm_package_passes_deep_scan(self):
        # "concurrently" is a popular but niche npm package not in the allowlist.
        # It's long enough to pass the short-name heuristic → UNKNOWN → deep scan.
        output = "  $ npm install concurrently\n"
        results = _run_pipeline(output, deep_scan_result=self.CLEAN_SANDBOX_RESULT)

        r = results[0]
        self.assertTrue(r["is_safe"], f"Expected SAFE but got: {r['reason']}")
        self.assertEqual(r["metadata"].get("sandbox_engine"), "firecracker")


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 4 — Unknown package escalated to deep scan → malicious behaviour
# ─────────────────────────────────────────────────────────────────────────────

class ScenarioUnknownPackageDeepScanMalicious(unittest.TestCase):
    """
    An unknown package is installed in the Firecracker sandbox.
    It writes to ~/.ssh/authorized_keys (credential-hijacking attempt).
    Expected: MALICIOUS verdict, install blocked.
    """

    SSH_HIJACK_RESULT = SandboxResult(
        install_exit_code=0,
        install_stdout="Installing…\n",
        install_stderr="",
        suspicious_files=[
            "/root/.ssh/authorized_keys",
            "/root/.ssh/known_hosts",
        ],
        virustotal_output="",
        is_suspicious=True,
    )

    def test_ssh_key_write_produces_malicious(self):
        output = "  $ pip install totally-legit-sdk\n"
        results = _run_pipeline(output, deep_scan_result=self.SSH_HIJACK_RESULT)

        r = results[0]
        self.assertFalse(r["is_safe"])
        self.assertEqual(r["risk"], RiskLevel.MALICIOUS.value)
        self.assertIn("/root/.ssh/authorized_keys", r["reason"])

    def test_malicious_metadata_contains_suspicious_files(self):
        output = "  $ pip install totally-legit-sdk\n"
        results = _run_pipeline(output, deep_scan_result=self.SSH_HIJACK_RESULT)

        suspicious = results[0]["metadata"].get("suspicious_files", [])
        self.assertIn("/root/.ssh/authorized_keys", suspicious)


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 5 — VirusTotal flags installed files
# ─────────────────────────────────────────────────────────────────────────────

class ScenarioVirusTotalFlag(unittest.TestCase):
    """
    The package installs cleanly (no suspicious path writes), but VirusTotal
    flags one of the installed files as malicious.
    Expected: MALICIOUS verdict from the VT signal alone.
    """

    VT_FLAGGED_RESULT = SandboxResult(
        install_exit_code=0,
        install_stdout="Installed.\n",
        install_stderr="",
        suspicious_files=[],
        virustotal_output=(
            '{"file": "/tmp/pkg_test/evil/__init__.py", '
            '"status": "malicious", "malicious": 7, "undetected": 54}'
        ),
        is_suspicious=True,
    )

    def test_virustotal_malicious_blocks_package(self):
        output = "  $ pip install suspiciously-clean-pkg\n"
        results = _run_pipeline(output, deep_scan_result=self.VT_FLAGGED_RESULT)

        r = results[0]
        self.assertFalse(r["is_safe"])
        self.assertEqual(r["risk"], RiskLevel.MALICIOUS.value)
        self.assertIn("VirusTotal", r["reason"])

    def test_virustotal_suspicious_rating(self):
        """VT 'suspicious' (not fully malicious) yields SUSPICIOUS verdict."""
        output = "  $ pip install grey-area-pkg\n"
        result = SandboxResult(
            install_exit_code=0,
            suspicious_files=[],
            virustotal_output='{"status": "suspicious", "suspicious": 3, "malicious": 0}',
        )
        results = _run_pipeline(output, deep_scan_result=result)

        r = results[0]
        self.assertFalse(r["is_safe"])
        self.assertEqual(r["risk"], RiskLevel.SUSPICIOUS.value)


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 6 — Package install fails inside sandbox
# ─────────────────────────────────────────────────────────────────────────────

class ScenarioInstallFailure(unittest.TestCase):
    """
    The package name resolves but fails to install (corrupted package,
    removed from registry, or intentionally broken malware dropper).
    Expected: SUSPICIOUS verdict — a failing install is a red flag.
    """

    FAILED_INSTALL_RESULT = SandboxResult(
        install_exit_code=1,
        install_stdout="",
        install_stderr="ERROR: Could not find a version that satisfies the requirement ghost-pkg",
        suspicious_files=[],
        virustotal_output="",
        is_suspicious=False,
    )

    def test_failed_install_is_suspicious(self):
        output = "  $ pip install ghost-pkg\n"
        results = _run_pipeline(output, deep_scan_result=self.FAILED_INSTALL_RESULT)

        r = results[0]
        self.assertFalse(r["is_safe"])
        self.assertEqual(r["risk"], RiskLevel.SUSPICIOUS.value)
        self.assertIn("exit code 1", r["reason"])


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 7 — Mixed batch: safe + blocked in same PTY chunk
# ─────────────────────────────────────────────────────────────────────────────

class ScenarioMixedBatch(unittest.TestCase):
    """
    Claude Code's output contains multiple install commands in one chunk —
    some trusted, some not. Each package is verified independently.
    """

    def test_safe_and_blocked_in_same_chunk(self):
        output = (
            "  $ pip install requests\n"
            "  $ pip install reqqests\n"   # typosquat
            "  $ pip install flask\n"
        )
        results = _run_pipeline(output)

        by_pkg = {r["package"]: r for r in results}
        self.assertTrue(by_pkg["requests"]["is_safe"])
        self.assertFalse(by_pkg["reqqests"]["is_safe"])
        self.assertEqual(by_pkg["reqqests"]["risk"], RiskLevel.SUSPICIOUS.value)
        self.assertTrue(by_pkg["flask"]["is_safe"])

    def test_multi_manager_same_chunk(self):
        """Different package managers in one output chunk all get checked."""
        output = (
            "  $ npm install react\n"
            "  $ pip install numpy\n"
            "  $ cargo add serde\n"
        )
        results = _run_pipeline(output)

        self.assertEqual(len(results), 3)
        managers = {r["manager"] for r in results}
        self.assertEqual(managers, {"npm", "pip", "cargo"})
        for r in results:
            self.assertTrue(r["is_safe"], f"{r['package']} should be safe")


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 8 — ANSI escape codes in PTY output (real Claude Code output)
# ─────────────────────────────────────────────────────────────────────────────

class ScenarioAnsiOutput(unittest.TestCase):
    """
    Claude Code's real terminal output is heavily decorated with ANSI escape
    codes (colour, cursor movement, bold). The detector must strip these
    before attempting regex matching.
    """

    def test_detection_through_ansi_colour_codes(self):
        output = (
            "\x1b[1;32m❯\x1b[0m \x1b[36mRunning\x1b[0m "
            "\x1b[33mpip install requests\x1b[0m\n"
        )
        results = _run_pipeline(output)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["package"], "requests")
        self.assertTrue(results[0]["is_safe"])

    def test_detection_with_bold_and_underline(self):
        output = "\x1b[1m$ npm install \x1b[4mlodash\x1b[0m\n"
        results = _run_pipeline(output)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["package"], "lodash")

    def test_no_false_positive_on_plain_text(self):
        """Lines that mention package names without install commands are ignored."""
        output = (
            "The requests library is already installed.\n"
            "Checking if numpy needs updating…\n"
        )
        results = _run_pipeline(output)
        self.assertEqual(len(results), 0)


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 9 — Version-pinned install commands
# ─────────────────────────────────────────────────────────────────────────────

class ScenarioVersionPinnedInstalls(unittest.TestCase):
    """
    Install commands with explicit version pins should still be detected and
    the base package name (without version) should be verified.
    """

    def test_pip_version_pin(self):
        output = "  $ pip install requests==2.31.0\n"
        results = _run_pipeline(output)

        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertEqual(r["package"], "requests")
        self.assertTrue(r["is_safe"])

    def test_npm_scoped_package_with_version(self):
        output = "  $ npm install @types/node@18.0.0\n"
        results = _run_pipeline(output)

        self.assertEqual(len(results), 1)

    def test_go_get_with_version(self):
        output = "  $ go get github.com/gin-gonic/gin@v1.9.0\n"
        results = _run_pipeline(output)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["package"], "github.com/gin-gonic/gin")

    def test_cargo_add_with_features(self):
        output = "  $ cargo add serde --features derive\n"
        results = _run_pipeline(output)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["package"], "serde")
        self.assertTrue(results[0]["is_safe"])


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 10 — Firecracker sandbox unavailable (graceful degradation)
# ─────────────────────────────────────────────────────────────────────────────

class ScenarioFirecrackerUnavailable(unittest.TestCase):
    """
    The user runs ClaudeGuard on a machine without Firecracker installed, or
    the VM fails to boot. The system must degrade gracefully:
      - FileNotFoundError → blocked with UNKNOWN, clear error message
      - RuntimeError      → blocked with UNKNOWN, error surfaced in metadata
    """

    def _run_with_fc_error(self, exc: Exception, output: str) -> dict:
        mock_sb = MagicMock()
        mock_sb.__enter__ = MagicMock(side_effect=exc)
        mock_sb.__exit__ = MagicMock(return_value=False)

        with patch("security_engine.deep_scan_verifier.FirecrackerSandbox", return_value=mock_sb):
            fallback = DeepScanVerifier()
            checker = SecurityChecker(
                primary_verifier=BasicVerifier(),
                fallback_verifier=fallback,
            )
            detected = CommandDetector().detect(output)
            return checker.check(detected[0].package_name, detected[0].manager)

    def test_missing_firecracker_binary_blocks_unknown_package(self):
        result = self._run_with_fc_error(
            FileNotFoundError("No such file: firecracker"),
            "  $ pip install unknown-niche-pkg\n",
        )
        self.assertFalse(result.is_safe)
        self.assertEqual(result.risk_level, RiskLevel.UNKNOWN)
        self.assertEqual(result.metadata["error"], "firecracker_not_found")

    def test_vm_boot_failure_blocks_unknown_package(self):
        result = self._run_with_fc_error(
            RuntimeError("KVM not available on this host"),
            "  $ pip install another-unknown-pkg\n",
        )
        self.assertFalse(result.is_safe)
        self.assertEqual(result.risk_level, RiskLevel.UNKNOWN)
        self.assertIn("error", result.metadata)

    def test_missing_firecracker_does_not_affect_trusted_packages(self):
        """Trusted packages should be allowed by BasicVerifier even if FC is broken."""
        result = self._run_with_fc_error(
            FileNotFoundError("No firecracker"),
            "  $ pip install requests\n",
        )
        # BasicVerifier hits allowlist first — FC is never called for trusted packages
        self.assertTrue(result.is_safe)
        self.assertEqual(result.risk_level, RiskLevel.SAFE)


# ─────────────────────────────────────────────────────────────────────────────
# Manual runner — pretty-print all scenario results
# ─────────────────────────────────────────────────────────────────────────────

def _print_pipeline_demo():
    """
    Run a curated set of scenarios and print coloured results to stdout.
    Useful for quick manual verification without pytest.
    """
    from security_engine.firecracker_sandbox import SandboxResult

    RESET  = "\033[0m"
    GREEN  = "\033[32m"
    RED    = "\033[31m"
    YELLOW = "\033[33m"
    CYAN   = "\033[36m"
    BOLD   = "\033[1m"

    demo_cases = [
        # (label, pty_output, deep_scan_result or None)
        (
            "Trusted pip package",
            "  $ pip install requests\n",
            None,
        ),
        (
            "Trusted npm package",
            "  $ npm install react --save\n",
            None,
        ),
        (
            "Typosquat blocked by heuristic",
            "  $ pip install reqqests\n",
            None,
        ),
        (
            "Unknown package — deep scan clean",
            "  $ pip install httpie\n",
            SandboxResult(
                install_exit_code=0,
                install_stdout="Installed httpie 3.2.2\n",
                suspicious_files=[],
                virustotal_output='{"status":"clean","malicious":0}',
            ),
        ),
        (
            "Unknown package — SSH key hijack detected",
            "  $ pip install totally-legit-sdk\n",
            SandboxResult(
                install_exit_code=0,
                suspicious_files=["/root/.ssh/authorized_keys"],
                virustotal_output="",
                is_suspicious=True,
            ),
        ),
        (
            "Unknown package — VirusTotal flags malicious file",
            "  $ pip install backdoor-as-a-service\n",
            SandboxResult(
                install_exit_code=0,
                suspicious_files=[],
                virustotal_output='{"status":"malicious","malicious":12}',
                is_suspicious=True,
            ),
        ),
        (
            "ANSI-decorated output (real Claude Code format)",
            "\x1b[1;32m❯\x1b[0m \x1b[36mRunning\x1b[0m \x1b[33mpip install flask\x1b[0m\n",
            None,
        ),
        (
            "Mixed batch — safe + typosquat",
            "  $ pip install requests\n  $ pip install reqqests\n",
            None,
        ),
    ]

    print(f"\n{BOLD}{'─'*65}{RESET}")
    print(f"{BOLD}  ClaudeGuard — Pipeline Integration Demo{RESET}")
    print(f"{BOLD}{'─'*65}{RESET}\n")

    for label, pty_output, deep_scan in demo_cases:
        results = _run_pipeline(pty_output, deep_scan_result=deep_scan)
        print(f"{CYAN}Scenario:{RESET} {label}")

        if not results:
            print(f"  {YELLOW}No install commands detected{RESET}\n")
            continue

        for r in results:
            icon  = f"{GREEN}✓" if r["is_safe"] else f"{RED}✗"
            color = GREEN if r["is_safe"] else RED
            print(
                f"  {icon} [{r['manager']}] {r['package']:30s} "
                f"{color}{r['risk'].upper():12s}{RESET} "
                f"│ {r['reason'][:55]}"
            )
        print()

    print(f"{BOLD}{'─'*65}{RESET}\n")


if __name__ == "__main__":
    _print_pipeline_demo()
    print("Running unittest suite…\n")
    unittest.main(argv=[""], exit=False, verbosity=2)
