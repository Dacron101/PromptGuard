"""
tests/test_firecracker_sandbox.py

Unit tests for FirecrackerSandbox and DeepScanVerifier.
Uses mocks — no actual Firecracker binary or VM required.

All subprocess.run / subprocess.Popen calls are patched so tests run
offline and complete in milliseconds. time.sleep is also patched to
prevent 20+ second hangs from the SSH readiness polling loop.
"""

import json
import os
import sys
import unittest
from unittest.mock import MagicMock, call, mock_open, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from security_engine.base import RiskLevel
from security_engine.deep_scan_verifier import DeepScanVerifier
from security_engine.firecracker_sandbox import FirecrackerSandbox, SandboxResult


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_run_side_effect(ssh_ready: bool = True):
    """
    Factory for a subprocess.run side-effect function that differentiates
    between curl API calls and SSH commands.

    - curl calls → return empty body (HTTP 204 success)
    - ssh calls  → return "ready" (or empty if ssh_ready=False)
    """
    def _side_effect(args, **kwargs):
        if args[0] == "curl":
            return MagicMock(returncode=0, stdout="", stderr="")
        elif args[0] == "ssh":
            stdout = "ready" if ssh_ready else ""
            return MagicMock(returncode=0 if ssh_ready else 1, stdout=stdout, stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")
    return _side_effect


# ─────────────────────────────────────────────────────────────────────────────
# TestFirecrackerSandbox
# ─────────────────────────────────────────────────────────────────────────────

class TestFirecrackerSandbox(unittest.TestCase):
    """Tests for the FirecrackerSandbox VM lifecycle manager."""

    @patch("security_engine.firecracker_sandbox.time.sleep")
    @patch("security_engine.firecracker_sandbox.subprocess.Popen")
    @patch("security_engine.firecracker_sandbox.subprocess.run")
    @patch("security_engine.firecracker_sandbox.os.remove")
    @patch("security_engine.firecracker_sandbox.os.path.exists", return_value=True)
    @patch("builtins.open", mock_open())
    def test_start_sends_correct_api_calls(
        self, mock_exists, mock_remove, mock_run, mock_popen, mock_sleep
    ):
        """
        start() should configure boot-source, drives/rootfs, network-interfaces,
        machine-config, and InstanceStart — in that order.
        """
        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_popen.return_value = mock_process

        # curl calls return empty 204; ssh "echo ready" returns "ready"
        mock_run.side_effect = _make_run_side_effect(ssh_ready=True)

        sandbox = FirecrackerSandbox(
            kernel_path="/test/vmlinux",
            rootfs_path="/test/rootfs.ext4",
            vm_ip="192.168.1.100",
            host_ip="192.168.1.1",
            tap_device="tap0",
            socket_path="/tmp/test.socket",
        )
        sandbox.start()

        # ── Verify firecracker process was started ─────────────────────────────
        mock_popen.assert_called_once()
        popen_cmd = mock_popen.call_args[0][0]
        self.assertEqual(popen_cmd[0], "firecracker")
        self.assertIn("--api-sock", popen_cmd)

        # ── Collect all curl API calls ─────────────────────────────────────────
        curl_calls = [
            c for c in mock_run.call_args_list if c[0][0][0] == "curl"
        ]
        # Must have at least 5: boot-source, drives/rootfs, network-interfaces,
        # machine-config, actions (InstanceStart)
        self.assertGreaterEqual(len(curl_calls), 5)

        api_urls = [c[0][0][-1] for c in curl_calls]
        self.assertIn("http://localhost/boot-source", api_urls)
        self.assertIn("http://localhost/drives/rootfs", api_urls)
        self.assertIn("http://localhost/network-interfaces/eth0", api_urls)  # NEW
        self.assertIn("http://localhost/machine-config", api_urls)
        self.assertIn("http://localhost/actions", api_urls)

        # ── Verify network-interfaces comes before InstanceStart ───────────────
        net_idx = api_urls.index("http://localhost/network-interfaces/eth0")
        start_idx = api_urls.index("http://localhost/actions")
        self.assertLess(net_idx, start_idx, "Network must be configured before VM start")

        sandbox.stop()

    @patch("security_engine.firecracker_sandbox.subprocess.run")
    def test_run_command_builds_correct_ssh_args(self, mock_run):
        """run_command() should invoke SSH with the proper arguments."""
        mock_run.return_value = MagicMock(
            returncode=0, stdout="hello world", stderr=""
        )

        sandbox = FirecrackerSandbox(
            vm_ip="10.0.0.5",
            ssh_key_path="/test/key.pem",
        )
        stdout, stderr, code = sandbox.run_command("echo hello")

        self.assertEqual(code, 0)
        self.assertEqual(stdout, "hello world")

        ssh_args = mock_run.call_args[0][0]
        self.assertEqual(ssh_args[0], "ssh")
        self.assertIn("-i", ssh_args)
        self.assertIn("/test/key.pem", ssh_args)
        self.assertIn("root@10.0.0.5", ssh_args)
        self.assertIn("echo hello", ssh_args)
        # BatchMode should be set to prevent password prompts
        self.assertIn("BatchMode=yes", " ".join(ssh_args))

    @patch("security_engine.firecracker_sandbox.subprocess.run")
    def test_run_command_without_ssh_key(self, mock_run):
        """run_command() without ssh_key_path should not include -i flag."""
        mock_run.return_value = MagicMock(returncode=0, stdout="ok", stderr="")

        sandbox = FirecrackerSandbox(vm_ip="10.0.0.5", ssh_key_path=None)
        sandbox.run_command("echo ok")

        ssh_args = mock_run.call_args[0][0]
        self.assertNotIn("-i", ssh_args)

    def test_build_install_command_pip(self):
        """_build_install_command should produce a correct pip install command."""
        cmd = FirecrackerSandbox._build_install_command("requests", "pip")
        self.assertIn("pip3 install", cmd)
        self.assertIn("requests", cmd)
        self.assertIn("/tmp/pkg_test", cmd)

    def test_build_install_command_npm(self):
        """_build_install_command should produce a correct npm install command."""
        cmd = FirecrackerSandbox._build_install_command("express", "npm")
        self.assertIn("npm install", cmd)
        self.assertIn("express", cmd)

    def test_build_install_command_cargo(self):
        """_build_install_command should produce a correct cargo install command."""
        cmd = FirecrackerSandbox._build_install_command("serde", "cargo")
        self.assertIn("cargo install", cmd)
        self.assertIn("serde", cmd)

    def test_build_install_command_unknown_manager(self):
        """_build_install_command should return None for unknown managers."""
        cmd = FirecrackerSandbox._build_install_command("pkg", "unknown_manager")
        self.assertIsNone(cmd)

    @patch("security_engine.firecracker_sandbox.os.path.exists", return_value=True)
    @patch("security_engine.firecracker_sandbox.os.remove")
    def test_stop_terminates_and_cleans_up(self, mock_remove, mock_exists):
        """stop() should terminate the process and remove the socket file."""
        mock_process = MagicMock()
        mock_process.pid = 99999
        mock_process.wait.return_value = None

        sandbox = FirecrackerSandbox(socket_path="/tmp/test-stop.socket")
        sandbox._process = mock_process
        sandbox._log_file = MagicMock()

        sandbox.stop()

        mock_process.terminate.assert_called_once()
        mock_remove.assert_called_once_with("/tmp/test-stop.socket")
        self.assertIsNone(sandbox._process)
        self.assertIsNone(sandbox._log_file)

    def test_context_manager_calls_stop(self):
        """Using FirecrackerSandbox as a context manager should call stop() on exit."""
        sandbox = FirecrackerSandbox()
        sandbox.stop = MagicMock()

        with sandbox:
            pass

        sandbox.stop.assert_called_once()

    @patch("security_engine.firecracker_sandbox.subprocess.run")
    def test_api_put_raises_on_curl_failure(self, mock_run):
        """_api_put() should raise RuntimeError when curl returns a non-zero exit code."""
        mock_run.return_value = MagicMock(
            returncode=22,   # curl --fail returns 22 on HTTP 4xx/5xx
            stdout='{"fault_message": "invalid request"}',
            stderr="The requested URL returned error: 400",
        )

        sandbox = FirecrackerSandbox(socket_path="/tmp/test-err.socket")
        with self.assertRaises(RuntimeError) as ctx:
            sandbox._api_put("/boot-source", {"kernel_image_path": "bad"})

        self.assertIn("/boot-source", str(ctx.exception))

    @patch("security_engine.firecracker_sandbox.subprocess.run")
    @patch("security_engine.firecracker_sandbox.time.sleep")
    def test_wait_for_ssh_exponential_backoff(self, mock_sleep, mock_run):
        """_wait_for_ssh() should apply exponential backoff between retries."""
        # First 2 calls fail, 3rd succeeds
        mock_run.side_effect = [
            MagicMock(returncode=1, stdout="", stderr=""),
            MagicMock(returncode=1, stdout="", stderr=""),
            MagicMock(returncode=0, stdout="ready", stderr=""),
        ]

        sandbox = FirecrackerSandbox()
        sandbox._wait_for_ssh(initial_delay=0.5, max_delay=4.0)

        # Two sleeps should have occurred before success on attempt 3
        self.assertEqual(mock_sleep.call_count, 2)
        # First sleep: 0.5, second sleep: 1.0 (doubled)
        delays = [c[0][0] for c in mock_sleep.call_args_list]
        self.assertEqual(delays[0], 0.5)
        self.assertEqual(delays[1], 1.0)

    @patch("security_engine.firecracker_sandbox.time.sleep")
    @patch("security_engine.firecracker_sandbox.os.path.exists")
    def test_wait_for_socket_polls_until_ready(self, mock_exists, mock_sleep):
        """_wait_for_socket() should poll until the socket file exists."""
        # Socket not present for 2 polls, then appears
        mock_exists.side_effect = [False, False, True]

        sandbox = FirecrackerSandbox(socket_path="/tmp/test-poll.socket")
        sandbox._wait_for_socket()

        self.assertEqual(mock_sleep.call_count, 2)

    @patch("security_engine.firecracker_sandbox.time.sleep")
    @patch("security_engine.firecracker_sandbox.time.monotonic")
    @patch("security_engine.firecracker_sandbox.os.path.exists", return_value=False)
    def test_wait_for_socket_raises_on_timeout(self, mock_exists, mock_monotonic, mock_sleep):
        """_wait_for_socket() should raise RuntimeError if socket never appears."""
        # Simulate time passing: first call (start), subsequent calls exceed timeout
        mock_monotonic.side_effect = [0.0, 0.0, 999.0]

        sandbox = FirecrackerSandbox(socket_path="/tmp/test-timeout.socket", startup_wait=5.0)
        with self.assertRaises(RuntimeError) as ctx:
            sandbox._wait_for_socket()

        self.assertIn("did not appear", str(ctx.exception))

    @patch("security_engine.firecracker_sandbox.subprocess.run")
    def test_run_virustotal_scan_skipped_without_key(self, mock_run):
        """_run_virustotal_scan_file() should return empty string when no VT key is set."""
        sandbox = FirecrackerSandbox(virustotal_key=None)
        result = sandbox._run_virustotal_scan_file("/tmp/pkg.tar.gz", "requests")

        self.assertEqual(result, "")
        mock_run.assert_not_called()

    @patch("security_engine.firecracker_sandbox.subprocess.run")
    def test_run_virustotal_scan_injects_key_in_command(self, mock_run):
        """_run_virustotal_scan_file() should inject VT_API_KEY inline in the SSH command."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"status": "clean", "malicious": 0, "suspicious": 0}',
            stderr="",
        )

        sandbox = FirecrackerSandbox(virustotal_key="test-vt-key-123")
        result = sandbox._run_virustotal_scan_file("/tmp/pkg.tar.gz", "requests")

        self.assertIn('"status"', result)
        # Check that VT key was embedded in the SSH command
        call_args = mock_run.call_args[0][0]
        ssh_cmd = call_args[-1]
        self.assertIn("VT_API_KEY=", ssh_cmd)
        self.assertIn("check_virustotal.py", ssh_cmd)


# ─────────────────────────────────────────────────────────────────────────────
# TestDeepScanVerifier
# ─────────────────────────────────────────────────────────────────────────────

class TestDeepScanVerifier(unittest.TestCase):
    """Tests for the DeepScanVerifier using a mocked FirecrackerSandbox."""

    def _make_sandbox_mock(self, MockSandbox, sandbox_result: SandboxResult):
        """Set up MockSandbox so context-manager protocol works correctly."""
        mock_instance = MagicMock()
        mock_instance.run_install_test.return_value = sandbox_result
        mock_instance.__enter__ = MagicMock(return_value=mock_instance)
        mock_instance.__exit__ = MagicMock(return_value=False)
        MockSandbox.return_value = mock_instance
        return mock_instance

    @patch("security_engine.deep_scan_verifier.FirecrackerSandbox")
    def test_verify_passes_virustotal_key_to_sandbox(self, MockSandbox):
        """verify() must pass virustotal_key to FirecrackerSandbox so scans work."""
        self._make_sandbox_mock(MockSandbox, SandboxResult(
            install_exit_code=0,
            suspicious_files=[],
            virustotal_output="",
        ))

        verifier = DeepScanVerifier(virustotal_key="my-vt-key")
        verifier.verify("requests", "pip")

        _, kwargs = MockSandbox.call_args
        self.assertEqual(kwargs.get("virustotal_key"), "my-vt-key")

    @patch("security_engine.deep_scan_verifier.FirecrackerSandbox")
    def test_verify_safe_package(self, MockSandbox):
        """verify() should return SAFE when sandbox finds no issues."""
        self._make_sandbox_mock(MockSandbox, SandboxResult(
            install_exit_code=0,
            install_stdout="Successfully installed requests",
            install_stderr="",
            suspicious_files=[],
            virustotal_output="",
            is_suspicious=False,
        ))

        result = DeepScanVerifier().verify("requests", "pip")

        self.assertTrue(result.is_safe)
        self.assertEqual(result.risk_level, RiskLevel.SAFE)
        self.assertEqual(result.metadata["sandbox_engine"], "firecracker")

    @patch("security_engine.deep_scan_verifier.FirecrackerSandbox")
    def test_verify_malicious_suspicious_files(self, MockSandbox):
        """verify() should return MALICIOUS when suspicious files are written."""
        self._make_sandbox_mock(MockSandbox, SandboxResult(
            install_exit_code=0,
            install_stdout="Installed",
            install_stderr="",
            suspicious_files=["/root/.ssh/authorized_keys"],
            virustotal_output="",
            is_suspicious=True,
        ))

        result = DeepScanVerifier().verify("evil-pkg", "pip")

        self.assertFalse(result.is_safe)
        self.assertEqual(result.risk_level, RiskLevel.MALICIOUS)
        self.assertIn("/root/.ssh/authorized_keys", result.reason)

    @patch("security_engine.deep_scan_verifier.FirecrackerSandbox")
    def test_verify_malicious_virustotal_flag(self, MockSandbox):
        """verify() should return MALICIOUS when VirusTotal flags a file."""
        self._make_sandbox_mock(MockSandbox, SandboxResult(
            install_exit_code=0,
            install_stdout="Installed",
            install_stderr="",
            suspicious_files=[],
            virustotal_output='{"status": "malicious", "malicious": 5}',
            is_suspicious=True,
        ))

        result = DeepScanVerifier().verify("bad-pkg", "npm")

        self.assertFalse(result.is_safe)
        self.assertEqual(result.risk_level, RiskLevel.MALICIOUS)

    @patch("security_engine.deep_scan_verifier.FirecrackerSandbox")
    def test_verify_suspicious_virustotal_flag(self, MockSandbox):
        """verify() should return SUSPICIOUS when VT marks a file suspicious."""
        self._make_sandbox_mock(MockSandbox, SandboxResult(
            install_exit_code=0,
            suspicious_files=[],
            virustotal_output='{"status": "suspicious", "suspicious": 2}',
        ))

        result = DeepScanVerifier().verify("questionable-pkg", "pip")

        self.assertFalse(result.is_safe)
        self.assertEqual(result.risk_level, RiskLevel.SUSPICIOUS)

    @patch("security_engine.deep_scan_verifier.FirecrackerSandbox")
    def test_verify_install_failure(self, MockSandbox):
        """verify() should return SUSPICIOUS when the install itself fails."""
        self._make_sandbox_mock(MockSandbox, SandboxResult(
            install_exit_code=1,
            install_stdout="",
            install_stderr="Package not found",
            suspicious_files=[],
            virustotal_output="",
            is_suspicious=False,
        ))

        result = DeepScanVerifier().verify("nonexistent-pkg", "pip")

        self.assertFalse(result.is_safe)
        self.assertEqual(result.risk_level, RiskLevel.SUSPICIOUS)
        self.assertIn("exit code 1", result.reason)

    @patch("security_engine.deep_scan_verifier.FirecrackerSandbox")
    def test_verify_handles_sandbox_exception(self, MockSandbox):
        """verify() should return UNKNOWN (blocked) when the sandbox throws."""
        mock_instance = MagicMock()
        mock_instance.__enter__ = MagicMock(side_effect=RuntimeError("VM boot failed"))
        mock_instance.__exit__ = MagicMock(return_value=False)
        MockSandbox.return_value = mock_instance

        result = DeepScanVerifier().verify("some-pkg", "pip")

        self.assertFalse(result.is_safe)
        self.assertEqual(result.risk_level, RiskLevel.UNKNOWN)
        self.assertIn("error", result.metadata)

    @patch("security_engine.deep_scan_verifier.FirecrackerSandbox")
    def test_verify_handles_firecracker_not_found(self, MockSandbox):
        """verify() should handle missing 'firecracker' binary gracefully."""
        mock_instance = MagicMock()
        mock_instance.__enter__ = MagicMock(
            side_effect=FileNotFoundError("No such file: firecracker")
        )
        mock_instance.__exit__ = MagicMock(return_value=False)
        MockSandbox.return_value = mock_instance

        result = DeepScanVerifier().verify("some-pkg", "pip")

        self.assertFalse(result.is_safe)
        self.assertEqual(result.risk_level, RiskLevel.UNKNOWN)
        self.assertEqual(result.metadata["error"], "firecracker_not_found")

    @patch("security_engine.deep_scan_verifier.FirecrackerSandbox")
    def test_malicious_takes_priority_over_install_failure(self, MockSandbox):
        """Suspicious files should produce MALICIOUS even when install also failed."""
        self._make_sandbox_mock(MockSandbox, SandboxResult(
            install_exit_code=1,
            suspicious_files=["/root/.ssh/id_rsa"],
            virustotal_output="",
        ))

        result = DeepScanVerifier().verify("dual-bad-pkg", "pip")

        self.assertEqual(result.risk_level, RiskLevel.MALICIOUS)


if __name__ == "__main__":
    unittest.main()
