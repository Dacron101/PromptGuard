"""
tests/test_firecracker_sandbox.py

Unit tests for FirecrackerSandbox and DeepScanVerifier.
Uses mocks — no actual Firecracker binary or VM required.
"""

import os
import sys
import json
import unittest
from unittest.mock import patch, MagicMock, mock_open, call

# Ensure project root is on sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from security_engine.firecracker_sandbox import FirecrackerSandbox, SandboxResult
from security_engine.deep_scan_verifier import DeepScanVerifier
from security_engine.base import RiskLevel


class TestFirecrackerSandbox(unittest.TestCase):
    """Tests for the FirecrackerSandbox VM lifecycle manager."""

    @patch("security_engine.firecracker_sandbox.subprocess.Popen")
    @patch("security_engine.firecracker_sandbox.subprocess.run")
    @patch("security_engine.firecracker_sandbox.os.path.exists", return_value=False)
    @patch("builtins.open", mock_open())
    def test_start_sends_correct_api_calls(self, mock_exists, mock_run, mock_popen):
        """start() should configure boot-source, drives, machine-config, and InstanceStart."""
        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_popen.return_value = mock_process

        # Mock curl calls to return empty JSON
        mock_run.return_value = MagicMock(
            returncode=0, stdout="", stderr=""
        )

        sandbox = FirecrackerSandbox(
            kernel_path="/test/vmlinux",
            rootfs_path="/test/rootfs.ext4",
            vm_ip="192.168.1.100",
            startup_wait=0,  # Don't actually sleep
        )
        sandbox.start()

        # Verify firecracker was started
        mock_popen.assert_called_once()
        popen_args = mock_popen.call_args[0][0]
        self.assertEqual(popen_args[0], "firecracker")
        self.assertIn("--api-sock", popen_args)

        # Verify 4 curl API calls were made + SSH readiness check
        # (boot-source, drives/rootfs, machine-config, actions, + SSH polls)
        curl_calls = [
            c for c in mock_run.call_args_list
            if c[0][0][0] == "curl"
        ]
        self.assertGreaterEqual(len(curl_calls), 4)

        # Check that the API endpoints are correct
        api_urls = [c[0][0][-1] for c in curl_calls]
        self.assertIn("http://localhost/boot-source", api_urls)
        self.assertIn("http://localhost/drives/rootfs", api_urls)
        self.assertIn("http://localhost/machine-config", api_urls)
        self.assertIn("http://localhost/actions", api_urls)

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

    def test_build_install_command_unknown_manager(self):
        """_build_install_command should return None for unknown managers."""
        cmd = FirecrackerSandbox._build_install_command("pkg", "unknown_manager")
        self.assertIsNone(cmd)

    @patch("security_engine.firecracker_sandbox.subprocess.Popen")
    @patch("security_engine.firecracker_sandbox.os.path.exists", return_value=True)
    @patch("security_engine.firecracker_sandbox.os.remove")
    def test_stop_terminates_and_cleans_up(self, mock_remove, mock_exists, mock_popen):
        """stop() should terminate the process and remove the socket file."""
        mock_process = MagicMock()
        mock_process.pid = 99999
        mock_process.wait.return_value = None

        sandbox = FirecrackerSandbox()
        sandbox._process = mock_process

        sandbox.stop()

        mock_process.terminate.assert_called_once()
        mock_remove.assert_called_once_with(sandbox._socket_path)
        self.assertIsNone(sandbox._process)

    def test_context_manager_calls_stop(self):
        """Using as a context manager should call stop() on exit."""
        sandbox = FirecrackerSandbox()
        sandbox.stop = MagicMock()

        with sandbox:
            pass

        sandbox.stop.assert_called_once()


class TestDeepScanVerifier(unittest.TestCase):
    """Tests for the DeepScanVerifier using a mocked FirecrackerSandbox."""

    def _setup_sandbox_mock(self, MockSandbox, sandbox_result):
        """Helper to set up the mock so the context manager works correctly."""
        mock_instance = MagicMock()
        mock_instance.run_install_test.return_value = sandbox_result
        mock_instance.__enter__ = MagicMock(return_value=mock_instance)
        mock_instance.__exit__ = MagicMock(return_value=False)
        MockSandbox.return_value = mock_instance
        return mock_instance

    @patch("security_engine.deep_scan_verifier.FirecrackerSandbox")
    def test_verify_safe_package(self, MockSandbox):
        """verify() should return SAFE when sandbox finds no issues."""
        self._setup_sandbox_mock(MockSandbox, SandboxResult(
            install_exit_code=0,
            install_stdout="Successfully installed requests",
            install_stderr="",
            suspicious_files=[],
            virustotal_output="",
            is_suspicious=False,
        ))

        verifier = DeepScanVerifier()
        result = verifier.verify("requests", "pip")

        self.assertTrue(result.is_safe)
        self.assertEqual(result.risk_level, RiskLevel.SAFE)
        self.assertEqual(result.metadata["sandbox_engine"], "firecracker")

    @patch("security_engine.deep_scan_verifier.FirecrackerSandbox")
    def test_verify_malicious_suspicious_files(self, MockSandbox):
        """verify() should return MALICIOUS when suspicious files are found."""
        self._setup_sandbox_mock(MockSandbox, SandboxResult(
            install_exit_code=0,
            install_stdout="Installed",
            install_stderr="",
            suspicious_files=["/root/.ssh/authorized_keys"],
            virustotal_output="",
            is_suspicious=True,
        ))

        verifier = DeepScanVerifier()
        result = verifier.verify("evil-pkg", "pip")

        self.assertFalse(result.is_safe)
        self.assertEqual(result.risk_level, RiskLevel.MALICIOUS)
        self.assertIn("/root/.ssh/authorized_keys", result.reason)

    @patch("security_engine.deep_scan_verifier.FirecrackerSandbox")
    def test_verify_malicious_virustotal_flag(self, MockSandbox):
        """verify() should return MALICIOUS when VirusTotal flags a file."""
        self._setup_sandbox_mock(MockSandbox, SandboxResult(
            install_exit_code=0,
            install_stdout="Installed",
            install_stderr="",
            suspicious_files=[],
            virustotal_output='{"malicious": 5, "undetected": 60}',
            is_suspicious=True,
        ))

        verifier = DeepScanVerifier()
        result = verifier.verify("bad-pkg", "npm")

        self.assertFalse(result.is_safe)
        self.assertEqual(result.risk_level, RiskLevel.MALICIOUS)

    @patch("security_engine.deep_scan_verifier.FirecrackerSandbox")
    def test_verify_install_failure(self, MockSandbox):
        """verify() should return SUSPICIOUS when install fails with no other flags."""
        self._setup_sandbox_mock(MockSandbox, SandboxResult(
            install_exit_code=1,
            install_stdout="",
            install_stderr="Package not found",
            suspicious_files=[],
            virustotal_output="",
            is_suspicious=False,
        ))

        verifier = DeepScanVerifier()
        result = verifier.verify("nonexistent-pkg", "pip")

        self.assertFalse(result.is_safe)
        self.assertEqual(result.risk_level, RiskLevel.SUSPICIOUS)

    @patch("security_engine.deep_scan_verifier.FirecrackerSandbox")
    def test_verify_handles_sandbox_exception(self, MockSandbox):
        """verify() should return UNKNOWN when the sandbox throws an exception."""
        mock_instance = MagicMock()
        mock_instance.__enter__ = MagicMock(side_effect=RuntimeError("VM boot failed"))
        mock_instance.__exit__ = MagicMock(return_value=False)
        MockSandbox.return_value = mock_instance

        verifier = DeepScanVerifier()
        result = verifier.verify("some-pkg", "pip")

        self.assertFalse(result.is_safe)
        self.assertEqual(result.risk_level, RiskLevel.UNKNOWN)
        self.assertIn("error", result.metadata)

    @patch("security_engine.deep_scan_verifier.FirecrackerSandbox")
    def test_verify_handles_firecracker_not_found(self, MockSandbox):
        """verify() should handle FileNotFoundError when firecracker is missing."""
        mock_instance = MagicMock()
        mock_instance.__enter__ = MagicMock(side_effect=FileNotFoundError("No firecracker"))
        mock_instance.__exit__ = MagicMock(return_value=False)
        MockSandbox.return_value = mock_instance

        verifier = DeepScanVerifier()
        result = verifier.verify("some-pkg", "pip")

        self.assertFalse(result.is_safe)
        self.assertEqual(result.risk_level, RiskLevel.UNKNOWN)
        self.assertEqual(result.metadata["error"], "firecracker_not_found")


if __name__ == "__main__":
    unittest.main()
