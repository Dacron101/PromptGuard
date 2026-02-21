"""
interceptor/tty_wrapper.py

TTYWrapper — PTY-based Man-in-the-Middle proxy for Claude Code.
───────────────────────────────────────────────────────────────
This module is the core of ClaudeGuard's runtime interception mechanism.
It forks a pseudo-terminal (PTY), launches Claude Code inside it, then
acts as a transparent proxy for all I/O between the user's terminal and
the Claude Code process.

How it works
────────────
  1. Python's `pty.fork()` creates a parent/child process pair linked by a PTY.
  2. The child process `exec`s the `claude` binary — from its perspective it
     has a real terminal and behaves normally (colour output, readline, etc.).
  3. The parent process runs a select()-based I/O loop:
       • stdin  → PTY fd  : forward keystrokes to Claude Code.
       • PTY fd → stdout  : intercept Claude Code's output, run detection,
                            then either pass through or block + warn.
  4. When an installation command is detected in the output stream:
       a. The output is immediately forwarded to the user (so they can see
          what Claude attempted).
       b. A SIGINT (Ctrl+C) is sent to the Claude process group to interrupt
          the running command.
       c. The SecurityChecker is consulted for each package.
       d. A coloured verdict is printed to the terminal.
       e. Control returns to the normal I/O loop — Claude Code resumes.

Limitations & known trade-offs
───────────────────────────────
  • We detect commands in Claude's OUTPUT stream. If Claude dispatches a
    shell command synchronously without printing the command text first,
    we may miss it. This is mitigated by Claude Code's UX pattern of always
    showing "Running: <cmd>" before execution.
  • The SIGINT interrupts the entire Claude Code process, not just the
    offending subprocess. Claude Code's internal error handling will catch
    this and present the user with an error prompt — that is intentional.

FUTURE INJECTION POINT — Shell shim / PATH hijacking (preferred long-term):
    A more reliable interception strategy is to prepend a directory of shim
    scripts to the PATH that Claude Code inherits:

        export PATH="/opt/claudeguard/shims:$PATH"

    Each shim (npm, pip, brew, …) calls THIS Python module's verify() before
    delegating to the real binary. That approach catches commands BEFORE they
    execute, not after they appear in output. The shim scripts would be
    auto-generated at startup and removed on exit.

    The _inject_path_shims() stub below marks where that logic lives.

FUTURE INJECTION POINT — eBPF / audit-log interception:
    For a kernel-level guarantee, an eBPF program can hook the execve()
    syscall and filter on argv[0] matching package manager names. The eBPF
    program sends events via a perf ring buffer to a userspace handler that
    calls SecurityChecker.check() and decides whether to allow or kill the
    process. This provides interception even if Claude Code uses an
    undocumented code path.
"""

import os
import pty
import select
import signal
import sys
import termios
import tty
import logging
from typing import Optional

from colorama import Fore, Style, init as colorama_init

from .command_detector import CommandDetector, DetectedCommand
from security_engine.checker import SecurityChecker

colorama_init(autoreset=True)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# Read buffer size for PTY I/O. Larger values reduce syscall overhead but
# increase latency before pattern matching.
_PTY_READ_SIZE = 4096

# ANSI colour shortcuts for ClaudeGuard UI messages
_BLOCKED = f"{Fore.RED}{Style.BRIGHT}"
_ALLOWED = f"{Fore.GREEN}{Style.BRIGHT}"
_INFO    = f"{Fore.CYAN}{Style.BRIGHT}"
_WARN    = f"{Fore.YELLOW}{Style.BRIGHT}"
_RESET   = Style.RESET_ALL

# ClaudeGuard prefix for all printed messages
_TAG = f"{_INFO}[ClaudeGuard]{_RESET}"


class TTYWrapper:
    """
    Transparent PTY proxy that intercepts package installation commands
    issued by Claude Code.

    Args:
        command_detector  : Configured CommandDetector instance.
        security_checker  : Configured SecurityChecker instance.
        claude_command    : The binary/path for Claude Code (default: "claude").
        allow_unknown     : If True, UNKNOWN packages are allowed through with
                            a warning rather than being blocked. Defaults to
                            False (conservative / block unknown).
    """

    def __init__(
        self,
        command_detector: CommandDetector,
        security_checker: SecurityChecker,
        claude_command: str = "claude",
        allow_unknown: bool = False,
    ) -> None:
        self._detector = command_detector
        self._checker = security_checker
        self._claude_command = claude_command
        self._allow_unknown = allow_unknown

        # The file descriptor for the child PTY (set after fork).
        self._child_fd: Optional[int] = None
        # The child process PID (set after fork).
        self._child_pid: Optional[int] = None
        # Rolling line buffer for pattern matching across chunk boundaries.
        self._line_buffer: str = ""

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self) -> int:
        """
        Fork a PTY, launch Claude Code, and begin proxying I/O.

        This call blocks until the Claude Code process exits.

        Returns:
            The exit code of the Claude Code process.
        """
        self._print_banner()

        # ── FUTURE INJECTION POINT — PATH shims ──────────────────────────────
        # Before forking, call self._inject_path_shims() here to prepend
        # interceptor shim scripts to PATH. The child process will inherit
        # the modified environment, ensuring every npm/pip/… invocation
        # goes through our verifier BEFORE the real binary runs.
        # self._inject_path_shims()
        # ─────────────────────────────────────────────────────────────────────

        try:
            self._child_pid, self._child_fd = pty.fork()
        except OSError as exc:
            logger.error("Failed to fork PTY: %s", exc)
            raise

        if self._child_pid == 0:
            # ── Child process ─────────────────────────────────────────────────
            # We are now inside the forked child. exec() replaces this process
            # with the real Claude Code binary. The PTY file descriptor is
            # automatically set as stdin/stdout/stderr by pty.fork().
            self._exec_claude()
            # exec never returns; if it does, something went wrong.
            sys.exit(1)
        else:
            # ── Parent process ────────────────────────────────────────────────
            return self._run_proxy()

    # ── Core proxy loop ───────────────────────────────────────────────────────

    def _run_proxy(self) -> int:
        """
        Main I/O proxy loop. Runs in the parent process after fork().
        Saves and restores terminal state around the raw-mode session.
        """
        # Save the current terminal settings so we can restore them on exit.
        stdin_fd = sys.stdin.fileno()
        original_term_settings = termios.tcgetattr(stdin_fd)

        exit_code = 0
        try:
            # Switch stdin to raw mode — every keystroke is forwarded
            # character-by-character to Claude Code without local echo.
            tty.setraw(stdin_fd)

            exit_code = self._io_loop(stdin_fd)

        except Exception as exc:
            logger.error("Proxy loop error: %s", exc, exc_info=True)
        finally:
            # Always restore terminal — failure here leaves the shell broken.
            try:
                termios.tcsetattr(stdin_fd, termios.TCSADRAIN, original_term_settings)
            except termios.error:
                pass  # stdin may have been closed already
            if self._child_fd is not None:
                try:
                    os.close(self._child_fd)
                except OSError:
                    pass

        return exit_code

    def _io_loop(self, stdin_fd: int) -> int:
        """
        select()-based bidirectional I/O loop.

        Reads from:
          • stdin       → forward raw bytes to the child PTY (user keystrokes).
          • child PTY   → process output through the detection pipeline,
                          then write to stdout.

        Returns when the child PTY closes (Claude Code has exited).
        """
        while True:
            try:
                # Timeout of 0.05 s keeps responsiveness without burning CPU.
                read_fds, _, _ = select.select(
                    [stdin_fd, self._child_fd], [], [], 0.05
                )
            except (ValueError, OSError):
                # File descriptor closed — child has exited.
                break

            # ── User → Claude Code ────────────────────────────────────────────
            if stdin_fd in read_fds:
                try:
                    user_input = os.read(stdin_fd, 1024)
                    if user_input:
                        os.write(self._child_fd, user_input)
                except OSError:
                    break

            # ── Claude Code → User (with interception) ────────────────────────
            if self._child_fd in read_fds:
                try:
                    raw_data = os.read(self._child_fd, _PTY_READ_SIZE)
                except OSError:
                    # Child PTY closed — process has exited.
                    break

                if not raw_data:
                    break

                self._process_output_chunk(raw_data)

        # Collect child exit status
        return self._wait_for_child()

    def _process_output_chunk(self, raw_data: bytes) -> None:
        """
        Core interception logic for each chunk of PTY output.

        Strategy:
          1. Decode the chunk and append to the rolling line buffer.
          2. Run CommandDetector against completed lines in the buffer.
          3. If no installation commands found → write raw bytes to stdout.
          4. If commands found → write raw bytes, then:
               a. Send SIGINT to interrupt the Claude process.
               b. Verify each package and print verdict.
        """
        # Always forward the raw output to the user first — they should see
        # exactly what Claude Code is doing, including the command it tried.
        sys.stdout.buffer.write(raw_data)
        sys.stdout.buffer.flush()

        # Decode for pattern matching (errors='replace' keeps the proxy alive
        # even if the output contains non-UTF-8 binary data).
        text_chunk = raw_data.decode("utf-8", errors="replace")
        self._line_buffer += text_chunk

        # Only run detection when we have at least one complete line.
        # This prevents false negatives from commands split across chunks.
        if "\n" not in self._line_buffer and "\r" not in self._line_buffer:
            return

        detected: list[DetectedCommand] = self._detector.detect(self._line_buffer)

        # Flush processed lines from the buffer (keep the last incomplete line).
        last_newline = max(
            self._line_buffer.rfind("\n"), self._line_buffer.rfind("\r")
        )
        if last_newline != -1:
            self._line_buffer = self._line_buffer[last_newline + 1 :]

        if not detected:
            return

        # ── Installation command(s) detected! ─────────────────────────────────
        # Interrupt Claude Code before (or as) it dispatches the install.
        self._interrupt_child()

        # Verify each detected package and print verdicts.
        for cmd in detected:
            self._handle_detected_command(cmd)

    def _handle_detected_command(self, cmd: DetectedCommand) -> None:
        """
        Verify a single detected installation command and print the verdict.

        Called once per package (not once per command — multi-package installs
        produce multiple DetectedCommand objects from CommandDetector).
        """
        pkg = cmd.package_name
        mgr = cmd.manager

        print(f"\n{_TAG} Detected: {_WARN}{mgr} install {pkg}{_RESET}")
        print(f"{_TAG} Verifying package integrity…", flush=True)

        result = self._checker.check(pkg, mgr)

        if result.is_safe:
            print(
                f"{_TAG} {_ALLOWED}✓ ALLOWED{_RESET}  "
                f"'{pkg}' passed security check "
                f"[{result.risk_level.value} | confidence {result.confidence:.0%}]"
            )
            print(f"{_TAG} {result.reason}")
        else:
            allow_anyway = self._allow_unknown and result.risk_level.value == "unknown"

            if allow_anyway:
                print(
                    f"{_TAG} {_WARN}⚠  WARNING{_RESET}  "
                    f"'{pkg}' is UNKNOWN — allowing (allow_unknown=True)"
                )
            else:
                print(
                    f"{_TAG} {_BLOCKED}✗ BLOCKED{_RESET}  "
                    f"'{pkg}' failed security check "
                    f"[{result.risk_level.value} | confidence {result.confidence:.0%}]"
                )
                print(f"{_TAG} Reason: {result.reason}")

            # Print metadata if the verifier enriched the result
            if result.metadata:
                for key, value in result.metadata.items():
                    print(f"{_TAG}   {key}: {value}")

        print()  # Visual separator

    # ── Child process management ─────────────────────────────────────────────

    def _exec_claude(self) -> None:
        """
        Replace the child process image with Claude Code.
        Called inside the forked child; never returns on success.
        """
        try:
            os.execvp(self._claude_command, [self._claude_command])
        except FileNotFoundError:
            # execvp failed — print to stderr (which is still the PTY at this
            # point) so the parent's proxy loop shows a useful error.
            sys.stderr.write(
                f"\n{_TAG} ERROR: '{self._claude_command}' not found. "
                "Is Claude Code installed and on your PATH?\n"
            )
            sys.exit(127)

    def _interrupt_child(self) -> None:
        """
        Send SIGINT to the child process group to interrupt the running command.

        SIGINT (Ctrl+C) is the standard way to abort a running shell command.
        Claude Code's readline / event loop will catch it and return to the
        prompt, allowing the session to continue.
        """
        try:
            os.killpg(os.getpgid(self._child_pid), signal.SIGINT)
            logger.debug("Sent SIGINT to child process group %d", self._child_pid)
        except ProcessLookupError:
            logger.debug("Child process %d already gone — skipping SIGINT", self._child_pid)
        except PermissionError as exc:
            logger.error("Could not send SIGINT to child: %s", exc)

    def _wait_for_child(self) -> int:
        """Reap the child process and return its exit code."""
        try:
            _, status = os.waitpid(self._child_pid, 0)
            if os.WIFEXITED(status):
                return os.WEXITSTATUS(status)
            if os.WIFSIGNALED(status):
                return -os.WTERMSIG(status)
        except ChildProcessError:
            pass
        return 0

    # ── Future stub methods ───────────────────────────────────────────────────

    def _inject_path_shims(self) -> None:
        """
        FUTURE INJECTION POINT — PATH shim injection.

        Before forking, generate tiny shell scripts named after each package
        manager (npm, pip, brew, cargo, go) inside a temporary directory, then
        prepend that directory to the PATH environment variable so the child
        process (Claude Code) picks up our shims instead of the real binaries.

        Each shim would:
          1. Parse its argv for install sub-commands.
          2. Call `python -c "from claudeguard import verify; verify(…)"`.
          3. If approved, exec the real binary with the original argv.
          4. If denied, exit 1 with a descriptive error message.

        This approach intercepts commands BEFORE they execute (unlike the
        PTY output monitoring above which is reactive). It also works when
        Claude Code uses a non-printing code path for command dispatch.

        Pseudocode:
            import tempfile, stat
            shim_dir = tempfile.mkdtemp(prefix="claudeguard_shims_")
            for manager in ("npm", "pip", "pip3", "brew", "cargo", "go"):
                shim_path = os.path.join(shim_dir, manager)
                with open(shim_path, "w") as f:
                    f.write(SHIM_TEMPLATE.format(manager=manager))
                os.chmod(shim_path, stat.S_IRWXU)
            os.environ["PATH"] = shim_dir + ":" + os.environ.get("PATH", "")
            # Register cleanup:
            import atexit, shutil
            atexit.register(shutil.rmtree, shim_dir, ignore_errors=True)
        """
        raise NotImplementedError(
            "_inject_path_shims() is a planned enhancement — see docstring."
        )

    # ── UI helpers ────────────────────────────────────────────────────────────

    @staticmethod
    def _print_banner() -> None:
        banner = (
            f"\n{_INFO}{'─' * 60}{_RESET}\n"
            f"{_INFO}  ClaudeGuard — Package Security Interceptor{_RESET}\n"
            f"{_INFO}  Monitoring: npm · pip · yarn · brew · cargo · go{_RESET}\n"
            f"{_INFO}{'─' * 60}{_RESET}\n"
        )
        print(banner, flush=True)
