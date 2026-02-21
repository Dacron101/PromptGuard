#!/usr/bin/env python3
"""
claudeguard.py — ClaudeGuard entry point.
──────────────────────────────────────────
Run this script INSTEAD of running `claude` directly:

    python claudeguard.py [options]

ClaudeGuard will:
  1. Print a startup banner.
  2. Configure the SecurityChecker with the appropriate verifier chain.
  3. Fork a PTY and launch Claude Code inside it.
  4. Proxy all I/O transparently, intercepting package installation commands.
  5. Verify each package and block or allow it based on the configured policy.
  6. Exit with the same exit code as Claude Code.

CLI Options
───────────
  --claude-cmd PATH      Path (or name) of the Claude Code binary.
                         Defaults to "claude".
  --allow-unknown        Allow packages not in the safe list (with a warning).
                         Default is to block them.
  --deep-scan            Enable DeepScanVerifier as a fallback (NOT YET
                         IMPLEMENTED — reserved for future use).
  --log-level LEVEL      Python logging level (DEBUG, INFO, WARNING, ERROR).
                         Defaults to WARNING.
  --version              Print ClaudeGuard version and exit.
  -h / --help            Show this help message and exit.

Exit Codes
──────────
  0     Claude Code exited normally.
  1     ClaudeGuard setup error (e.g., Claude Code binary not found).
  127   Claude Code binary not found (propagated from child).
  Any other value is the raw exit code of the Claude Code process.
"""

import argparse
import logging
import sys
import os

# Ensure the project root is on sys.path so relative imports work when the
# script is executed directly (not as a module).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from security_engine.basic_verifier import BasicVerifier
from security_engine.checker import SecurityChecker

# DeepScanVerifier is imported for the CLI flag, but kept disabled until
# its implementation is complete.
# FUTURE INJECTION POINT — DeepScanVerifier activation:
#   from security_engine.deep_scan_verifier import DeepScanVerifier
#   When --deep-scan is passed, construct:
#       fallback = DeepScanVerifier(virustotal_key=os.getenv("VT_API_KEY"))
#   and pass it to SecurityChecker(primary_verifier=..., fallback_verifier=fallback)

from interceptor.command_detector import CommandDetector
from interceptor.tty_wrapper import TTYWrapper

__version__ = "0.1.0"


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="claudeguard",
        description=(
            "ClaudeGuard — Security wrapper for Claude Code that intercepts "
            "and verifies package installation commands before they execute."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--claude-cmd",
        default="claude",
        metavar="PATH",
        help="Path or name of the Claude Code binary. Default: 'claude'.",
    )
    parser.add_argument(
        "--allow-unknown",
        action="store_true",
        default=False,
        help=(
            "Allow packages that are not in the trusted allowlist (prints a "
            "warning but does not block). Default: block unknown packages."
        ),
    )
    parser.add_argument(
        "--deep-scan",
        action="store_true",
        default=False,
        help=(
            "[NOT YET IMPLEMENTED] Enable DeepScanVerifier (Docker sandbox + "
            "VirusTotal) as a fallback for unknown packages."
        ),
    )
    parser.add_argument(
        "--log-level",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the Python logging level. Default: WARNING.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"ClaudeGuard {__version__}",
    )
    return parser


def configure_logging(level_str: str) -> None:
    """Set up structured logging to stderr."""
    logging.basicConfig(
        stream=sys.stderr,
        level=getattr(logging, level_str.upper(), logging.WARNING),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def build_security_checker(args: argparse.Namespace) -> SecurityChecker:
    """
    Construct the SecurityChecker from CLI arguments.

    Current verifier chain:
        Primary  : BasicVerifier (always active)
        Fallback : None (until --deep-scan is implemented)

    FUTURE INJECTION POINT — Deep scan flag:
        if args.deep_scan:
            from security_engine.deep_scan_verifier import DeepScanVerifier
            fallback = DeepScanVerifier(
                virustotal_key=os.getenv("VT_API_KEY"),
                timeout_seconds=120,
            )
        else:
            fallback = None
        return SecurityChecker(
            primary_verifier=BasicVerifier(),
            fallback_verifier=fallback,
        )
    """
    if args.deep_scan:
        logging.getLogger(__name__).warning(
            "--deep-scan was requested but DeepScanVerifier is not yet "
            "implemented. Falling back to BasicVerifier only."
        )

    return SecurityChecker(
        primary_verifier=BasicVerifier(),
        fallback_verifier=None,
    )


def main() -> int:
    """
    ClaudeGuard entry point.

    Returns the exit code to pass to the OS.
    """
    parser = build_arg_parser()
    args = parser.parse_args()

    configure_logging(args.log_level)
    logger = logging.getLogger(__name__)

    logger.info("ClaudeGuard %s starting", __version__)
    logger.info("Config: claude_cmd=%s allow_unknown=%s deep_scan=%s",
                args.claude_cmd, args.allow_unknown, args.deep_scan)

    # ── Sanity check: is Claude Code available? ───────────────────────────────
    import shutil
    if not shutil.which(args.claude_cmd):
        # Don't hard-error: pty.fork() + execvp will produce a clean error
        # inside the terminal session.  But warn so the user sees it early.
        print(
            f"\033[33m[ClaudeGuard] WARNING: '{args.claude_cmd}' not found on "
            f"PATH. The session will fail unless the path is correct.\033[0m",
            file=sys.stderr,
        )

    # ── Build the verifier chain ──────────────────────────────────────────────
    checker = build_security_checker(args)

    # ── Build the command detector ────────────────────────────────────────────
    detector = CommandDetector()

    # ── Build the TTY wrapper ─────────────────────────────────────────────────
    wrapper = TTYWrapper(
        command_detector=detector,
        security_checker=checker,
        claude_command=args.claude_cmd,
        allow_unknown=args.allow_unknown,
    )

    # ── Launch Claude Code and block until it exits ───────────────────────────
    try:
        exit_code = wrapper.start()
    except KeyboardInterrupt:
        # User pressed Ctrl+C at the top level — exit cleanly.
        exit_code = 130  # 128 + SIGINT
    except Exception as exc:
        logger.exception("Unhandled exception in TTYWrapper: %s", exc)
        print(
            f"\033[31m[ClaudeGuard] Fatal error: {exc}\033[0m",
            file=sys.stderr,
        )
        exit_code = 1

    logger.info("ClaudeGuard exiting with code %d", exit_code)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
