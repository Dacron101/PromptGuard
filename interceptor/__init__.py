"""
interceptor — ClaudeGuard's runtime I/O interception layer.

Public API:
    TTYWrapper       : PTY Man-in-the-Middle proxy for Claude Code.
    CommandDetector  : Regex-based installation command scanner.
    DetectedCommand  : Data class representing a single detected command.
"""

from .command_detector import CommandDetector, DetectedCommand
from .tty_wrapper import TTYWrapper

__all__ = [
    "CommandDetector",
    "DetectedCommand",
    "TTYWrapper",
]
