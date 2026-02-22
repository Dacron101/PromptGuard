"""
injection_locator/models.py

Data structures for the prompt injection locator pipeline.
"""

from dataclasses import dataclass, field
from typing import Optional
import time


@dataclass
class ContextEntry:
    """
    A single entry in the captured conversation log.

    Each entry represents one chunk of I/O between the user and Claude Code,
    captured by TTYWrapper during the session.

    Attributes:
        role         : "user" (keystrokes typed) or "assistant" (Claude output).
        content      : The raw text content of this entry.
        timestamp    : Unix timestamp when this entry was captured.
        source_type  : Origin classification — "prompt" for direct user input,
                       "file_read" for file contents Claude read,
                       "tool_output" for tool/command results,
                       "system" for system messages.
        source_ref   : Optional reference to the original source (e.g. filename,
                       URL). Populated when the content originated from a file
                       read or document.
        line_start   : Optional start line if the content came from a file.
        line_end     : Optional end line if the content came from a file.
    """
    role: str
    content: str
    timestamp: float = field(default_factory=time.time)
    source_type: str = "prompt"
    source_ref: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None

    def token_estimate(self) -> int:
        """Rough token count estimate (~4 chars per token)."""
        return max(1, len(self.content) // 4)


@dataclass
class InjectionReport:
    """
    Report produced by InjectionLocator after binary search completes.

    Attributes:
        found           : Whether an injection source was successfully localised.
        source_type     : Classification of the injection origin.
        segment_text    : The narrowed-down text segment containing the injection.
        segment_index   : Position of the segment in the original context log.
        original_source : Human-readable description of the source
                          (e.g. "user prompt", "document.pdf page 3").
        line_range      : (start, end) line numbers if applicable.
        iterations_used : Number of binary search steps performed.
        confidence      : 0.0–1.0 confidence that the injection is in this segment.
        search_path     : Debug log of the binary search decisions.
    """
    found: bool
    source_type: str = "unknown"
    segment_text: str = ""
    segment_index: int = -1
    original_source: str = ""
    line_range: Optional[tuple[int, int]] = None
    iterations_used: int = 0
    confidence: float = 0.0
    search_path: list[str] = field(default_factory=list)
