"""
injection_locator/source_mapper.py

Maps a narrowed-down context segment back to its original input source.

After the binary search converges on a particular ContextEntry (or range of
entries), SourceMapper translates that into human-readable provenance:

  - User-typed prompt → character offset range in the original input.
  - File content Claude read → filename + line numbers.
  - Tool / command output → the command that produced it.
  - URL / web page → URL + section identifier.
"""

import re
import logging
from typing import Optional

from .models import ContextEntry, InjectionReport

logger = logging.getLogger(__name__)

# Patterns that indicate file reads in Claude's output
_FILE_READ_PATTERN = re.compile(
    r"(?:Reading|read|Cat|cat|View|view)\s+(?:file\s+)?['\"]?([^\s'\"]+)['\"]?",
    re.IGNORECASE,
)
_FILE_PATH_PATTERN = re.compile(
    r"(/[\w./-]+\.(?:py|js|ts|md|txt|json|yaml|yml|csv|html|xml|sh|env|cfg|ini|toml))"
)
_URL_PATTERN = re.compile(
    r"https?://[^\s<>\"']+",
    re.IGNORECASE,
)


class SourceMapper:
    """
    Translates a context segment into a human-readable source reference.

    Used after the binary search converges to tell the user WHERE the
    injection originated — the prompt, a specific file, a URL, etc.
    """

    @staticmethod
    def map_segment(
        entries: list[ContextEntry],
        segment_start: int,
        segment_end: int,
    ) -> InjectionReport:
        """
        Map a range of context entries to an InjectionReport with source info.

        Args:
            entries       : Full context log.
            segment_start : Start index (inclusive) of the narrowed segment.
            segment_end   : End index (exclusive) of the narrowed segment.

        Returns:
            An InjectionReport with source_type, original_source, and
            line_range populated.
        """
        if segment_start >= len(entries) or segment_end <= 0:
            return InjectionReport(found=False)

        # Clamp to valid range
        start = max(0, segment_start)
        end = min(len(entries), segment_end)
        segment_entries = entries[start:end]

        if not segment_entries:
            return InjectionReport(found=False)

        # Use the most informative entry in the segment
        best_entry = SourceMapper._find_best_entry(segment_entries)

        source_type = best_entry.source_type
        segment_text = best_entry.content
        original_source = ""
        line_range = None

        if best_entry.source_ref:
            original_source = best_entry.source_ref
            if best_entry.line_start is not None:
                line_range = (
                    best_entry.line_start,
                    best_entry.line_end or best_entry.line_start,
                )

        # Try to extract source from content if no explicit ref
        if not original_source:
            original_source = SourceMapper._infer_source(best_entry)

        # Build the description
        if source_type == "prompt":
            description = "User prompt input"
            if original_source:
                description = f"User prompt: {original_source}"
        elif source_type == "file_read":
            description = f"File: {original_source}"
            if line_range:
                description += f" (lines {line_range[0]}–{line_range[1]})"
        elif source_type == "tool_output":
            description = f"Tool output: {original_source or 'command result'}"
        elif source_type == "url":
            description = f"Web page: {original_source}"
        else:
            description = f"Context segment (entries {start}–{end - 1})"

        return InjectionReport(
            found=True,
            source_type=source_type,
            segment_text=segment_text[:2000],  # Cap for readability
            segment_index=start,
            original_source=description,
            line_range=line_range,
            confidence=0.0,  # Caller sets this based on search quality
        )

    @staticmethod
    def _find_best_entry(entries: list[ContextEntry]) -> ContextEntry:
        """
        Pick the most informative entry from a list of candidates.

        Prefers entries with explicit source_ref, then user inputs, then
        longest content (likely to contain the injection payload).
        """
        # Prefer entries with explicit source references
        with_ref = [e for e in entries if e.source_ref]
        if with_ref:
            return max(with_ref, key=lambda e: len(e.content))

        # Prefer user-role entries (injections come from input)
        user_entries = [e for e in entries if e.role == "user"]
        if user_entries:
            return max(user_entries, key=lambda e: len(e.content))

        # Fallback: longest entry
        return max(entries, key=lambda e: len(e.content))

    @staticmethod
    def _infer_source(entry: ContextEntry) -> str:
        """
        Try to infer the source from the entry's content using heuristics.

        Looks for URLs, file paths, or other identifying patterns.
        Checks URLs first since they contain path-like substrings.
        """
        content = entry.content

        # Check for URLs first (they contain path-like substrings)
        url_match = _URL_PATTERN.search(content)
        if url_match:
            return url_match.group(0)[:100]

        # Check for file paths
        file_match = _FILE_PATH_PATTERN.search(content)
        if file_match:
            return file_match.group(1)

        # Check for file read commands
        read_match = _FILE_READ_PATTERN.search(content)
        if read_match:
            return read_match.group(1)

        # For user prompts, return a truncated preview
        if entry.role == "user" and len(content) > 20:
            return content[:60].strip() + "…"

        return ""
