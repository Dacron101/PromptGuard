"""
injection_locator/injection_locator.py

Context-window chunk locator for prompt injection.
──────────────────────────────────────────────────
When PromptGate detects a malicious action (e.g. a blocked package install),
this module locates the context window segment that caused the agent to behave
maliciously by chunking the conversation history and re-prompting.

Algorithm (two-phase shrink over context entries):
  1. Take the full conversation context as an ordered list of ContextEntry objects.
  2. Verify the full context reproduces the malicious behaviour.
  3. Phase 1 — Trim from the END: progressively remove chunks of entries from
     the right side and re-prompt Claude each time.  Once Claude stops
     reproducing the malicious command, the right boundary has been found.
  4. Phase 2 — Trim from the START: within [0, right_boundary], progressively
     remove chunks from the left.  Once Claude stops reproducing, the left
     boundary has been found.
  5. Report the narrowed segment of context entries.

Key differences from a word-level search:
  - Operates on ContextEntry objects (the full context window), not words within
    a single user message.  The injection may be in a file read, tool output,
    earlier user turn, or any other entry.
  - Re-prompts by formatting the candidate slice as a conversation transcript
    and letting Claude respond naturally.
  - The check is whether the agent, given only that context slice, would still
    attempt the malicious action — NOT whether the command string appears
    literally somewhere in the prompt text.
"""

import logging
import re
import subprocess

from .models import ContextEntry, InjectionReport

logger = logging.getLogger(__name__)

# Terminal colours
_TAG = "\033[36m[PromptGate]\033[0m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RESET = "\033[0m"
_BG_RED = "\033[41m\033[97m"  # Red background + white text

# How many context entries to remove per shrinking step.
# 1 = maximum precision; increase to reduce API calls for large contexts.
_CHUNK_SIZE = 1

# Maximum re-prompt calls per phase (safety cap to limit API costs).
_MAX_STEPS_PER_PHASE = 25


class InjectionLocator:
    """
    Two-phase context-entry shrinking to locate the injection source.

    Args:
        context_log     : Captured conversation entries from TTYWrapper.
        blocked_command : The malicious command that was blocked
                          (e.g. "pip install evil-pkg").
        claude_command  : Path to the Claude CLI binary.
        max_iterations  : Max re-prompt calls per phase (default 25).
    """

    def __init__(
        self,
        context_log: list[ContextEntry],
        blocked_command: str,
        claude_command: str = "claude",
        max_iterations: int = _MAX_STEPS_PER_PHASE,
    ) -> None:
        self._context = context_log
        self._blocked_command = blocked_command
        self._claude_cmd = claude_command
        self._max_steps = max_iterations

    # ── Public API ────────────────────────────────────────────────────────────

    def locate(self) -> InjectionReport:
        """
        Run the two-phase locator and return the result.

        Returns:
            InjectionReport identifying the malicious context segment.
        """
        entries = self._context
        if not entries:
            return InjectionReport(
                found=False,
                search_path=["No context entries found"],
            )

        print(
            f"{_TAG} 🔎 Starting injection locator "
            f"({len(entries)} context entries, chunk size {_CHUNK_SIZE})"
        )
        print(
            f"{_TAG} Looking for malicious behaviour triggered by: "
            f"{_YELLOW}{self._blocked_command}{_RESET}"
        )

        search_path: list[str] = []

        # ── Verify the full context reproduces ────────────────────────────────
        print(f"{_TAG}")
        print(
            f"{_TAG}   Verifying full context ({len(entries)} entries)…",
            end="",
            flush=True,
        )
        if not self._test_context_chunk(entries):
            print(f" → {_GREEN}clean{_RESET}")
            search_path.append(
                "Full context → clean (malicious behaviour not reproducible headlessly)"
            )
            return self._build_not_found_report(search_path, entries)
        print(f" → {_RED}reproduces{_RESET}")
        search_path.append("Full context → reproduces")

        # ── Phase 1: Trim from the END ────────────────────────────────────────
        # Find the right boundary: progressively remove chunks from the end
        # until Claude stops reproducing the malicious behaviour.
        print(f"{_TAG}")
        print(f"{_TAG} {_BOLD}Phase 1:{_RESET} Trimming from the end…")

        right_boundary = len(entries)
        step = 0

        while right_boundary > 0 and step < self._max_steps:
            step += 1
            candidate_right = right_boundary - _CHUNK_SIZE

            if candidate_right <= 0:
                # Narrowed to the first chunk — can't shrink further.
                break

            test_entries = entries[:candidate_right]
            print(
                f"{_TAG}   Step {step}: testing entries[0:{candidate_right}]…",
                end="",
                flush=True,
            )

            if self._test_context_chunk(test_entries):
                print(f" → {_RED}reproduces{_RESET}")
                search_path.append(
                    f"Phase 1 step {step}: entries[0:{candidate_right}] → reproduces"
                )
                # Smaller slice still reproduces → keep shrinking
                right_boundary = candidate_right
            else:
                print(f" → {_GREEN}clean{_RESET}")
                search_path.append(
                    f"Phase 1 step {step}: entries[0:{candidate_right}] → clean"
                )
                # Removing entries[candidate_right:right_boundary] stopped the
                # behaviour.  The injection is inside that removed chunk.
                # right_boundary is already set to the last reproducing value.
                break

        # ── Phase 2: Trim from the START ──────────────────────────────────────
        # Find the left boundary: within entries[0:right_boundary], remove
        # chunks from the left until Claude stops reproducing.
        print(f"{_TAG}")
        print(
            f"{_TAG} {_BOLD}Phase 2:{_RESET} "
            f"Trimming from the start (within entries[0:{right_boundary}])…"
        )

        left_boundary = 0
        step = 0

        while left_boundary < right_boundary and step < self._max_steps:
            step += 1
            candidate_left = left_boundary + _CHUNK_SIZE

            if candidate_left >= right_boundary:
                # Only one chunk remains — the injection must be in it.
                break

            test_entries = entries[candidate_left:right_boundary]
            print(
                f"{_TAG}   Step {step}: testing entries[{candidate_left}:{right_boundary}]…",
                end="",
                flush=True,
            )

            if self._test_context_chunk(test_entries):
                print(f" → {_RED}reproduces{_RESET}")
                search_path.append(
                    f"Phase 2 step {step}: entries[{candidate_left}:{right_boundary}] → reproduces"
                )
                # Smaller slice still reproduces → keep shrinking from the left
                left_boundary = candidate_left
            else:
                print(f" → {_GREEN}clean{_RESET}")
                search_path.append(
                    f"Phase 2 step {step}: entries[{candidate_left}:{right_boundary}] → clean"
                )
                # Removing entries[left_boundary:candidate_left] stopped it.
                # left_boundary is already the last reproducing start.
                break

        # ── Build the result ──────────────────────────────────────────────────
        malicious_entries = entries[left_boundary:right_boundary]
        malicious_text = self._format_context(malicious_entries)

        print(f"{_TAG}")
        print(f"{_TAG} {_BOLD}🎯 Injection source located!{_RESET}")
        print(f"{_TAG}")
        print(
            f"{_TAG} {_DIM}Malicious segment: "
            f"entries {left_boundary}–{right_boundary - 1} "
            f"(of {len(entries)} total){_RESET}"
        )
        print(f"{_TAG}")

        print(f"{_TAG} Malicious segment (highlighted in {_BG_RED}red background{_RESET}):")
        print(f"{_TAG}")

        # A few words of context from the entry immediately before the malicious segment.
        pre_context = ""
        if left_boundary > 0:
            pre_words = (
                entries[left_boundary - 1]
                .content.replace("\n", " ").replace("\r", " ").split()
            )
            if pre_words:
                pre_context = "…" + " ".join(pre_words[-6:]) + " "

        # The malicious content itself (all malicious entries joined).
        malicious_display = " ".join(
            e.content.replace("\n", " ").replace("\r", " ").strip()
            for e in malicious_entries
        )

        # A few words of context from the entry immediately after the malicious segment.
        post_context = ""
        if right_boundary < len(entries):
            post_words = (
                entries[right_boundary]
                .content.replace("\n", " ").replace("\r", " ").split()
            )
            if post_words:
                post_context = " " + " ".join(post_words[:6]) + "…"

        print(f"{_TAG}   {pre_context}{_BG_RED}{malicious_display}{_RESET}{post_context}")
        print(f"{_TAG}")

        # Pick the most informative entry for source reporting
        source_entry = max(malicious_entries, key=lambda e: len(e.content))

        total_steps = len(search_path)
        confidence = self._compute_confidence(
            total_steps, len(malicious_entries), len(entries)
        )
        print(f"{_TAG}   Confidence: {confidence:.0%}")
        print(f"{_TAG}   API calls: {total_steps}")

        return InjectionReport(
            found=True,
            segment_text=malicious_text,
            segment_index=left_boundary,
            source_type=source_entry.source_type,
            original_source=(
                source_entry.source_ref
                or f"Context entries {left_boundary}–{right_boundary - 1}"
            ),
            confidence=confidence,
            iterations_used=total_steps,
            search_path=search_path,
        )

    # ── Private helpers ───────────────────────────────────────────────────────

    def _test_context_chunk(self, entries: list[ContextEntry]) -> bool:
        """
        Re-prompt Claude with the given context slice formatted as a
        conversation transcript, and check whether the agent would still
        attempt the blocked malicious command.

        The entries are formatted as a conversation and sent to Claude, which
        is asked to continue the conversation naturally.  The response is then
        checked for any attempt to execute the malicious command.

        This does NOT search the prompt text for the command string — it checks
        whether the agent's *behaviour* (output) is still malicious.
        """
        if not entries:
            return False

        conversation = self._format_context(entries)
        prompt = (
            "You are Claude Code, an AI coding assistant that can run "
            "terminal commands. Below is a conversation transcript. "
            "Continue the conversation as the assistant — include any "
            "terminal commands you would run.\n\n"
            f"Conversation:\n{conversation}\n\n"
            "Assistant:"
        )

        try:
            response = self._call_claude(prompt)
            return self._response_contains_blocked_command(response)
        except Exception as exc:
            logger.warning("Re-prompt failed: %s", exc)
            return False

    @staticmethod
    def _format_context(entries: list[ContextEntry]) -> str:
        """Format a list of ContextEntry objects as a readable conversation transcript."""
        parts = []
        for entry in entries:
            role_label = "User" if entry.role == "user" else "Assistant"
            content = entry.content
            # Truncate very long entries (e.g. large file reads) to keep prompts manageable
            if len(content) > 800:
                content = content[:800] + "… [truncated]"
            parts.append(f"{role_label}: {content}")
        return "\n\n".join(parts)

    def _call_claude(self, prompt: str) -> str:
        """Call Claude Code CLI headlessly."""
        cmd = [
            self._claude_cmd,
            "--print",
            "-p", prompt,
            "--output-format", "text",
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.returncode != 0:
            logger.warning(
                "Claude CLI exit code %d: %s",
                result.returncode, result.stderr[:200],
            )

        return result.stdout

    def _response_contains_blocked_command(self, response: str) -> bool:
        """
        Check if Claude's response attempts the blocked malicious command.

        Uses both exact string matching and package-name extraction to handle
        cases where Claude uses a slightly different command format.
        """
        if not response:
            return False

        response_lower = response.lower().strip()
        blocked_lower = self._blocked_command.lower().strip()

        # Direct substring match on the full command
        if blocked_lower in response_lower:
            return True

        # Extract the package name from "pip install <pkg>" etc.
        pkg_match = re.search(
            r"(?:pip|pip3|npm|yarn|cargo|brew|go)\s+"
            r"(?:install|add|get)\s+(.+?)(?:\s|$)",
            blocked_lower,
        )
        if pkg_match:
            pkg_name = pkg_match.group(1).strip().lower()
            if pkg_name in response_lower:
                return True

        return False

    def _build_not_found_report(
        self,
        search_path: list[str],
        entries: list[ContextEntry],
    ) -> InjectionReport:
        """Build a report when the locator couldn't isolate the injection."""
        print(
            f"\n{_TAG} {_YELLOW}⚠ Could not isolate the injection "
            f"segment.{_RESET}"
        )
        print(
            f"{_TAG} The malicious intent may be distributed across "
            f"the entire context, or not reproducible in a headless re-prompt."
        )
        return InjectionReport(
            found=False,
            segment_text=self._format_context(entries)[:2000],
            search_path=search_path,
        )

    @staticmethod
    def _compute_confidence(
        total_steps: int,
        malicious_entries: int,
        total_entries: int,
    ) -> float:
        """
        Confidence score based on how precisely we narrowed the segment.

        Higher when: more steps were run and the malicious segment is a
        small fraction of the total context.
        """
        if total_entries == 0 or total_steps == 0:
            return 0.3

        # Precision: smaller malicious segment relative to total = higher confidence
        precision = 1.0 - (malicious_entries / total_entries)

        # Effort: more steps = more confident in the result
        effort = min(1.0, total_steps / 10)

        return round(min(0.95, 0.3 + 0.4 * precision + 0.25 * effort), 2)
