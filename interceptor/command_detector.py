"""
interceptor/command_detector.py

CommandDetector — regex-based installation command parser.
──────────────────────────────────────────────────────────
Scans a string of terminal output (typically one or more lines received from
the Claude Code PTY) and returns structured information about any package
installation commands it finds.

Supported package managers:
    npm       node install
    yarn      yarn add
    pip       pip / pip3 / python -m pip install
    brew      Homebrew install
    cargo     Rust package manager
    go get    Go module fetcher

Design notes:
    • All regex patterns are compiled once at module load time (not per call).
    • Each pattern captures both the full command and the individual package
      name(s) so the caller never needs to parse twice.
    • Multi-package invocations (e.g., `pip install requests flask`)  produce
      one DetectedCommand per package — simplifying the verification loop.
    • The detector is intentionally conservative: it prefers false positives
      (blocking a safe command) over false negatives (missing a bad one).

FUTURE INJECTION POINT — Shell history / audit-log scanning:
    This module currently operates on PTY output text. In a future hardened
    mode the same patterns can be applied to:
      • The shell's HISTFILE after each command
      • Linux audit-log events (auditd) for execve() calls
      • eBPF probes attached to exec system calls
    Swap `detect(text)` for `detect_from_audit_event(event: dict)` when
    moving to kernel-level interception.
"""

import re
import logging
from dataclasses import dataclass
from typing import List, Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DetectedCommand:
    """
    Represents a single package-installation command found in terminal output.

    Attributes:
        manager      : Normalised package manager name (e.g. "npm", "pip").
        full_command : The entire command string as it appeared in the output.
        package_name : The first (or only) package name in the command.
                       For multi-package commands this is repeated once per
                       package — see CommandDetector.detect().
        flags        : Any flags present (e.g. ["--save-dev", "-g"]).
        version      : Version specifier if present, e.g. "==1.2.3" or "@^2".
        raw_line     : The original unmodified line where the command was found.
    """
    manager: str
    full_command: str
    package_name: str
    flags: List[str]
    version: Optional[str]
    raw_line: str


# ─────────────────────────────────────────────────────────────────────────────
# Pattern registry
#
# Each entry maps a package-manager name to a compiled regex.
# Named groups used:
#   full_cmd  — the entire install command token (without the preceding shell prompt)
#   packages  — the package-name portion of the command (may be multiple words)
#   flags     — optional flag cluster before/after the package list
#
# The patterns are written to be resilient to:
#   • ANSI escape codes that Claude Code might embed in its output
#   • Optional `sudo` or `npx` prefixes
#   • Version specifiers (==, @, :)
#   • Multiple space/tab separators
# ─────────────────────────────────────────────────────────────────────────────

_PATTERNS: dict[str, re.Pattern] = {

    # ── npm install ───────────────────────────────────────────────────────────
    # Matches:
    #   npm install <pkg>
    #   npm i <pkg>
    #   sudo npm install -g <pkg>
    #   npx --yes npm install <pkg>
    "npm": re.compile(
        r"""
        (?:sudo\s+)?                # optional sudo
        (?:npx\s+(?:--yes\s+)?)?   # optional npx invocation
        npm\s+(?:install|i|add)\s+ # npm install | npm i | npm add
        (?P<flags>(?:-{1,2}\S+\s+)*)   # optional flags (e.g. --save-dev, -g)
        (?P<packages>[a-zA-Z0-9@._/\-]+ # package name (scoped or plain)
          (?:\s+[a-zA-Z0-9@._/\-]+)*)   # optional additional packages
        """,
        re.VERBOSE | re.IGNORECASE,
    ),

    # ── yarn add ──────────────────────────────────────────────────────────────
    # Matches:
    #   yarn add <pkg>
    #   yarn add --dev <pkg>
    #   yarn global add <pkg>
    "yarn": re.compile(
        r"""
        (?:sudo\s+)?
        yarn\s+
        (?:global\s+)?              # optional 'global'
        add\s+
        (?P<flags>(?:-{1,2}\S+\s+)*)
        (?P<packages>[a-zA-Z0-9@._/\-]+
          (?:\s+[a-zA-Z0-9@._/\-]+)*)
        """,
        re.VERBOSE | re.IGNORECASE,
    ),

    # ── pip install ───────────────────────────────────────────────────────────
    # Matches:
    #   pip install <pkg>
    #   pip3 install <pkg>
    #   python -m pip install <pkg>
    #   python3 -m pip install --upgrade <pkg>
    "pip": re.compile(
        r"""
        (?:sudo\s+)?
        (?:python3?\s+-m\s+)?       # optional python -m prefix
        pip3?\s+install\s+
        (?P<flags>(?:-{1,2}\S+\s+)*)
        (?P<packages>[a-zA-Z0-9._\-]+(?:[=<>!~]{1,2}[^\s]+)?
          (?:\s+[a-zA-Z0-9._\-]+(?:[=<>!~]{1,2}[^\s]+)?)*)
        """,
        re.VERBOSE | re.IGNORECASE,
    ),

    # ── brew install ─────────────────────────────────────────────────────────
    # Matches:
    #   brew install <formula>
    #   brew install --cask <app>
    "brew": re.compile(
        r"""
        (?:sudo\s+)?
        brew\s+install\s+
        (?P<flags>(?:-{1,2}\S+\s+)*)
        (?P<packages>[a-zA-Z0-9._/\-]+
          (?:\s+[a-zA-Z0-9._/\-]+)*)
        """,
        re.VERBOSE | re.IGNORECASE,
    ),

    # ── cargo add ────────────────────────────────────────────────────────────
    # Matches:
    #   cargo add <crate>
    #   cargo add serde --features derive
    "cargo": re.compile(
        r"""
        (?:sudo\s+)?
        cargo\s+add\s+
        (?P<packages>[a-zA-Z0-9_\-]+(?:@[^\s]+)?)
        (?P<flags>(?:\s+-{1,2}\S+)*)
        """,
        re.VERBOSE | re.IGNORECASE,
    ),

    # ── go get ────────────────────────────────────────────────────────────────
    # Matches:
    #   go get <module>
    #   go get github.com/user/repo@v1.2.3
    #   go install github.com/user/tool@latest
    "go": re.compile(
        r"""
        (?:sudo\s+)?
        go\s+(?:get|install)\s+
        (?P<flags>(?:-{1,2}\S+\s+)*)
        (?P<packages>[a-zA-Z0-9._/\-@]+
          (?:\s+[a-zA-Z0-9._/\-@]+)*)
        """,
        re.VERBOSE | re.IGNORECASE,
    ),
}

# Compiled ANSI-strip pattern (Claude Code uses colour in its output)
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m|\x1b\[[0-9;]*[A-Za-z]")

# Flag tokens (for parsing out of package lists)
_FLAG_TOKEN = re.compile(r"^-{1,2}\S+$")

# Version specifier attached to a package name
_VERSION_SPECIFIER = re.compile(
    r"(?:@[^@\s]+|[=<>!~]{1,2}[^\s]+)$"
)


class CommandDetector:
    """
    Scans terminal-output text for package installation commands.

    Instantiate once and call `detect(text)` for each chunk of PTY output.
    """

    def detect(self, text: str) -> List[DetectedCommand]:
        """
        Scan `text` for installation commands across all supported managers.

        Multi-package commands produce one DetectedCommand per package.
        Duplicate detections within the same text chunk are deduplicated.

        Args:
            text : One or more lines of raw PTY output (may contain ANSI codes).

        Returns:
            A list of DetectedCommand objects, one per package found.
            Returns an empty list when no installation commands are detected.
        """
        # Strip ANSI escape sequences before matching
        clean_text = _ANSI_ESCAPE.sub("", text)

        results: List[DetectedCommand] = []
        seen: set[tuple[str, str]] = set()  # (manager, package) dedup key

        for manager, pattern in _PATTERNS.items():
            for match in pattern.finditer(clean_text):
                raw_line = self._extract_raw_line(text, match.start(), match.end())
                full_command = match.group(0).strip()
                packages_raw = match.group("packages").strip()
                flags_raw = (match.group("flags") or "").strip()

                # Parse individual package names from the packages group
                for pkg in self._split_packages(packages_raw):
                    pkg_name, version = self._split_version(pkg, manager)

                    # Skip empty / flag-like tokens that slipped past the regex
                    if not pkg_name or _FLAG_TOKEN.match(pkg_name):
                        continue

                    dedup_key = (manager, pkg_name.lower())
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    cmd = DetectedCommand(
                        manager=manager,
                        full_command=full_command,
                        package_name=pkg_name,
                        flags=flags_raw.split() if flags_raw else [],
                        version=version,
                        raw_line=raw_line,
                    )
                    results.append(cmd)
                    logger.debug(
                        "Detected install command | manager=%s pkg=%s version=%s",
                        manager, pkg_name, version,
                    )

        return results

    # ── Private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _extract_raw_line(original_text: str, start: int, end: int) -> str:
        """Return the full line from the original (ANSI-intact) text."""
        line_start = original_text.rfind("\n", 0, start) + 1
        line_end_idx = original_text.find("\n", end)
        line_end = line_end_idx if line_end_idx != -1 else len(original_text)
        return original_text[line_start:line_end].strip()

    @staticmethod
    def _split_packages(packages_raw: str) -> List[str]:
        """Split a whitespace-separated package list into individual tokens."""
        return [p for p in packages_raw.split() if p]

    @staticmethod
    def _split_version(token: str, manager: str) -> tuple[str, Optional[str]]:
        """
        Separate a package name from its version specifier.

        Examples:
            npm:   react@18.2.0   → ("react", "@18.2.0")
            pip:   requests==2.31  → ("requests", "==2.31")
            go:    pkg@v1.2        → ("pkg", "@v1.2")
            cargo: serde@1.0       → ("serde", "@1.0")
        """
        version_match = _VERSION_SPECIFIER.search(token)
        if version_match:
            pkg_name = token[: version_match.start()]
            version = version_match.group(0)
            return pkg_name, version
        return token, None
