# ClaudeGuard

A security middleware wrapper for [Claude Code](https://docs.anthropic.com/claude/claude-code) that intercepts package installation commands in real time, verifies them against a trusted allowlist and heuristic rules, and blocks potentially malicious or hallucinated packages before they can execute.

---

## How It Works

```
User Terminal
     │
     ▼
┌─────────────────────────────────────────────────┐
│              claudeguard.py                      │
│  ┌────────────────────────────────────────────┐  │
│  │           TTYWrapper (PTY MITM)            │  │
│  │  ┌──────────────┐   ┌──────────────────┐  │  │
│  │  │CommandDetector│──▶│ SecurityChecker  │  │  │
│  │  │  (regex FSM)  │   │ (Strategy Chain) │  │  │
│  │  └──────────────┘   └──────────────────┘  │  │
│  │          │                    │            │  │
│  │  ┌───────▼────────────────────▼──────────┐ │  │
│  │  │  BasicVerifier  │  DeepScanVerifier*  │ │  │
│  │  │  (allowlist +   │  (Docker sandbox +  │ │  │
│  │  │   heuristics)   │   VirusTotal stub)  │ │  │
│  │  └─────────────────────────────────────┘ │  │
│  └────────────────────────────────────────────┘  │
│                        │                         │
│            ┌───────────▼───────────┐             │
│            │    claude (process)   │             │
│            └───────────────────────┘             │
└─────────────────────────────────────────────────┘

* DeepScanVerifier is a planned stub — not yet active.
```

1. The user runs `python claudeguard.py` instead of `claude`.
2. ClaudeGuard forks a PTY and launches Claude Code inside it.
3. All I/O flows through the `TTYWrapper` proxy transparently.
4. When a line matching an install command (e.g. `pip install foo`) is detected, `CommandDetector` fires.
5. `SecurityChecker` consults the verifier chain (currently `BasicVerifier`).
6. If the package is **safe** → session continues uninterrupted.
7. If the package is **unsafe/unknown** → Claude Code receives `SIGINT`, a warning is printed, and the install is aborted.

---

## Project Structure

```
CodeGate/
├── claudeguard.py               # Entry point — run this
├── requirements.txt
│
├── security_engine/             # Pluggable verification layer
│   ├── __init__.py
│   ├── base.py                  # PackageVerifier ABC + VerificationResult
│   ├── basic_verifier.py        # Offline allowlist + heuristic verifier
│   ├── deep_scan_verifier.py    # Docker/VirusTotal stub (future)
│   └── checker.py               # SecurityChecker (Strategy orchestrator)
│
└── interceptor/                 # Runtime interception layer
    ├── __init__.py
    ├── command_detector.py      # Regex-based install command parser
    └── tty_wrapper.py           # PTY Man-in-the-Middle proxy
```

---

## Installation

```bash
# Clone the repo
git clone <repo-url>
cd CodeGate

# Install dependencies
pip install -r requirements.txt

# Make the entry point executable (optional)
chmod +x claudeguard.py
```

**Requirements:** Python 3.10+, `pexpect`, `colorama`, Claude Code installed and on `PATH`.

---

## Usage

```bash
# Basic usage — replaces running 'claude' directly
python claudeguard.py

# Use a custom path to the claude binary
python claudeguard.py --claude-cmd /usr/local/bin/claude

# Allow unknown packages (warn instead of block)
python claudeguard.py --allow-unknown

# Verbose debug output
python claudeguard.py --log-level DEBUG

# Show help
python claudeguard.py --help
```

---

## Supported Package Managers

| Manager | Intercepted Commands |
|---------|---------------------|
| npm     | `npm install`, `npm i`, `npm add` |
| yarn    | `yarn add`, `yarn global add` |
| pip     | `pip install`, `pip3 install`, `python -m pip install` |
| brew    | `brew install` |
| cargo   | `cargo add` |
| go      | `go get`, `go install` |

---

## Architecture: Strategy Pattern

`SecurityChecker` owns a **primary** and optional **fallback** `PackageVerifier`. Adding a new verification backend requires only:

1. Subclass `PackageVerifier` and implement `verify()`.
2. Pass an instance as `fallback_verifier` to `SecurityChecker`.

```python
# Future usage once DeepScanVerifier is implemented:
from security_engine.deep_scan_verifier import DeepScanVerifier
from security_engine.checker import SecurityChecker

checker = SecurityChecker(
    primary_verifier=BasicVerifier(),
    fallback_verifier=DeepScanVerifier(virustotal_key="your_key"),
)
```

---

## Roadmap

- [x] PTY-based Man-in-the-Middle proxy
- [x] Regex detection for 6 package managers
- [x] Offline allowlist + heuristic verifier (`BasicVerifier`)
- [x] Strategy Pattern verifier chain (`SecurityChecker`)
- [ ] `DeepScanVerifier` — Docker sandbox (network-isolated container install)
- [ ] `DeepScanVerifier` — VirusTotal file-hash submission
- [ ] `DeepScanVerifier` — OSV/Snyk advisory lookup
- [ ] `DeepScanVerifier` — ML-based typosquatting detector
- [ ] PATH shim injection (proactive interception before execution)
- [ ] eBPF/audit-log kernel-level interception mode
- [ ] Web dashboard for audit logs
- [ ] Allowlist sync from PyPA/npm advisory databases

---

## Security Notes

- ClaudeGuard is a **defence-in-depth** layer, not a complete sandbox. A sufficiently sophisticated threat (e.g., a package that defers its payload to post-install hooks) may still cause harm. The `DeepScanVerifier` roadmap addresses this.
- The PTY interception is **reactive** — it fires when the command appears in Claude Code's output stream, which is typically just before execution. The PATH shim approach (roadmap item) provides truly **proactive** interception.
- Always review the `security_engine/basic_verifier.py` allowlist to ensure it matches your organisation's approved packages.
