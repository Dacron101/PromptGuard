# PromptGuard

**Real-time security middleware for Claude Code** — intercepts malicious package installs, catches prompt injection attacks before they execute, and tells you exactly where in the context the threat came from.

---

## The Problem

AI coding agents like Claude Code are powerful — and that's exactly what makes them dangerous. A single malicious instruction buried in a README, a web page Claude scraped, or a tool output can silently poison the agent's context and cause it to install a backdoored package, exfiltrate credentials, or modify system files. By the time you notice, it's already done.

PromptGuard sits between you and Claude Code and stops this.

---

## What It Does

```
Your Terminal
      │
      ▼
┌─────────────────────────────────────────────────────────┐
│                      PromptGuard                        │
│                                                         │
│  ┌───────────────────────────────────────────────────┐  │
│  │           TTYWrapper  (PTY Man-in-the-Middle)     │  │
│  │                                                   │  │
│  │   ┌─────────────────┐    ┌──────────────────────┐ │  │
│  │   │ CommandDetector │───▶│  SecurityChecker    │ │  │
│  │   │ (regex, 6 pkg   │    │  (Strategy Chain)    │ │  │
│  │   │  managers)      │    └──────────┬───────────┘ │  │
│  │   └─────────────────┘              │              │  │
│  │                          ┌─────────┴──────────┐   │  │
│  │                          │                    │   │  │
│  │              ┌───────────┴───────┐  ┌─────────┴──────────────┐
│  │              │  BasicVerifier    │  │   DeepScanVerifier     │
│  │              │  allowlist +      │  │   Firecracker microVM  │
│  │              │  typosquatting    │  │   + VirusTotal API v3  │
│  │              └───────────────────┘  └────────────────────────┘
│  │                                                   │  │
│  │   ┌───────────────────────────────────────────┐   │  │
│  │   │            InjectionLocator               │   │  │
│  │   │  ┌──────────────────────┬──────────────┐  │   │  │
│  │   │  │ Two-phase binary     │  Embedding   │  │   │  │
│  │   │  │ search over context  │  cosine-sim  │  │   │  │
│  │   │  │ (re-prompts Claude)  │  (O(1) calls)│  │   │  │
│  │   │  └──────────────────────┴──────────────┘  │   │  │
│  │   └───────────────────────────────────────────┘   │  │
│  │                                                   │  │
│  │   ┌───────────────────────────────────────────┐   │  │
│  │   │  GeminiExplainer  (2.0 flash-lite)        │   │  │
│  │   │  plain-English verdict on every block     │   │  │
│  │   └───────────────────────────────────────────┘   │  │
│  └───────────────────────────────────────────────────┘  │
│                          │                              │
│             ┌────────────▼───────────┐                  │
│             │    claude  (process)   │                  │
│             └────────────────────────┘                  │
└─────────────────────────────────────────────────────────┘
```

---

## Three Layers of Defence

### Layer 1 — Package Verification

Every `npm install`, `pip install`, `cargo add` (and more) is intercepted the moment it appears in Claude Code's output stream. The package name is checked against a two-stage verifier chain before a single byte hits the network:

- **BasicVerifier** — instant, offline. Allowlist of trusted packages + heuristic rules for typosquatting (Levenshtein similarity against popular packages), suspicious keywords, and abnormal naming patterns.
- **DeepScanVerifier** — triggered for unknowns. Spins up an isolated **Firecracker microVM** (hardware-level KVM isolation), installs the package inside it, monitors for suspicious filesystem mutations (`~/.ssh`, cron, `/etc/ld.so.preload`, …), then runs a **VirusTotal API v3** scan on the installed files. The VM is destroyed when done — nothing touches the host.

If a threat is detected, Claude Code receives `SIGINT` and the install is aborted. A Gemini-powered explanation tells you exactly why.

### Layer 2 — Prompt Injection Detection

When a package install is blocked, PromptGuard doesn't just stop there. It launches the **InjectionLocator** to answer the harder question: *where in the context did this instruction come from?*

Two complementary strategies run in parallel:

**Binary-search locator** — re-prompts Claude with progressively smaller slices of the conversation history using a two-phase shrink algorithm (trim from end → trim from start). When Claude stops reproducing the malicious command, the boundary has been found. Precise to a single context entry.

**Embedding locator** — encodes every sentence in the context window and the blocked command into vector space, then ranks chunks by cosine similarity. Finds the injection in O(1) API calls instead of O(log N). Supports OpenAI embeddings (when `OPENAI_API_KEY` is set) or a fully local model — no external calls required.

Both locators return an **InjectionReport** with:
- The exact text segment that caused the malicious behaviour
- The source: which file was read, which URL was fetched, which user turn contained it
- A confidence score
- Highlighted output showing the malicious context in red

### Layer 3 — AI-Powered Threat Explanation

Every block triggers a call to **Gemini 2.0 Flash Lite** (the cheapest production Gemini model at ~$0.0001 per call) to generate a concise, human-readable explanation:

> *"The installation of 'totally-legit-sdk' via pip was blocked because VirusTotal identified it as a credential-stealer (7/72 engines flagged it, including Trojan.Gen.2). Claude Code has been interrupted to protect your system."*

If the Gemini API is unavailable, a deterministic fallback template is used — the block always happens regardless.

---

## Installation

```bash
git clone <repo-url>
cd PromptGuard
pip install -r requirements.txt
```

**Requirements:** Python 3.10+, Claude Code on `PATH`.

Copy `.env.example` to `.env` and fill in your API keys:

```bash
cp .env.example .env
```

---

## Usage

```bash
# Drop-in replacement for 'claude'
python claudeguard.py

# Enable Firecracker deep scan for unknown packages
python claudeguard.py --deep-scan

# Deep scan with explicit paths
python claudeguard.py --deep-scan \
    --kernel-path /opt/firecracker/vmlinux \
    --rootfs-path /opt/firecracker/rootfs.ext4 \
    --vm-ip 172.16.0.2 \
    --ssh-key-path ~/.ssh/firecracker_id_rsa

# Warn on unknown packages instead of blocking
python claudeguard.py --allow-unknown

# Debug logging
python claudeguard.py --log-level DEBUG
```

---

## Supported Package Managers

| Manager | Intercepted Commands |
|---------|----------------------|
| pip     | `pip install`, `pip3 install`, `python -m pip install` |
| npm     | `npm install`, `npm i`, `npm add` |
| yarn    | `yarn add`, `yarn global add` |
| cargo   | `cargo add` |
| go      | `go get`, `go install` |
| brew    | `brew install` |

---

## Configuration

All keys are read from environment variables (set in `.env`):

| Variable | Purpose |
|----------|---------|
| `GEMINI_API_KEY` | Gemini 2.0 Flash Lite — threat explanations. Get one at [aistudio.google.com](https://aistudio.google.com/app/apikey). |
| `VT_API_KEY` | VirusTotal API v3 — in-VM file scanning. |
| `OPENAI_API_KEY` | OpenAI embeddings for the embedding-based injection locator. Falls back to a local model if unset. |
| `FC_KERNEL_PATH` | Path to the Firecracker vmlinux kernel image. |
| `FC_ROOTFS_PATH` | Path to the rootfs.ext4 image. |
| `FC_VM_IP` | VM IP address for SSH access (default: `172.16.0.2`). |
| `FC_HOST_IP` | Host-side TAP interface IP (default: `172.16.0.1`). |
| `FC_TAP_DEVICE` | TAP device name (default: `tap0`). |
| `FC_SSH_KEY_PATH` | SSH private key for `root@VM`. |

---

## Project Structure

```
PromptGuard/
├── claudeguard.py              # Entry point
├── requirements.txt
├── .env.example
│
├── security_engine/            # Package verification
│   ├── base.py                 # PackageVerifier ABC + VerificationResult
│   ├── basic_verifier.py       # Offline allowlist + heuristic checks
│   ├── deep_scan_verifier.py   # Firecracker + VirusTotal verifier
│   ├── firecracker_sandbox.py  # VM lifecycle manager
│   ├── gemini_explainer.py     # Gemini-powered threat explanations
│   └── checker.py              # SecurityChecker (Strategy orchestrator)
│
├── interceptor/                # Runtime interception
│   ├── command_detector.py     # Regex-based install command parser
│   └── tty_wrapper.py          # PTY Man-in-the-Middle proxy
│
├── injection_locator/          # Prompt injection attribution
│   ├── injection_locator.py    # Two-phase binary-search locator
│   ├── embedding_locator.py    # Cosine-similarity embedding locator
│   ├── source_mapper.py        # Maps context entries to source files/URLs
│   └── models.py               # ContextEntry, InjectionReport dataclasses
│
├── scripts/
│   └── check_virustotal.py     # VirusTotal scanner deployed inside the VM
│
└── tests/
    ├── test_firecracker_sandbox.py
    ├── test_injection_locator.py
    └── integration/
        └── test_pipeline_scenarios.py  # 55 end-to-end scenarios
```

---

## Security Notes

- PromptGuard is a **defence-in-depth** layer. The BasicVerifier allowlist should be tuned to your organisation's approved packages.
- The PTY interception is **reactive** — it fires when the install command appears in Claude Code's output stream, typically just before execution.
- The Firecracker microVM provides **hardware-level KVM isolation**. Even a root-privileged package cannot escape the VM boundary to affect the host.
- The InjectionLocator re-prompts Claude using its `--print` headless mode. Each re-prompt counts against your Anthropic usage. The binary-search approach uses at most `2 × log₂(N)` calls; the embedding approach uses exactly one.
