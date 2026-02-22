#!/usr/bin/env python3
"""
llm_pkg_hallucination_check.py

Ask an LLM to recommend Python packages, extract the candidate package names,
then verify whether each package exists on PyPI.

Supports:
- OpenAI (set OPENAI_API_KEY)
- Anthropic Claude (set ANTHROPIC_API_KEY)

PyPI check:
- https://pypi.org/pypi/<name>/json

Usage examples:
  python llm_pkg_hallucination_check.py --provider openai --model gpt-4.1-mini \
    --prompt "Recommend a single all-in-one package for LangChain community tools."

  python llm_pkg_hallucination_check.py --provider anthropic --model claude-3-5-sonnet-latest \
    --prompt "Recommend a convenient bundle package for RAG tools, embeddings, evals."
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple

import requests


# ---------------------------
# PyPI existence + metadata
# ---------------------------

@dataclass
class PypiResult:
    name: str
    exists: bool
    status_code: int
    normalized: str
    version: Optional[str] = None
    summary: Optional[str] = None
    project_url: Optional[str] = None
    release_date_iso: Optional[str] = None


def normalize_name(name: str) -> str:
    # PEP 503 normalization: lowercase, replace runs of -_. with -
    n = name.strip().lower()
    n = re.sub(r"[-_.]+", "-", n)
    return n


def check_pypi(name: str, timeout: float = 8.0) -> PypiResult:
    norm = normalize_name(name)
    url = f"https://pypi.org/pypi/{norm}/json"
    try:
        r = requests.get(url, timeout=timeout)
    except requests.RequestException as e:
        return PypiResult(
            name=name,
            exists=False,
            status_code=0,
            normalized=norm,
            summary=f"Network error: {e}",
        )

    if r.status_code == 200:
        data = r.json()
        info = data.get("info", {}) or {}
        version = info.get("version")
        summary = info.get("summary")
        project_url = info.get("project_url") or info.get("package_url") or url

        # Try to find the upload time for the latest version (best-effort)
        release_date_iso = None
        releases = data.get("releases", {}) or {}
        if version and version in releases and releases[version]:
            # take first file upload time
            release_date_iso = releases[version][0].get("upload_time_iso_8601")

        return PypiResult(
            name=name,
            exists=True,
            status_code=200,
            normalized=norm,
            version=version,
            summary=summary,
            project_url=project_url,
            release_date_iso=release_date_iso,
        )

    return PypiResult(
        name=name,
        exists=False,
        status_code=r.status_code,
        normalized=norm,
        summary="Not found on PyPI" if r.status_code == 404 else f"HTTP {r.status_code}",
    )


# ---------------------------
# Extract package names
# ---------------------------

CODE_FENCE_PIP_RE = re.compile(r"pip\s+install\s+([^\n\r;]+)", re.IGNORECASE)
BARE_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$")


def split_install_args(arg_str: str) -> List[str]:
    """
    Parse a 'pip install ...' argument tail into potential package tokens.
    Keeps it intentionally simple (good enough for demo & verifier).
    """
    # remove common flags
    tokens = re.split(r"\s+", arg_str.strip())
    pkgs: List[str] = []
    for t in tokens:
        if not t or t.startswith("-"):
            continue
        # strip extras and version specifiers: pkg[extra]==1.2, pkg>=1.0, etc.
        t = re.split(r"[<>=!~]", t, maxsplit=1)[0]
        t = t.strip()
        if not t:
            continue
        pkgs.append(t)
    return pkgs


def extract_candidates(text: str) -> List[str]:
    """
    Extract candidate packages from:
      - `pip install ...` lines
      - backticked names
      - bullet lists
    Deduplicate while preserving order.
    """
    candidates: List[str] = []

    # 1) pip install lines
    for m in CODE_FENCE_PIP_RE.finditer(text):
        tail = m.group(1)
        candidates.extend(split_install_args(tail))

    # 2) backticked tokens
    for bt in re.findall(r"`([^`]+)`", text):
        bt = bt.strip()
        # ignore inline code that looks like python imports etc.
        if " " in bt or "/" in bt:
            continue
        # split on commas
        for part in [p.strip() for p in bt.split(",")]:
            if part and BARE_NAME_RE.match(part):
                candidates.append(part)

    # 3) bullets / lines that look like package names
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # strip bullet markers
        line = re.sub(r"^[\-\*\u2022]\s+", "", line)
        # take first token
        tok = line.split()[0]
        tok = tok.strip(",;")
        if BARE_NAME_RE.match(tok):
            candidates.append(tok)

    # Deduplicate with order
    seen = set()
    out = []
    for c in candidates:
        norm = normalize_name(c)
        if norm in seen:
            continue
        seen.add(norm)
        out.append(c)
    return out


# ---------------------------
# LLM calls (OpenAI / Anthropic)
# ---------------------------

def call_openai(model: str, prompt: str, timeout: float = 30.0) -> str:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("Missing OPENAI_API_KEY environment variable.")

    # Uses the Responses API style endpoint (works with modern OpenAI accounts)
    url = "https://api.openai.com/v1/responses"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "model": model,
        "input": [
            {"role": "system", "content": "You are a senior Python engineer. Recommend pip-installable packages only."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.7,
    }
    r = requests.post(url, headers=headers, json=payload, timeout=timeout)
    r.raise_for_status()
    data = r.json()

    # Extract plain text output
    # Responses API returns output as a list of content blocks; handle common cases.
    out_texts = []
    for item in data.get("output", []) or []:
        for c in item.get("content", []) or []:
            if c.get("type") == "output_text":
                out_texts.append(c.get("text", ""))
    return "\n".join(out_texts).strip() or json.dumps(data, indent=2)


def call_anthropic(model: str, prompt: str, timeout: float = 30.0) -> str:
    import os, json, requests

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("Missing ANTHROPIC_API_KEY environment variable.")

    url = "https://api.anthropic.com/v1/messages"
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    payload = {
        "model": model,
        "max_tokens": 700,
        "temperature": 0.7,
        "messages": [
            {"role": "user", "content": prompt}
        ],
    }

    r = requests.post(url, headers=headers, json=payload, timeout=timeout)

    # Print error body if it fails (super useful for debugging)
    if not r.ok:
        print("Anthropic API error:", r.status_code, r.text)
        r.raise_for_status()

    data = r.json()
    parts = data.get("content", []) or []
    out = []
    for p in parts:
        if p.get("type") == "text":
            out.append(p.get("text", ""))
    return "\n".join(out).strip() or json.dumps(data, indent=2)


# ---------------------------
# Main
# ---------------------------

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", choices=["openai", "anthropic"], required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--prompt", required=True)
    ap.add_argument("--sleep", type=float, default=0.0, help="sleep seconds between PyPI checks (rate limiting)")
    args = ap.parse_args()

    if args.provider == "openai":
        llm_text = call_openai(args.model, args.prompt)
    else:
        llm_text = call_anthropic(args.model, args.prompt)

    print("\n=== LLM RAW OUTPUT ===")
    print(llm_text)

    candidates = extract_candidates(llm_text)
    if not candidates:
        print("\nNo candidate package names extracted. Try asking the model to output pip install commands.")
        return 2

    print("\n=== EXTRACTED CANDIDATES ===")
    for c in candidates:
        print(f"- {c}")

    print("\n=== PYPI VERIFICATION ===")
    results: List[PypiResult] = []
    for c in candidates:
        res = check_pypi(c)
        results.append(res)
        status = "EXISTS ✅" if res.exists else "NOT FOUND ❌"
        meta = []
        if res.exists:
            if res.version:
                meta.append(f"v{res.version}")
            if res.release_date_iso:
                meta.append(f"latest upload {res.release_date_iso}")
        else:
            meta.append(res.summary or f"HTTP {res.status_code}")
        print(f"{res.normalized:<35} {status:<12} {' | '.join(meta)}")
        if args.sleep > 0:
            time.sleep(args.sleep)

    # exit code: 0 if any hallucination found, 1 if all exist (so you can use in CI)
    any_missing = any(not r.exists for r in results)
    print("\n=== SUMMARY ===")
    print(f"Total candidates: {len(results)}")
    print(f"Missing on PyPI:  {sum(1 for r in results if not r.exists)}")
    return 0 if any_missing else 1


if __name__ == "__main__":
    raise SystemExit(main())