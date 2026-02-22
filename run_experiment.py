#!/usr/bin/env python3
"""
run_experiment.py — Measure LLM package hallucination rates.

Usage
-----
    # Fastest: mock mode uses pre-saved sample responses
    python run_experiment.py --provider mock --n_prompts 60 --out results.json

    # Live inference (requires OPENAI_API_KEY)
    python run_experiment.py --provider openai --model gpt-4o-mini --n_prompts 40

    # Live inference (requires ANTHROPIC_API_KEY)
    python run_experiment.py --provider anthropic --model claude-haiku-4-5-20251001

    # Bypass disk cache for fresh PyPI lookups
    python run_experiment.py --provider mock --force-refresh
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import textwrap
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from llm_adapter import get_adapter
from prompts import Prompt, generate_prompts
from pypi_check import PackageStatus, check_package, normalize_name


# ---------------------------------------------------------------------------
# Package name extraction
# ---------------------------------------------------------------------------

# Words that are never package names even if they appear in pip-install lines
_STOPWORDS = frozenset({
    "python", "python3", "pip", "pip3", "install", "library", "package",
    "module", "import", "use", "using", "tool", "framework", "the", "a",
    "an", "and", "or", "not", "for", "to", "of", "in", "is", "are",
    "with", "at", "by", "from", "if", "as", "on", "be", "it", "you",
    "your", "this", "that", "also", "can", "will", "should", "note",
    "example", "bash", "shell", "script", "code", "run", "cmd", "command",
    "requirements", "etc", "optional", "minimal", "full", "basic",
    "above", "below", "following", "standard", "additional",
    "primary", "alternative", "recommended", "supported", "latest",
    "version", "see", "check", "try", "add", "both", "all", "one",
    "two", "three", "first", "second", "third", "step", "steps",
})

_SKIP_EXTENSIONS = frozenset({
    ".txt", ".py", ".cfg", ".toml", ".json", ".yml", ".yaml", ".ini",
    ".sh", ".bat", ".md", ".rst", ".lock",
})


def _normalize_token(raw: str) -> str | None:
    """Strip version specifiers, extras, URLs; return normalised name or None."""
    raw = raw.strip('"\'')
    # Skip URL-style requirements
    if raw.startswith(("git+", "http://", "https://", "file://")):
        return None
    # Strip extras: foo[bar,baz] → foo
    raw = re.sub(r"\[.*?\]", "", raw)
    # Strip version specifiers: foo>=1.0 → foo
    raw = re.split(r"[><=!~;@#]", raw)[0]
    # Normalise: underscores → hyphens, lowercase
    norm = raw.replace("_", "-").lower().strip("-").strip()
    return norm if norm else None


def _is_valid(name: str) -> bool:
    """Return True if *name* looks like a plausible PyPI package name."""
    if not name or name in _STOPWORDS:
        return False
    if len(name) < 2 or len(name) > 60:
        return False
    if any(name.endswith(ext) for ext in _SKIP_EXTENSIONS):
        return False
    # Must start with a letter; only alphanumeric, hyphen, dot allowed
    if not re.match(r"^[a-z][a-z0-9\-\.]*$", name):
        return False
    # Skip standalone version numbers
    if re.match(r"^\d+\.\d+", name):
        return False
    return True


def extract_packages(text: str) -> list[str]:
    """
    Parse an LLM response and return a deduplicated, normalised list of
    candidate package names.

    Extraction sources (in priority order):
      1. ``pip install`` lines       — highest signal; usually explicit
      2. Backtick-quoted names       — markdown inline code, e.g. `requests`
      3. Bold-marked names           — e.g. **requests**
      4. Bullet-list first tokens    — e.g. "- requests: HTTP library"
    """
    found: set[str] = set()

    # 1. pip install lines
    for m in re.finditer(r"pip(?:3)?\s+install\s+([^\n\r]+)", text, re.IGNORECASE):
        for token in m.group(1).split():
            if token.startswith("-"):
                continue
            norm = _normalize_token(token)
            if norm and _is_valid(norm):
                found.add(norm)

    # 2. Backtick-quoted names
    for m in re.finditer(r"`([A-Za-z][A-Za-z0-9_\-\.]{1,59})`", text):
        norm = _normalize_token(m.group(1))
        if norm and _is_valid(norm):
            found.add(norm)

    # 3. **bold** names
    for m in re.finditer(r"\*\*([A-Za-z][A-Za-z0-9_\-\.]{1,59})\*\*", text):
        norm = _normalize_token(m.group(1))
        if norm and _is_valid(norm):
            found.add(norm)

    # 4. Bullet-list first tokens:  "- PackageName:" / "- PackageName -" / "* PackageName —"
    for m in re.finditer(
        r"^[ \t]*[-*•]\s+\**`?([A-Za-z][A-Za-z0-9_\-\.]{1,59})`?\**\s*[-:—(]",
        text,
        re.MULTILINE,
    ):
        norm = _normalize_token(m.group(1))
        if norm and _is_valid(norm):
            found.add(norm)

    return sorted(found)


def _find_intro_sentence(text: str, pkg_name: str) -> str:
    """
    Return the first line in *text* that mentions *pkg_name* (or its
    underscore variant).  Truncated to 200 chars for safety.
    """
    variants = {pkg_name, pkg_name.replace("-", "_"), pkg_name.replace("-", "")}
    for line in text.splitlines():
        ll = line.lower()
        if any(v in ll for v in variants):
            return line.strip()[:200]
    return ""


# ---------------------------------------------------------------------------
# Privacy helpers
# ---------------------------------------------------------------------------


def _hash_name(name: str) -> str:
    """Return the first 8 hex chars of SHA-256(name)."""
    return hashlib.sha256(name.encode()).hexdigest()[:8]


# ---------------------------------------------------------------------------
# Core experiment loop
# ---------------------------------------------------------------------------


def run_experiment(
    prompts: list[Prompt],
    adapter,
    force_refresh: bool = False,
    verbose: bool = False,
) -> list[dict]:
    """
    For each prompt: call the LLM, extract packages, verify on PyPI.
    Returns a list of per-prompt result dicts.
    """
    results: list[dict] = []

    # Cache already-verified names within this run to avoid duplicate HTTP calls
    pkg_cache: dict[str, dict] = {}

    for i, prompt in enumerate(prompts, 1):
        print(f"\n[{i:>3}/{len(prompts)}] {prompt.id}  [{prompt.category}]")
        if verbose:
            print(textwrap.fill(f"  Prompt: {prompt.text}", width=90))

        # --- LLM call ---
        try:
            response = adapter.complete(prompt.text)
        except Exception as exc:
            print(f"  ERROR from LLM: {exc}")
            response = ""

        # --- Extract packages ---
        packages = extract_packages(response)
        if verbose:
            print(f"  Extracted: {packages}")
        else:
            print(f"  Extracted {len(packages)} candidate(s): {', '.join(packages) or '—'}")

        # --- Verify each package ---
        pkg_results: list[dict] = []
        for pkg in packages:
            norm = normalize_name(pkg)
            if norm not in pkg_cache:
                pkg_cache[norm] = check_package(pkg, force_refresh=force_refresh)
            result = pkg_cache[norm]
            intro = _find_intro_sentence(response, pkg)
            pkg_results.append({
                "name": pkg,
                "normalized": norm,
                "status": result["status"],
                "status_code": result.get("status_code"),
                "intro_sentence": intro,
            })

        # --- Build per-prompt record ---
        nonexistent = [p for p in pkg_results if p["status"] == PackageStatus.NOT_FOUND]
        ambiguous   = [p for p in pkg_results if p["status"] == PackageStatus.AMBIGUOUS]
        existing    = [p for p in pkg_results if p["status"] == PackageStatus.EXISTS]

        total = len(pkg_results)
        h_rate = len(nonexistent) / total if total else 0.0

        flag = "✗ HALLUCINATED" if nonexistent else ("⚠ AMBIGUOUS" if ambiguous else "✓ clean")
        print(f"  → {len(existing)} exist / {len(nonexistent)} not found / "
              f"{len(ambiguous)} ambiguous   [{flag}]")

        results.append({
            "prompt_id": prompt.id,
            "prompt_text": prompt.text,
            "category": prompt.category,
            "risk_pattern": prompt.risk_pattern,
            "raw_response": response,
            "suggested_packages": [p["name"] for p in pkg_results],
            "pkg_results": pkg_results,
            "hallucination_rate": round(h_rate, 4),
            "n_exist": len(existing),
            "n_not_found": len(nonexistent),
            "n_ambiguous": len(ambiguous),
        })

    return results


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


def _pct(n: int, d: int) -> str:
    return f"{100 * n / d:.1f}%" if d else "—"


def generate_report(results: list[dict], safe_mode: bool = True) -> None:
    """Print a human-readable summary to stdout."""
    sep = "─" * 70

    # Aggregate
    all_pkgs: list[dict] = []
    for r in results:
        all_pkgs.extend(r["pkg_results"])

    total_unique = len({p["normalized"] for p in all_pkgs})
    total_not_found = len({
        p["normalized"] for p in all_pkgs if p["status"] == PackageStatus.NOT_FOUND
    })
    total_ambiguous = len({
        p["normalized"] for p in all_pkgs if p["status"] == PackageStatus.AMBIGUOUS
    })
    overall_rate = total_not_found / total_unique if total_unique else 0.0

    print(f"\n{'═'*70}")
    print("  HALLUCINATION EXPERIMENT — SUMMARY REPORT")
    print(f"{'═'*70}")
    print(f"  Prompts evaluated      : {len(results)}")
    print(f"  Unique packages found  : {total_unique}")
    print(f"  Not found on PyPI      : {total_not_found}  ({_pct(total_not_found, total_unique)})")
    print(f"  Ambiguous (timeout)    : {total_ambiguous}  ({_pct(total_ambiguous, total_unique)})")
    print(f"  Overall hallucination  : {overall_rate:.1%}")
    print(f"{sep}")

    # Per-category breakdown
    cat_stats: dict[str, dict] = defaultdict(lambda: {"prompts": 0, "pkgs": 0, "nf": 0})
    for r in results:
        cs = cat_stats[r["category"]]
        cs["prompts"] += 1
        cs["pkgs"]   += len(r["pkg_results"])
        cs["nf"]     += r["n_not_found"]

    print("\n  BREAKDOWN BY CATEGORY")
    print(f"  {'Category':<25} {'Prompts':>7} {'Pkgs':>6} {'Not found':>10} {'Rate':>8}")
    print(f"  {'-'*25} {'-'*7} {'-'*6} {'-'*10} {'-'*8}")
    for cat, cs in sorted(cat_stats.items()):
        print(f"  {cat:<25} {cs['prompts']:>7} {cs['pkgs']:>6} "
              f"{cs['nf']:>10} {_pct(cs['nf'], cs['pkgs']):>8}")
    print(f"{sep}")

    # Per-risk-pattern breakdown
    rp_stats: dict[str, dict] = defaultdict(lambda: {"prompts": 0, "pkgs": 0, "nf": 0})
    for r in results:
        rps = rp_stats[r["risk_pattern"]]
        rps["prompts"] += 1
        rps["pkgs"]   += len(r["pkg_results"])
        rps["nf"]     += r["n_not_found"]

    print("\n  TOP RISK PATTERNS")
    rows = sorted(rp_stats.items(), key=lambda kv: kv[1]["nf"] / max(kv[1]["pkgs"], 1), reverse=True)
    print(f"  {'Risk pattern':<22} {'Prompts':>7} {'Pkgs':>6} {'Not found':>10} {'Rate':>8}")
    print(f"  {'-'*22} {'-'*7} {'-'*6} {'-'*10} {'-'*8}")
    for rp, rps in rows:
        print(f"  {rp:<22} {rps['prompts']:>7} {rps['pkgs']:>6} "
              f"{rps['nf']:>10} {_pct(rps['nf'], rps['pkgs']):>8}")
    print(f"{sep}")

    # Per-prompt table (hallucination_rate desc)
    print("\n  PER-PROMPT HALLUCINATION RATES (top 15)")
    per_prompt = sorted(results, key=lambda r: r["hallucination_rate"], reverse=True)[:15]
    print(f"  {'ID':<6} {'Category':<25} {'Rate':>6} {'NF':>4} {'Total':>6}")
    print(f"  {'-'*6} {'-'*25} {'-'*6} {'-'*4} {'-'*6}")
    for r in per_prompt:
        print(f"  {r['prompt_id']:<6} {r['category']:<25} "
              f"{r['hallucination_rate']:>6.1%} {r['n_not_found']:>4} "
              f"{len(r['pkg_results']):>6}")
    print(f"{sep}")

    # Example cases (up to 5 prompts that had ≥1 hallucination)
    halluc_examples = [r for r in results if r["n_not_found"] > 0][:5]
    print(f"\n  EXAMPLE HALLUCINATION CASES (safe mode={'ON' if safe_mode else 'OFF'})")
    if not halluc_examples:
        print("  No hallucinated packages detected in this run.")
    for r in halluc_examples:
        print(f"\n  ▸ {r['prompt_id']}  category={r['category']}  "
              f"risk_pattern={r['risk_pattern']}")
        snippet = r["prompt_text"][:120].replace("\n", " ")
        print(f"    Prompt snippet : {snippet}…")
        for pkg in r["pkg_results"]:
            if pkg["status"] != PackageStatus.NOT_FOUND:
                continue
            display = (_hash_name(pkg["normalized"]) + "…") if safe_mode else pkg["name"]
            intro = pkg["intro_sentence"] or "(no intro found)"
            print(f"    Not-found name : {display}")
            print(f"    Introduced via : {intro[:160]}")
    print(f"\n{'═'*70}\n")


# ---------------------------------------------------------------------------
# JSON output (CodeGate Incident Detail compatible)
# ---------------------------------------------------------------------------


def build_json_output(
    results: list[dict],
    provider: str,
    model: str,
    n_prompts: int,
) -> dict[str, Any]:
    """
    Build a JSON-serialisable dict compatible with a UI Incident Detail view.
    Nonexistent package names are hashed (SHA-256 prefix) for safe disclosure.
    """
    all_pkgs: list[dict] = []
    for r in results:
        all_pkgs.extend(r["pkg_results"])

    total_unique = len({p["normalized"] for p in all_pkgs})
    total_nf     = len({p["normalized"] for p in all_pkgs if p["status"] == PackageStatus.NOT_FOUND})
    total_amb    = len({p["normalized"] for p in all_pkgs if p["status"] == PackageStatus.AMBIGUOUS})

    incidents = []
    for r in results:
        pkg_evidence = {
            p["normalized"]: {
                "status": p["status"],
                "status_code": p["status_code"],
            }
            for p in r["pkg_results"]
        }
        nonexistent_hashed = [
            {
                "hash_prefix": _hash_name(p["normalized"]),
                "category": r["category"],
                "intro_sentence": p["intro_sentence"][:200] if p["intro_sentence"] else None,
            }
            for p in r["pkg_results"]
            if p["status"] == PackageStatus.NOT_FOUND
        ]

        incidents.append({
            "prompt_id": r["prompt_id"],
            "prompt_text": r["prompt_text"],
            "category": r["category"],
            "risk_pattern": r["risk_pattern"],
            "suggested_packages": r["suggested_packages"],
            "nonexistent_packages_hashed": nonexistent_hashed,
            "hallucination_rate": r["hallucination_rate"],
            "evidence": pkg_evidence,
        })

    return {
        "experiment_id": hashlib.sha256(
            (provider + model + datetime.now(timezone.utc).isoformat()).encode()
        ).hexdigest()[:12],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "provider": provider,
        "model": model,
        "n_prompts_requested": n_prompts,
        "n_prompts_evaluated": len(results),
        "summary": {
            "total_unique_packages": total_unique,
            "not_found_count": total_nf,
            "ambiguous_count": total_amb,
            "hallucination_rate": round(total_nf / total_unique, 4) if total_unique else 0.0,
        },
        "incidents": incidents,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Measure LLM package hallucination rates across niche Python domains.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        Examples
        --------
          python run_experiment.py --provider mock --n_prompts 60
          python run_experiment.py --provider openai --model gpt-4o-mini --n_prompts 40
          python run_experiment.py --provider anthropic --model claude-haiku-4-5-20251001
          python run_experiment.py --provider mock --force-refresh --unsafe
        """),
    )
    p.add_argument("--provider",      default="mock",       help="LLM provider: mock | openai | anthropic")
    p.add_argument("--model",         default=None,         help="Model name override")
    p.add_argument("--n_prompts",     type=int, default=60, help="Number of prompts to sample (default 60)")
    p.add_argument("--out",           default="results.json", help="Output JSON file (default results.json)")
    p.add_argument("--seed",          type=int, default=42, help="Random seed for prompt sampling")
    p.add_argument("--force-refresh", action="store_true",  help="Bypass disk cache for PyPI lookups")
    p.add_argument("--verbose",       action="store_true",  help="Print full prompt text and extractions")
    p.add_argument("--unsafe",        action="store_true",
                   help="Print plain nonexistent names instead of hashed values (opt-in)")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    safe_mode = not args.unsafe

    print(f"ClaudeGate Hallucination Experiment")
    print(f"  provider : {args.provider}")
    print(f"  model    : {args.model or '(default)'}")
    print(f"  prompts  : {args.n_prompts}")
    print(f"  output   : {args.out}")
    print(f"  safe mode: {safe_mode}")

    # Build adapter
    try:
        adapter = get_adapter(args.provider, model=args.model)
    except Exception as exc:
        print(f"\nERROR: Could not initialise adapter — {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"  adapter  : {adapter.provider_name} / {adapter.model_name}\n")

    # Generate prompts
    prompts = generate_prompts(args.n_prompts, seed=args.seed)
    print(f"Generated {len(prompts)} prompts covering "
          f"{len({p.category for p in prompts})} categories.\n")

    # Run experiment
    results = run_experiment(
        prompts,
        adapter,
        force_refresh=args.force_refresh,
        verbose=args.verbose,
    )

    # Report
    generate_report(results, safe_mode=safe_mode)

    # Write JSON
    output = build_json_output(
        results,
        provider=adapter.provider_name,
        model=adapter.model_name,
        n_prompts=args.n_prompts,
    )
    out_path = Path(args.out)
    with out_path.open("w") as f:
        json.dump(output, f, indent=2)
    print(f"Results written to {out_path}")


if __name__ == "__main__":
    main()
