"""
vt_summarizer.py — Map VirusTotal engine labels to a human-readable summary.

Public API
----------
    summarize_vt(vt_json, resolver_signals) -> {headline, one_liner, bullets, confidence}

Contract
--------
- ONLY evidence present in vt_json / resolver_signals is used.
- Never speculates about behaviour — only reports what engines flagged.
- Verdict: most severe of (VT signal, resolver signal). VT never downgraded.
- one_liner is guaranteed ≤ 22 words.
- bullets is guaranteed ≤ 3 items.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Tunable thresholds
# ---------------------------------------------------------------------------

_BLOCK_THRESHOLD   = 5     # malicious engines required to issue BLOCKED
_HIGH_COVERAGE     = 50    # engines scanned → "high" confidence possible
_LOW_COVERAGE      = 15    # engines scanned → "low" confidence

_VERDICT_RANK: dict[str, int] = {"ALLOWED": 0, "QUARANTINED": 1, "BLOCKED": 2}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _vt_verdict(malicious: int, suspicious: int) -> str:
    if malicious >= _BLOCK_THRESHOLD:
        return "BLOCKED"
    if malicious >= 1 or suspicious >= 1:
        return "QUARANTINED"
    return "ALLOWED"


def _resolver_verdict(rs: dict | None) -> str:
    if not rs:
        return "ALLOWED"
    v = (rs.get("verdict") or "ALLOW").upper()
    if "BLOCK" in v:
        return "BLOCKED"
    if "QUARANTINE" in v:
        return "QUARANTINED"
    return "ALLOWED"


def _confidence(malicious: int, suspicious: int, harmless: int, undetected: int) -> str:
    total = malicious + suspicious + harmless + undetected
    if total < _LOW_COVERAGE:
        return "low"
    # Clear signal with good coverage
    if malicious >= 10 and total >= _HIGH_COVERAGE:
        return "high"
    if malicious == 0 and suspicious == 0 and harmless >= 40:
        return "high"
    return "medium"


def _truncate_words(text: str, max_words: int = 22) -> str:
    words = text.split()
    if len(words) <= max_words:
        return text
    return " ".join(words[:max_words]).rstrip(".,;:") + "…"


def _extract_labels(results: dict, max_labels: int = 3) -> list[str]:
    """
    Return up to *max_labels* unique label strings from engine results where
    category is 'malicious' (collected first) or 'suspicious'.
    Null / empty labels are skipped.
    """
    malicious_labels: list[str] = []
    suspicious_labels: list[str] = []
    seen: set[str] = set()

    for engine_data in results.values():
        cat   = (engine_data.get("category") or "").lower()
        label = (engine_data.get("result")   or "").strip()
        if not label or label in seen:
            continue
        seen.add(label)
        if cat == "malicious":
            malicious_labels.append(label)
        elif cat == "suspicious":
            suspicious_labels.append(label)

    return (malicious_labels + suspicious_labels)[:max_labels]


def _resolver_bullet(rs: dict) -> str | None:
    """
    Pick the single most informative bullet from resolver signals.
    Priority: typosquat similarity > package freshness > publisher signals > freeform reason.
    """
    evidence = rs.get("evidence") or {}

    sim           = float(evidence.get("best_similarity") or 0.0)
    closest       = evidence.get("closest_known_good") or ""
    age           = evidence.get("age_days")
    missing_links = bool(evidence.get("missing_links", False))
    release_count = evidence.get("release_count")

    if sim >= 0.85 and closest:
        pct = f"{sim:.0%}"
        return f"Name closely resembles known package '{closest}' (similarity {pct})."

    if isinstance(age, (int, float)) and age < 30:
        d = int(age)
        return f"Package is only {d} day{'s' if d != 1 else ''} old on PyPI."

    if missing_links and isinstance(release_count, int) and release_count < 3:
        r = release_count
        return (
            f"Publisher has no project links and only {r} "
            f"release{'s' if r != 1 else ''}."
        )

    # Fall back to first non-boilerplate reason string
    for reason in rs.get("reasons") or []:
        if "No high-risk" not in reason and "lockfile" not in reason.lower():
            return reason.rstrip(".") + "."

    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def summarize_vt(
    vt_json: dict,
    resolver_signals: dict | None = None,
) -> dict:
    """
    Summarise a VirusTotal package scan alongside optional ClaudeGate resolver
    signals.

    Parameters
    ----------
    vt_json :
        Raw VirusTotal API response (top-level envelope or bare ``attributes``
        dict).  Reads ``attributes.last_analysis_stats`` and
        ``attributes.last_analysis_results``.
    resolver_signals :
        Optional output of the ClaudeGate verifier (POST /verify response).
        Contributes a supplementary bullet and can raise (never lower) the
        verdict.

    Returns
    -------
    dict
        {
          "headline":   "BLOCKED" | "QUARANTINED" | "ALLOWED",
          "one_liner":  str,   # ≤ 22 words
          "bullets":    list,  # ≤ 3 items
          "confidence": "low" | "medium" | "high",
        }
    """
    # ---- Unpack attributes (tolerate both API envelope shapes) ----
    attrs = (
        vt_json.get("attributes")
        or (vt_json.get("data") or {}).get("attributes")
        or vt_json
    )
    stats   = attrs.get("last_analysis_stats")   or {}
    results = attrs.get("last_analysis_results") or {}

    malicious  = int(stats.get("malicious",  0))
    suspicious = int(stats.get("suspicious", 0))
    harmless   = int(stats.get("harmless",   0))
    undetected = int(stats.get("undetected", 0))
    total      = malicious + suspicious + harmless + undetected

    # ---- Verdict: take the more severe of VT and resolver ----
    vt_v  = _vt_verdict(malicious, suspicious)
    res_v = _resolver_verdict(resolver_signals)
    headline = vt_v if _VERDICT_RANK[vt_v] >= _VERDICT_RANK[res_v] else res_v

    # ---- Confidence ----
    confidence = _confidence(malicious, suspicious, harmless, undetected)

    # ---- Up to 3 unique engine labels (malicious priority) ----
    labels = _extract_labels(results)

    # ---- One-liner (≤ 22 words) ----
    flagged = malicious + suspicious
    if total == 0:
        one_liner = "No VirusTotal scan results available."
    elif flagged == 0:
        one_liner = f"All {total} security engines report this package as clean."
    elif malicious >= _BLOCK_THRESHOLD:
        label_part = f" ({labels[0]})" if labels else ""
        one_liner = (
            f"{malicious} of {total} engines flagged this package "
            f"as malicious{label_part}."
        )
    else:
        parts = []
        if malicious:
            parts.append(f"{malicious} malicious")
        if suspicious:
            parts.append(f"{suspicious} suspicious")
        flag_str  = " and ".join(parts)
        flag_word = "flag" if flagged == 1 else "flags"
        label_part = f"; labels include {labels[0]}" if labels else ""
        one_liner = (
            f"{flag_str.capitalize()} {flag_word} from "
            f"{total} engines scanned{label_part}."
        )

    one_liner = _truncate_words(one_liner)

    # ---- Bullets (max 3) ----
    bullets: list[str] = []

    # Bullet 1 — VT engine counts (always present)
    if malicious == 0 and suspicious == 0:
        bullets.append(
            f"{harmless} of {total} engines: harmless; {undetected} undetected."
        )
    else:
        bullets.append(
            f"{malicious} malicious, {suspicious} suspicious "
            f"out of {total} engines scanned."
        )

    # Bullet 2 — engine label strings (only if flagged engines provided labels)
    if labels:
        bullets.append(f"Engine labels: {', '.join(labels)}.")

    # Bullet 3 — resolver signal (if provided and space remains)
    if resolver_signals and len(bullets) < 3:
        rb = _resolver_bullet(resolver_signals)
        if rb:
            bullets.append(rb)

    return {
        "headline":   headline,
        "one_liner":  one_liner,
        "bullets":    bullets,
        "confidence": confidence,
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
#
# Each fixture is a (vt_json, resolver_signals) pair.
# vt_json.attributes.last_analysis_results shows a representative subset of
# engine results; last_analysis_stats always reflects the full engine count.

FIXTURE_BLOCKED = (
    # vt_json ---------------------------------------------------------------
    {
        "attributes": {
            "last_analysis_stats": {
                "malicious":  18,
                "suspicious":  3,
                "harmless":   47,
                "undetected":  4,
            },
            # Representative subset — real VT responses contain ~72 entries
            "last_analysis_results": {
                "Kaspersky":    {"category": "malicious",  "result": "Trojan.Python.Agent.gen"},
                "Sophos":       {"category": "malicious",  "result": "Troj/PyAgent-A"},
                "ESET-NOD32":   {"category": "malicious",  "result": "Python/TrojanDownloader.Agent"},
                "BitDefender":  {"category": "malicious",  "result": "Gen:Variant.Trojan.Python.1"},
                "Fortinet":     {"category": "malicious",  "result": "PythonTrojan/Agent.A"},
                "DrWeb":        {"category": "malicious",  "result": "Python.Trojan.195"},
                "Microsoft":    {"category": "malicious",  "result": "TrojanDownloader:Python/Agent"},
                "Avast":        {"category": "malicious",  "result": "Python:Trojan-gen"},
                "Malwarebytes": {"category": "suspicious", "result": "PUP.Optional.Suspicious.Python"},
                "ClamAV":       {"category": "harmless",   "result": None},
                "McAfee":       {"category": "harmless",   "result": None},
            },
        }
    },
    # resolver_signals -------------------------------------------------------
    {
        "package":    "reqeusts",
        "version":    "0.0.1",
        "risk_score": 92,
        "verdict":    "BLOCK",
        "reasons": [
            "Name is highly similar to 'requests' (sim=0.92)",
            "New package (age=2 days)",
            "Low publisher signals (few releases / missing links)",
        ],
        "evidence": {
            "age_days":          2,
            "best_similarity":   0.92,
            "closest_known_good":"requests",
            "release_count":     1,
            "missing_links":     True,
            "features": {"x_fresh": 0.9889, "x_sim": 0.5385, "x_pub": 1.0},
            "calibration": {"z": 2.80, "p": 0.943},
            "model": "logistic_v1",
        },
    },
)

FIXTURE_QUARANTINED = (
    # vt_json ---------------------------------------------------------------
    {
        "attributes": {
            "last_analysis_stats": {
                "malicious":  2,
                "suspicious": 4,
                "harmless":  58,
                "undetected": 8,
            },
            "last_analysis_results": {
                "Kaspersky":    {"category": "suspicious", "result": "HEUR:Backdoor.Python.Generic"},
                "Sophos":       {"category": "malicious",  "result": "Sus/PythonDrop-A"},
                "DrWeb":        {"category": "suspicious", "result": "Python.Suspicious.Obfuscated"},
                "Malwarebytes": {"category": "malicious",  "result": "Trojan.Dropper.Python"},
                "ESET-NOD32":   {"category": "suspicious", "result": "Python/Suspicious.Agent"},
                "ClamAV":       {"category": "harmless",   "result": None},
                "Microsoft":    {"category": "harmless",   "result": None},
                "McAfee":       {"category": "harmless",   "result": None},
            },
        }
    },
    # resolver_signals -------------------------------------------------------
    {
        "package":    "numpy-utils",
        "version":    "0.1.0",
        "risk_score": 55,
        "verdict":    "QUARANTINE",
        "reasons": [
            "New package (age=8 days)",
            "Low publisher signals (few releases / missing links)",
        ],
        "evidence": {
            "age_days":           8,
            "best_similarity":    0.71,
            "closest_known_good": "numpy",
            "release_count":      2,
            "missing_links":      True,
            "features": {"x_fresh": 0.9556, "x_sim": 0.0, "x_pub": 0.5},
            "calibration": {"z": 0.51, "p": 0.625},
            "model": "logistic_v1",
        },
    },
)

FIXTURE_ALLOWED = (
    # vt_json ---------------------------------------------------------------
    {
        "attributes": {
            "last_analysis_stats": {
                "malicious":  0,
                "suspicious": 0,
                "harmless":   70,
                "undetected":  2,
            },
            "last_analysis_results": {
                "Kaspersky":    {"category": "harmless",   "result": None},
                "Sophos":       {"category": "harmless",   "result": None},
                "ESET-NOD32":   {"category": "harmless",   "result": None},
                "BitDefender":  {"category": "harmless",   "result": None},
                "Microsoft":    {"category": "harmless",   "result": None},
                "McAfee":       {"category": "harmless",   "result": None},
                "ClamAV":       {"category": "harmless",   "result": None},
                "Avast":        {"category": "harmless",   "result": None},
                "Malwarebytes": {"category": "harmless",   "result": None},
                "DrWeb":        {"category": "undetected", "result": None},
            },
        }
    },
    # resolver_signals -------------------------------------------------------
    {
        "package":    "requests",
        "version":    "2.31.0",
        "risk_score": 12,
        "verdict":    "ALLOW",
        "reasons": ["No high-risk signals triggered"],
        "evidence": {
            "age_days":           4851,
            "best_similarity":    0.67,
            "closest_known_good": "httpx",
            "release_count":      75,
            "missing_links":      False,
            "features": {"x_fresh": 0.0, "x_sim": 0.0, "x_pub": 0.0},
            "calibration": {"z": -2.20, "p": 0.10},
            "model": "logistic_v1",
        },
    },
)


# ---------------------------------------------------------------------------
# Demo runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json

    _PALETTE = {
        "BLOCKED":     "\033[1;31m",   # bold red
        "QUARANTINED": "\033[1;33m",   # bold yellow
        "ALLOWED":     "\033[1;32m",   # bold green
        "RESET":       "\033[0m",
    }

    cases = [
        ("reqeusts 0.0.1",    FIXTURE_BLOCKED),
        ("numpy-utils 0.1.0", FIXTURE_QUARANTINED),
        ("requests 2.31.0",   FIXTURE_ALLOWED),
    ]

    for pkg_label, (vt_json, resolver) in cases:
        result = summarize_vt(vt_json, resolver)

        h   = result["headline"]
        col = _PALETTE.get(h, "")
        rst = _PALETTE["RESET"]

        print(f"\n{'━'*62}")
        print(f"  Package : {pkg_label}")
        print(f"  Verdict : {col}{h}{rst}  (confidence: {result['confidence']})")
        print(f"{'━'*62}")
        print(f"  {result['one_liner']}")
        print()
        for b in result["bullets"]:
            print(f"  • {b}")
        print()
        print("  Raw JSON:")
        print(
            "\n".join(
                "    " + line
                for line in json.dumps(result, indent=2).splitlines()
            )
        )

    print(f"\n{'━'*62}\n")
