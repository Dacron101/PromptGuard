"""
ClaudeGate verification service — logistic risk scorer + native detectors.

Run:  uvicorn app:app --reload --port 8080
"""

from __future__ import annotations

import json
import math
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import requests as http_requests
from fastapi import FastAPI, Query
from pydantic import BaseModel
from rapidfuzz import fuzz

from native_detectors import detect_unicode_risk, inspect_artifacts_for_install_hooks

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CACHE_DIR = Path("./cache_pypi")
CACHE_DIR.mkdir(exist_ok=True)

KNOWN_GOOD = [
    "requests",
    "numpy",
    "pandas",
    "flask",
    "fastapi",
    "django",
    "pytest",
    "python-dotenv",
    "huggingface-hub",
    "uvicorn",
    "httpx",
    "pydantic",
]

# Logistic model weights
W_FRESH = 2.0
W_SIM   = 3.5
W_PUB   = 1.2
BIAS    = -2.2

# Verdict thresholds (logistic score)
BLOCK_THRESHOLD      = 80
QUARANTINE_THRESHOLD = 40

# Similarity thresholds
SIM_THRESHOLD = 0.85
SIM_SCALE_MAX = 0.98

# Freshness cap (days)
FRESH_CAP_DAYS = 180

# Policy override: RULE-HOOK-01 escalates to BLOCK when package is this fresh
HOOK_FRESH_DAYS = 7

# Verdict ordering for policy escalation
_VERDICT_RANK: dict[str, int] = {"ALLOW": 0, "QUARANTINE": 1, "BLOCK": 2}


def _escalate(current: str, floor: str) -> str:
    """Return whichever verdict is stricter."""
    return current if _VERDICT_RANK[current] >= _VERDICT_RANK[floor] else floor


# ---------------------------------------------------------------------------
# PyPI helpers (unchanged)
# ---------------------------------------------------------------------------


def normalize_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def cache_path(name: str) -> Path:
    return CACHE_DIR / f"pypi_{normalize_name(name)}.json"


def fetch_pypi(package: str, force_refresh: bool = False) -> dict:
    path = cache_path(package)
    if path.exists() and not force_refresh:
        with path.open() as f:
            return json.load(f)

    resp = http_requests.get(
        f"https://pypi.org/pypi/{package}/json",
        timeout=10,
        headers={"Accept": "application/json"},
    )
    resp.raise_for_status()
    data = resp.json()
    with path.open("w") as f:
        json.dump(data, f)
    return data


def _parse_upload_time(ts: str) -> datetime | None:
    if not ts:
        return None
    try:
        ts = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def compute_age_days(pypi_data: dict) -> int:
    earliest: datetime | None = None
    for file_list in pypi_data.get("releases", {}).values():
        for finfo in file_list:
            dt = _parse_upload_time(
                finfo.get("upload_time_iso_8601") or finfo.get("upload_time", "")
            )
            if dt and (earliest is None or dt < earliest):
                earliest = dt
    if earliest is None:
        return 0
    return (datetime.now(timezone.utc) - earliest).days


def compute_similarity(package: str) -> tuple[float, str | None]:
    pkg_lower = package.lower()
    best_sim = 0.0
    closest: str | None = None
    for known in KNOWN_GOOD:
        if known == pkg_lower:
            continue
        sim = fuzz.ratio(pkg_lower, known) / 100.0
        if sim > best_sim:
            best_sim = sim
            closest = known
    return best_sim, closest


def sigmoid(z: float) -> float:
    return 1.0 / (1.0 + math.exp(-z))


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


class VerifyRequest(BaseModel):
    ecosystem: str = "pypi"
    package: str
    version: Optional[str] = None
    project: Optional[str] = None
    lockfile_packages: Optional[list[str]] = None


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(title="ClaudeGate Verifier", version="2.0.0")


@app.get("/health")
def health() -> dict[str, bool]:
    return {"ok": True}


@app.post("/verify")
def verify(
    req: VerifyRequest,
    force_refresh: bool = Query(False, description="Bypass disk cache for PyPI lookup"),
) -> dict[str, Any]:
    package = req.package

    # ------------------------------------------------------------------ #
    # 0. Unicode check — runs before any network I/O                       #
    # ------------------------------------------------------------------ #
    unicode_result = detect_unicode_risk(package)

    # ------------------------------------------------------------------ #
    # 1. Lockfile membership — computed once, used in overrides + reasons  #
    # ------------------------------------------------------------------ #
    in_lockfile = True
    lockfile_names: set[str] = set()
    if req.lockfile_packages is not None:
        lockfile_names = {
            lp.split("==")[0].split(">=")[0].split("<=")[0].split("!=")[0]
            .strip().lower()
            for lp in req.lockfile_packages
        }
        in_lockfile = package.lower() in lockfile_names

    # ------------------------------------------------------------------ #
    # 2. PyPI fetch (cached)                                               #
    # ------------------------------------------------------------------ #
    try:
        pypi_data = fetch_pypi(package, force_refresh=force_refresh)
    except Exception:
        # Unicode check is still valid even when PyPI is unreachable
        rule_ids = ["RULE-UNICODE-01"] if unicode_result["note"] else []
        verdict = "BLOCK" if unicode_result["note"] else "QUARANTINE"
        reasons: list[str] = []
        if unicode_result["note"]:
            reasons.append("Confusable / non-ASCII characters detected in package name")
        reasons.append("Registry lookup failed — requires manual review")
        return {
            "package": package,
            "version": req.version,
            "risk_score": 50,
            "verdict": verdict,
            "reasons": reasons[:3],
            "rule_ids": rule_ids,
            "evidence": {
                "age_days": None,
                "best_similarity": None,
                "closest_known_good": None,
                "release_count": None,
                "missing_links": None,
                "features": None,
                "calibration": None,
                "model": "logistic_v1",
                "unicode": unicode_result,
                "artifact": None,
                "install_hooks": None,
            },
        }

    # ------------------------------------------------------------------ #
    # 3. Logistic signals                                                   #
    # ------------------------------------------------------------------ #
    age_days = compute_age_days(pypi_data)
    best_similarity, closest_known_good = compute_similarity(package)

    info: dict = pypi_data.get("info", {})
    project_urls: dict = info.get("project_urls") or {}
    home_page: str = info.get("home_page") or ""
    missing_links: bool = not project_urls and not home_page
    releases: dict = pypi_data.get("releases", {})
    release_count: int = len(releases)
    pub_proxy: float = (0.5 if missing_links else 0.0) + (
        0.5 if release_count < 3 else 0.0
    )

    x_fresh = 1.0 - min(age_days, FRESH_CAP_DAYS) / FRESH_CAP_DAYS
    x_sim = 0.0
    if best_similarity >= SIM_THRESHOLD:
        x_sim = min(
            (best_similarity - SIM_THRESHOLD) / (SIM_SCALE_MAX - SIM_THRESHOLD), 1.0
        )
    x_pub = pub_proxy

    z = BIAS + W_FRESH * x_fresh + W_SIM * x_sim + W_PUB * x_pub
    p = sigmoid(z)
    risk_score = round(100 * p)

    if risk_score >= BLOCK_THRESHOLD:
        verdict = "BLOCK"
    elif risk_score >= QUARANTINE_THRESHOLD:
        verdict = "QUARANTINE"
    else:
        verdict = "ALLOW"

    # ------------------------------------------------------------------ #
    # 4. Artifact inspection (best-effort, never executes code)            #
    # ------------------------------------------------------------------ #
    try:
        artifact = inspect_artifacts_for_install_hooks(
            pypi_data, package, req.version
        )
    except Exception as exc:
        artifact = {
            "wheel_available": False,
            "sdist_available": False,
            "sdist_only": False,
            "has_setup_py": False,
            "has_pyproject": False,
            "suspicious_keywords": [],
            "note": f"artifact inspection skipped: {exc}",
        }

    # ------------------------------------------------------------------ #
    # 5. Policy overrides — escalate verdict, collect rule IDs             #
    # ------------------------------------------------------------------ #
    rule_ids: list[str] = []

    # RULE-UNICODE-01: any non-ASCII or confusable char → at least QUARANTINE
    if unicode_result["note"]:
        rule_ids.append("RULE-UNICODE-01")
        verdict = _escalate(verdict, "QUARANTINE")

    # RULE-SDIST-01: no wheel available → install may run build scripts
    if artifact["sdist_only"]:
        rule_ids.append("RULE-SDIST-01")
        verdict = _escalate(verdict, "QUARANTINE")

    # RULE-HOOK-01: suspicious keywords in setup.py
    if artifact["suspicious_keywords"]:
        rule_ids.append("RULE-HOOK-01")
        is_fresh = age_days < HOOK_FRESH_DAYS
        if is_fresh or not in_lockfile:
            # Fresh unknown package with executable hooks → BLOCK
            verdict = "BLOCK"
        else:
            verdict = _escalate(verdict, "QUARANTINE")

    # Lockfile upgrade: ALLOW → QUARANTINE when package not in lockfile
    if not in_lockfile:
        verdict = _escalate(verdict, "QUARANTINE")

    # ------------------------------------------------------------------ #
    # 6. Reasons — native signals first, publisher proxy last, cap at 3   #
    # ------------------------------------------------------------------ #
    candidate_reasons: list[str] = []

    # Native / policy signals (highest priority)
    if unicode_result["note"]:
        candidate_reasons.append(
            "Confusable / non-ASCII characters detected in package name"
        )
    if artifact["sdist_only"]:
        candidate_reasons.append(
            "Only sdist available (install may execute build scripts) — manual review"
        )
    if artifact["suspicious_keywords"]:
        kw_sample = ", ".join(artifact["suspicious_keywords"][:3])
        candidate_reasons.append(f"Suspicious keywords in setup.py: {kw_sample}")

    # Logistic signals
    if x_sim > 0:
        candidate_reasons.append(
            f"Name is highly similar to '{closest_known_good}' (sim={best_similarity:.2f})"
        )
    if x_fresh > 0.3:
        candidate_reasons.append(f"New package (age={age_days} days)")

    # Lockfile signal
    if not in_lockfile:
        candidate_reasons.append("Not in project lockfile / allowlist")

    # Publisher proxy (weakest — only if we have room and nothing else filled slot)
    if x_pub > 0:
        candidate_reasons.append("Low publisher signals (few releases / missing links)")

    if not candidate_reasons:
        candidate_reasons.append("No high-risk signals triggered")

    final_reasons = candidate_reasons[:3]

    # ------------------------------------------------------------------ #
    # 7. Response                                                          #
    # ------------------------------------------------------------------ #
    return {
        "package": package,
        "version": req.version,
        "risk_score": risk_score,
        "verdict": verdict,
        "reasons": final_reasons,
        "rule_ids": rule_ids,
        "evidence": {
            "age_days": age_days,
            "best_similarity": round(best_similarity, 4),
            "closest_known_good": closest_known_good,
            "release_count": release_count,
            "missing_links": missing_links,
            "features": {
                "x_fresh": round(x_fresh, 4),
                "x_sim":   round(x_sim, 4),
                "x_pub":   round(x_pub, 4),
            },
            "calibration": {
                "z": round(z, 4),
                "p": round(p, 4),
            },
            "model": "logistic_v1",
            "unicode": unicode_result,
            "artifact": {
                "wheel_available": artifact["wheel_available"],
                "sdist_available": artifact["sdist_available"],
                "sdist_only":      artifact["sdist_only"],
            },
            "install_hooks": {
                "has_setup_py":        artifact["has_setup_py"],
                "has_pyproject":       artifact["has_pyproject"],
                "suspicious_keywords": artifact["suspicious_keywords"],
                "note":                artifact["note"],
            },
        },
    }
