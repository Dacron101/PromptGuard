"""
pypi_check.py — PyPI package existence checker with disk caching.

For each package name we query:
    https://pypi.org/pypi/<normalized-name>/json

HTTP 200  → EXISTS
HTTP 404  → NOT_FOUND
Timeout / other error → AMBIGUOUS

Results are cached to ./cache_halluc/<name>.json so repeated runs are
fast and network-independent (demo-stable).
"""

from __future__ import annotations

import json
import re
import time
from enum import Enum
from pathlib import Path

import requests

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CACHE_DIR = Path("./cache_halluc")
PYPI_BASE = "https://pypi.org/pypi"
REQUEST_TIMEOUT = 8          # seconds per HTTP request
RATE_LIMIT_DELAY = 0.25     # polite delay between uncached requests


# ---------------------------------------------------------------------------
# Status enum
# ---------------------------------------------------------------------------


class PackageStatus(str, Enum):
    EXISTS = "exists"
    NOT_FOUND = "not_found"
    AMBIGUOUS = "ambiguous"   # timeout / unexpected HTTP status


# ---------------------------------------------------------------------------
# Name normalisation  (PEP 503)
# ---------------------------------------------------------------------------


def normalize_name(name: str) -> str:
    """
    Normalise a PyPI package name: lowercase and collapse runs of [-_.] to
    a single hyphen, as per PEP 503.
    """
    return re.sub(r"[-_.]+", "-", name.lower()).strip("-")


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------


def _cache_path(normalized: str) -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR / f"{normalized}.json"


def _load_cache(normalized: str) -> dict | None:
    path = _cache_path(normalized)
    if path.exists():
        try:
            with path.open() as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return None


def _save_cache(normalized: str, result: dict) -> None:
    try:
        with _cache_path(normalized).open("w") as f:
            json.dump(result, f)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def check_package(name: str, force_refresh: bool = False) -> dict:
    """
    Return a dict describing whether *name* exists on PyPI::

        {
            "name":        str,   # original name as provided
            "normalized":  str,   # PEP 503 normalised form
            "status":      str,   # PackageStatus value
            "status_code": int | None,
        }

    Results are served from disk cache unless force_refresh=True.
    """
    norm = normalize_name(name)

    if not force_refresh:
        cached = _load_cache(norm)
        if cached is not None:
            return cached

    try:
        time.sleep(RATE_LIMIT_DELAY)
        resp = requests.get(
            f"{PYPI_BASE}/{norm}/json",
            timeout=REQUEST_TIMEOUT,
            headers={"Accept": "application/json"},
        )
        if resp.status_code == 200:
            status = PackageStatus.EXISTS
        elif resp.status_code == 404:
            status = PackageStatus.NOT_FOUND
        else:
            status = PackageStatus.AMBIGUOUS
        code: int | None = resp.status_code

    except requests.exceptions.Timeout:
        status = PackageStatus.AMBIGUOUS
        code = None
    except requests.exceptions.RequestException:
        status = PackageStatus.AMBIGUOUS
        code = None

    result = {
        "name": name,
        "normalized": norm,
        "status": status,
        "status_code": code,
    }
    _save_cache(norm, result)
    return result


def check_packages_bulk(
    names: list[str],
    force_refresh: bool = False,
    progress: bool = True,
) -> dict[str, dict]:
    """
    Check multiple packages and return a dict keyed by normalised name.
    Deduplicates before querying.
    """
    seen: dict[str, dict] = {}
    unique = sorted({normalize_name(n) for n in names})

    for i, norm in enumerate(unique, 1):
        if progress:
            print(f"  [{i:>3}/{len(unique)}] checking {norm} ...", end="\r")
        seen[norm] = check_package(norm, force_refresh=force_refresh)

    if progress and unique:
        print()  # clear the \r line

    return seen
