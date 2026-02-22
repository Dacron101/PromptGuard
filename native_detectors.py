"""
native_detectors.py — Deterministic, zero-execution native detection signals.

Two signals, no VirusTotal, no code execution:
  A) detect_unicode_risk(name)
       → confusable / non-ASCII char detection
  B) inspect_artifacts_for_install_hooks(pypi_data, package, version)
       → sdist download + static keyword scan of setup.py
"""

from __future__ import annotations

import os
import tarfile
import tempfile
import unicodedata
from pathlib import Path

import requests as http_requests

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ARTIFACT_CACHE_DIR = Path("./cache_pypi_artifacts")
HTTP_TIMEOUT = 15            # seconds per network request
MAX_SETUP_PY_BYTES = 200_000  # 200 KB scan ceiling

# Keywords that are suspicious in setup.py / setup.cfg.
# We scan only setup.py (never execute it).
SUSPICIOUS_KEYWORDS: list[str] = [
    "exec(",
    "eval(",
    "base64",
    "subprocess",
    "os.system",
    "curl",
    "wget",
    "powershell",
    "requests.post",
    "socket",
    "chmod",
    "chown",
]


# ---------------------------------------------------------------------------
# A) Unicode / confusables detector
# ---------------------------------------------------------------------------


def detect_unicode_risk(name: str) -> dict:
    """
    Detect non-ASCII or Unicode confusable characters in a package name.

    Strategy
    --------
    1. Try to encode the name as ASCII; any failure → non_ascii = True.
    2. NFKD-normalise then strip non-ASCII bytes and compare to original.
       This catches lookalike characters that survive ASCII encoding (none do,
       but NFKD normalization also decomposes accented chars: é → e + combining).

    Returns
    -------
    {"non_ascii": bool, "normalized": str, "note": str | None}
    """
    try:
        name.encode("ascii")
        non_ascii = False
    except UnicodeEncodeError:
        non_ascii = True

    # NFKD decompose → strip any remaining non-ASCII bytes
    normalized = (
        unicodedata.normalize("NFKD", name)
        .encode("ascii", errors="ignore")
        .decode("ascii")
    )

    note: str | None = None
    if non_ascii or normalized != name:
        note = "Confusable / non-ASCII characters detected in package name"

    return {
        "non_ascii": non_ascii,
        "normalized": normalized,
        "note": note,
    }


# ---------------------------------------------------------------------------
# B) Artifact / install-hook inspector
# ---------------------------------------------------------------------------


def _get_version_files(pypi_data: dict, version: str | None) -> list[dict]:
    """Return the dist-file list for *version*, falling back to latest."""
    releases: dict = pypi_data.get("releases") or {}
    info: dict = pypi_data.get("info") or {}

    if version and version in releases:
        return releases[version]

    latest = info.get("version") or ""
    if latest and latest in releases:
        return releases[latest]

    # Top-level "urls" always reflects the latest release on /pypi/<pkg>/json
    return pypi_data.get("urls") or []


def _safe_extractall(tf: tarfile.TarFile, dest: Path) -> None:
    """
    Extract *tf* into *dest*, rejecting any member whose resolved path escapes
    *dest* (prevents TarSlip / path-traversal).  Symlinks and hard links are
    also skipped — they can point outside the extraction root.
    """
    abs_dest = dest.resolve()
    for member in tf.getmembers():
        if member.issym() or member.islnk():
            continue  # skip links entirely
        target = (abs_dest / member.name).resolve()
        try:
            target.relative_to(abs_dest)  # raises ValueError if outside
        except ValueError:
            continue  # path-traversal attempt — skip silently
        tf.extract(member, abs_dest, set_attrs=False)


def _scan_setup_py(content: bytes) -> list[str]:
    """Return sorted list of SUSPICIOUS_KEYWORDS found in *content*."""
    try:
        text = content.decode("utf-8", errors="replace")
    except Exception:
        return []
    return sorted({kw for kw in SUSPICIOUS_KEYWORDS if kw in text})


def inspect_artifacts_for_install_hooks(
    pypi_data: dict,
    package: str,
    version: str | None = None,
) -> dict:
    """
    Inspect PyPI dist artifacts for install-time hook risks.
    NEVER executes any code from the package.

    Steps
    -----
    1. Classify available files (wheel / sdist).
    2. If sdist present: download (disk-cached), extract safely, scan setup.py
       for suspicious keywords up to MAX_SETUP_PY_BYTES.
    3. Detect presence of setup.py and pyproject.toml.

    Returns
    -------
    {
        wheel_available:     bool,
        sdist_available:     bool,
        sdist_only:          bool,
        has_setup_py:        bool,
        has_pyproject:       bool,
        suspicious_keywords: list[str],
        note:                str | None,   # set on skip/error
    }
    """
    result: dict = {
        "wheel_available": False,
        "sdist_available": False,
        "sdist_only": False,
        "has_setup_py": False,
        "has_pyproject": False,
        "suspicious_keywords": [],
        "note": None,
    }

    files = _get_version_files(pypi_data, version)
    if not files:
        result["note"] = "No release files found in PyPI metadata"
        return result

    wheel_files = [f for f in files if f.get("packagetype") == "bdist_wheel"]
    sdist_files = [f for f in files if f.get("packagetype") == "sdist"]

    result["wheel_available"] = bool(wheel_files)
    result["sdist_available"] = bool(sdist_files)
    result["sdist_only"] = result["sdist_available"] and not result["wheel_available"]

    if not sdist_files:
        return result  # wheel-only: clean bill of health for install hooks

    # ---- Download sdist (cached) ----------------------------------------
    sdist_meta = sdist_files[0]
    sdist_url = sdist_meta.get("url") or ""
    filename = sdist_meta.get("filename") or "source.tar.gz"

    if not sdist_url:
        result["note"] = "sdist URL missing in PyPI metadata"
        return result

    cache_dir = ARTIFACT_CACHE_DIR / package / (version or "latest")
    cache_dir.mkdir(parents=True, exist_ok=True)
    cached_file = cache_dir / filename

    if not cached_file.exists():
        try:
            resp = http_requests.get(
                sdist_url,
                timeout=HTTP_TIMEOUT,
                stream=True,
                headers={"Accept-Encoding": "identity"},
            )
            resp.raise_for_status()
            with cached_file.open("wb") as fh:
                for chunk in resp.iter_content(chunk_size=65_536):
                    fh.write(chunk)
        except Exception as exc:
            result["note"] = f"artifact inspection skipped: download failed ({exc})"
            return result

    # ---- Extract and scan -----------------------------------------------
    try:
        with tempfile.TemporaryDirectory(prefix="cgx_") as tmpdir:
            tmp_path = Path(tmpdir)

            with tarfile.open(cached_file, "r:*") as tf:
                _safe_extractall(tf, tmp_path)

            for fpath in tmp_path.rglob("*"):
                if not fpath.is_file():
                    continue
                fname = fpath.name.lower()

                if fname == "setup.py":
                    result["has_setup_py"] = True
                    raw = fpath.read_bytes()[:MAX_SETUP_PY_BYTES]
                    found = _scan_setup_py(raw)
                    result["suspicious_keywords"] = sorted(
                        set(result["suspicious_keywords"]) | set(found)
                    )
                elif fname == "pyproject.toml":
                    result["has_pyproject"] = True

    except tarfile.TarError as exc:
        result["note"] = f"artifact inspection skipped: bad archive ({exc})"
    except Exception as exc:
        result["note"] = f"artifact inspection skipped: {exc}"

    return result
