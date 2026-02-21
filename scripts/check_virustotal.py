#!/usr/bin/env python3
"""
scripts/check_virustotal.py
───────────────────────────
Scan a single file against the VirusTotal API v3 and print a JSON verdict.

This script is designed to be deployed inside the Firecracker rootfs at:
    /usr/local/bin/check_virustotal.py

It is called by FirecrackerSandbox._run_virustotal_scan() via SSH with the
VT API key injected as an environment variable:

    VT_API_KEY=<key> python3 /usr/local/bin/check_virustotal.py /path/to/file

Output (stdout, one JSON object):
    {
        "file": "/path/to/file",
        "sha256": "<hash>",
        "status": "clean" | "malicious" | "suspicious" | "undetected" | "error",
        "malicious": <int>,
        "suspicious": <int>,
        "undetected": <int>,
        "analysis_id": "<id>"
    }

Exit codes:
    0   File is clean (0 malicious detections)
    1   File is flagged as malicious (≥1 malicious detection)
    2   File is flagged as suspicious (0 malicious but ≥1 suspicious)
    3   Error (API key missing, upload failed, scan timed out, etc.)

VT API Flow:
    1. POST the file to /api/v3/files  → get analysis_id
    2. GET /api/v3/analyses/{id}       → poll until status != queued/in-progress
    3. Parse last_analysis_stats       → extract malicious/suspicious counts
    4. Print JSON result + exit with appropriate code
"""

import hashlib
import json
import os
import sys
import time

try:
    import requests
except ImportError:
    # Provide a clear error message if requests is not in the rootfs
    print(json.dumps({
        "file": sys.argv[1] if len(sys.argv) > 1 else "unknown",
        "status": "error",
        "error": "Python 'requests' library is not installed in the VM rootfs.",
    }))
    sys.exit(3)

# ── Constants ──────────────────────────────────────────────────────────────────

VT_API_BASE = "https://www.virustotal.com/api/v3"
POLL_INTERVAL_SECONDS = 5
MAX_POLL_ATTEMPTS = 24   # 24 × 5s = 120s max wait per file


# ── Core functions ─────────────────────────────────────────────────────────────

def compute_sha256(file_path: str) -> str:
    """Compute the SHA-256 hash of a file for deduplication."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def upload_file(file_path: str, api_key: str) -> str:
    """
    Upload a file to VirusTotal and return the analysis ID.

    Uses the large-file upload endpoint for files > 32MB, and the standard
    endpoint for smaller files.

    Returns:
        The analysis ID string (e.g. "NjY0MjRhO...").

    Raises:
        RuntimeError : On non-2xx response.
    """
    file_size = os.path.getsize(file_path)
    headers = {"x-apikey": api_key, "accept": "application/json"}

    if file_size > 32 * 1024 * 1024:
        # Large file path: get a one-time upload URL first
        url_resp = requests.get(
            f"{VT_API_BASE}/files/upload_url",
            headers=headers,
            timeout=30,
        )
        url_resp.raise_for_status()
        upload_url = url_resp.json()["data"]
    else:
        upload_url = f"{VT_API_BASE}/files"

    with open(file_path, "rb") as f:
        resp = requests.post(
            upload_url,
            headers=headers,
            files={"file": (os.path.basename(file_path), f)},
            timeout=120,
        )

    if not resp.ok:
        raise RuntimeError(
            f"VirusTotal upload failed: HTTP {resp.status_code} — {resp.text[:200]}"
        )

    analysis_id = resp.json()["data"]["id"]
    return analysis_id


def poll_analysis(analysis_id: str, api_key: str) -> dict:
    """
    Poll the VirusTotal analysis endpoint until the scan is complete.

    VirusTotal queues submitted files; the scan typically completes in
    30–90 seconds. We poll with a fixed interval and a hard cap.

    Returns:
        The `last_analysis_stats` dict with keys:
            malicious, suspicious, undetected, harmless, timeout, failure, …

    Raises:
        RuntimeError : If the scan does not complete within MAX_POLL_ATTEMPTS.
    """
    url = f"{VT_API_BASE}/analyses/{analysis_id}"
    headers = {"x-apikey": api_key, "accept": "application/json"}

    for attempt in range(1, MAX_POLL_ATTEMPTS + 1):
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()

        data = resp.json()["data"]
        status = data["attributes"]["status"]

        if status not in ("queued", "in-progress"):
            # Scan is complete (status == "completed")
            stats = data["attributes"].get("stats", {})
            return stats

        time.sleep(POLL_INTERVAL_SECONDS)

    raise RuntimeError(
        f"VirusTotal analysis {analysis_id} did not complete "
        f"after {MAX_POLL_ATTEMPTS * POLL_INTERVAL_SECONDS}s."
    )


def check_existing_report(sha256: str, api_key: str) -> dict | None:
    """
    Check if VirusTotal already has a report for this file hash.
    Returns stats dict if found, None if the file is not in VT's database.
    This avoids re-uploading and re-analysing files VT already knows about.
    """
    url = f"{VT_API_BASE}/files/{sha256}"
    headers = {"x-apikey": api_key, "accept": "application/json"}

    resp = requests.get(url, headers=headers, timeout=30)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json()["data"]["attributes"].get("last_analysis_stats", {})


def scan_file(file_path: str, api_key: str) -> dict:
    """
    Full scan pipeline: check cache → upload if needed → poll → return verdict.

    Returns a result dict suitable for JSON serialisation.
    """
    sha256 = compute_sha256(file_path)

    # ── Step 1: Check if VT already has this hash (avoids redundant upload) ──
    stats = check_existing_report(sha256, api_key)
    analysis_id = "cached"

    if stats is None:
        # ── Step 2: Upload the file and wait for analysis ──────────────────
        analysis_id = upload_file(file_path, api_key)
        stats = poll_analysis(analysis_id, api_key)

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)

    if malicious > 0:
        status = "malicious"
    elif suspicious > 0:
        status = "suspicious"
    else:
        status = "clean"

    return {
        "file": file_path,
        "sha256": sha256,
        "status": status,
        "malicious": malicious,
        "suspicious": suspicious,
        "undetected": undetected,
        "analysis_id": analysis_id,
    }


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> int:
    if len(sys.argv) < 2:
        print(
            json.dumps({
                "status": "error",
                "error": "Usage: check_virustotal.py <file_path>",
            })
        )
        return 3

    file_path = sys.argv[1]

    # Resolve the API key — standardised on VT_API_KEY across the project
    api_key = os.getenv("VT_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        print(
            json.dumps({
                "file": file_path,
                "status": "error",
                "error": (
                    "VirusTotal API key not set. "
                    "Export VT_API_KEY before running this script."
                ),
            })
        )
        return 3

    if not os.path.isfile(file_path):
        print(
            json.dumps({
                "file": file_path,
                "status": "error",
                "error": f"File not found: {file_path}",
            })
        )
        return 3

    try:
        result = scan_file(file_path, api_key)
        print(json.dumps(result))

        if result["status"] == "malicious":
            return 1
        if result["status"] == "suspicious":
            return 2
        return 0

    except Exception as exc:
        print(
            json.dumps({
                "file": file_path,
                "status": "error",
                "error": str(exc),
            })
        )
        return 3


if __name__ == "__main__":
    sys.exit(main())
