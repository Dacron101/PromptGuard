"""
security_engine/gemini_explainer.py

GeminiExplainer — AI-generated interruption messages via Gemini 2.0 Flash Lite.
────────────────────────────────────────────────────────────────────────────────
When ClaudeGuard blocks a package installation (malicious or suspicious verdict),
this module calls the Gemini API to generate a concise, human-readable explanation
of WHY the session was interrupted — including the specific threat type where
VirusTotal provides enough signal.

Example output:
    "The installation of 'totally-legit-sdk' via pip was blocked because
     VirusTotal identified it as a credential-stealer (7/72 engines flagged it,
     including Trojan.Gen.2 and Backdoor.Python.Agent). Claude Code has been
     interrupted to protect your system."

Model: gemini-2.0-flash-lite
    The cheapest production Gemini model as of 2026. At $0.075 / 1M input tokens
    and $0.30 / 1M output tokens, a single explanation costs < $0.0001.
    The model is called with a low temperature (0.2) and a 150-token output cap
    to keep responses tight and deterministic.

Failure handling:
    The explainer is non-critical. If the API key is missing, the network is
    unavailable, or Gemini returns an error, the method falls back gracefully
    to a pre-built template string. The rest of the pipeline is never blocked
    by an explainer failure.
"""

import json
import logging
from typing import Optional

import requests

logger = logging.getLogger(__name__)

_GEMINI_API_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models"
    "/gemini-2.0-flash-lite:generateContent"
)

_SYSTEM_INSTRUCTION = (
    "You are the security engine inside ClaudeGuard, a tool that intercepts "
    "dangerous package installations attempted by Claude Code (an AI coding assistant). "
    "Your job is to write a SHORT, clear, non-technical explanation of why a "
    "package installation was blocked. "
    "Rules:\n"
    "- 1–2 sentences maximum, ≤ 80 words total.\n"
    "- Start with: \"The installation of '[package]' via [manager] was blocked because \"\n"
    "- Be specific about the threat type when the data allows it "
    "(e.g. 'credential-stealer', 'backdoor', 'cryptominer', 'trojan').\n"
    "- Mention the VirusTotal engine count only if > 0.\n"
    "- End every message with: \"Claude Code has been interrupted to protect your system.\"\n"
    "- Do NOT include markdown, code blocks, or bullet points."
)


class GeminiExplainer:
    """
    Wraps the Gemini 2.0 Flash Lite API to produce one-sentence threat summaries.

    Args:
        api_key : Google AI Studio API key (from GEMINI_API_KEY env var).
        timeout : HTTP request timeout in seconds. Default 10s.
    """

    def __init__(self, api_key: str, timeout: int = 10) -> None:
        self._api_key = api_key
        self._timeout = timeout

    def explain(
        self,
        package_name: str,
        package_manager: str,
        vt_malicious: int = 0,
        vt_suspicious: int = 0,
        suspicious_files: Optional[list[str]] = None,
        vt_raw_output: str = "",
    ) -> str:
        """
        Ask Gemini to explain why this package was blocked.

        Gathers all available threat signals into a structured prompt, sends
        it to gemini-2.0-flash-lite, and returns the model's response text.

        Falls back to a deterministic template string on any failure so that
        the calling code never needs to handle exceptions from this method.

        Args:
            package_name     : Name of the blocked package.
            package_manager  : e.g. "pip", "npm", "cargo".
            vt_malicious     : Number of malicious detections from VirusTotal.
            vt_suspicious    : Number of suspicious detections from VirusTotal.
            suspicious_files : Filesystem paths written to suspicious locations.
            vt_raw_output    : Raw JSON lines from check_virustotal.py (used to
                               extract engine names for a richer prompt).

        Returns:
            A 1–2 sentence explanation string ready to display to the user.
        """
        try:
            prompt = self._build_prompt(
                package_name=package_name,
                package_manager=package_manager,
                vt_malicious=vt_malicious,
                vt_suspicious=vt_suspicious,
                suspicious_files=suspicious_files or [],
                vt_raw_output=vt_raw_output,
            )
            return self._call_api(prompt)
        except Exception as exc:
            logger.warning(
                "GeminiExplainer failed (%s) — using fallback message.", exc
            )
            return self._fallback(
                package_name, package_manager, vt_malicious, vt_suspicious,
                suspicious_files or [],
            )

    # ── Private helpers ───────────────────────────────────────────────────────

    def _build_prompt(
        self,
        package_name: str,
        package_manager: str,
        vt_malicious: int,
        vt_suspicious: int,
        suspicious_files: list[str],
        vt_raw_output: str,
    ) -> str:
        """
        Construct the user-turn prompt with all available threat context.
        The richer the context, the more specific Gemini's explanation will be.
        """
        lines = [
            f"Package name:    {package_name}",
            f"Package manager: {package_manager}",
        ]

        if vt_malicious > 0 or vt_suspicious > 0:
            lines.append(
                f"VirusTotal detections: {vt_malicious} malicious, "
                f"{vt_suspicious} suspicious"
            )

        # Extract engine names from the raw VT output if available
        engine_names = self._extract_engine_names(vt_raw_output)
        if engine_names:
            lines.append(f"Flagging AV engines: {', '.join(engine_names[:5])}")

        if suspicious_files:
            lines.append(
                f"Suspicious filesystem writes: {', '.join(suspicious_files[:4])}"
            )

        lines.append("\nWrite the interruption explanation now:")
        return "\n".join(lines)

    def _call_api(self, user_prompt: str) -> str:
        """Send the prompt to Gemini and return the response text."""
        payload = {
            "system_instruction": {
                "parts": [{"text": _SYSTEM_INSTRUCTION}]
            },
            "contents": [
                {"role": "user", "parts": [{"text": user_prompt}]}
            ],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 150,
                "stopSequences": ["\n\n"],
            },
        }

        resp = requests.post(
            _GEMINI_API_URL,
            params={"key": self._api_key},
            json=payload,
            timeout=self._timeout,
        )
        resp.raise_for_status()

        data = resp.json()
        text = (
            data["candidates"][0]["content"]["parts"][0]["text"].strip()
        )
        logger.debug("Gemini explanation: %s", text)
        return text

    @staticmethod
    def _extract_engine_names(vt_raw_output: str) -> list[str]:
        """
        Parse engine/threat names from the raw VirusTotal JSON output.
        check_virustotal.py currently doesn't include per-engine names, so
        this is a best-effort parse — returns an empty list if nothing useful
        is found. Future versions of check_virustotal.py can add an
        `engine_names` field to enrich the prompt further.
        """
        names: list[str] = []
        for line in vt_raw_output.strip().splitlines():
            try:
                data = json.loads(line)
                # check_virustotal.py may include an "engine_names" list
                for name in data.get("engine_names", []):
                    if name not in names:
                        names.append(name)
            except (json.JSONDecodeError, TypeError):
                continue
        return names

    @staticmethod
    def _fallback(
        package_name: str,
        package_manager: str,
        vt_malicious: int,
        vt_suspicious: int,
        suspicious_files: list[str],
    ) -> str:
        """
        Deterministic fallback when the Gemini API is unavailable.
        Produces a readable message without any AI inference.
        """
        if vt_malicious > 0:
            detail = (
                f"VirusTotal flagged it as malicious "
                f"({vt_malicious} engine(s) detected a threat)"
            )
        elif vt_suspicious > 0:
            detail = (
                f"VirusTotal rated it suspicious "
                f"({vt_suspicious} engine(s) raised concerns)"
            )
        elif suspicious_files:
            paths = ", ".join(suspicious_files[:2])
            detail = f"it wrote to sensitive system paths during installation ({paths})"
        else:
            detail = "it exhibited potentially malicious behaviour in the sandbox"

        return (
            f"The installation of '{package_name}' via {package_manager} was "
            f"blocked because {detail}. "
            "Claude Code has been interrupted to protect your system."
        )
