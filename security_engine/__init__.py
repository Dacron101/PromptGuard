"""
security_engine — ClaudeGuard's pluggable package verification layer.

Public API:
    SecurityChecker   : Orchestrator — use this from application code.
    PackageVerifier   : Abstract base — subclass this to add new verifiers.
    VerificationResult: Value object returned by all verifiers.
    RiskLevel         : Enum for granular risk classification.
    BasicVerifier     : Offline allowlist + heuristic verifier.
    DeepScanVerifier  : Deep-scan stub (Docker + VirusTotal — not yet active).
"""

from .base import PackageVerifier, VerificationResult, RiskLevel
from .basic_verifier import BasicVerifier
from .checker import SecurityChecker
from .deep_scan_verifier import DeepScanVerifier

__all__ = [
    "PackageVerifier",
    "VerificationResult",
    "RiskLevel",
    "BasicVerifier",
    "SecurityChecker",
    "DeepScanVerifier",
]
