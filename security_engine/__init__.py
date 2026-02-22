"""
security_engine — PromptGate's pluggable package verification layer.

Public API:
    SecurityChecker      : Orchestrator — use this from application code.
    PackageVerifier      : Abstract base — subclass this to add new verifiers.
    VerificationResult   : Value object returned by all verifiers.
    RiskLevel            : Enum for granular risk classification.
    BasicVerifier        : Offline allowlist + heuristic verifier.
    DeepScanVerifier     : Firecracker microVM sandbox verifier.
    FirecrackerSandbox   : Firecracker VM lifecycle manager.
"""

from .base import PackageVerifier, VerificationResult, RiskLevel
from .basic_verifier import BasicVerifier
from .checker import SecurityChecker
from .deep_scan_verifier import DeepScanVerifier
from .firecracker_sandbox import FirecrackerSandbox

__all__ = [
    "PackageVerifier",
    "VerificationResult",
    "RiskLevel",
    "BasicVerifier",
    "SecurityChecker",
    "DeepScanVerifier",
    "FirecrackerSandbox",
]
