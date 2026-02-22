"""
security_engine/base.py

Defines the core abstractions for PromptGate's security verification layer.

Architecture Note:
    This module implements the Strategy Pattern. `PackageVerifier` is the
    abstract "strategy" interface. Concrete implementations (BasicVerifier,
    DeepScanVerifier, etc.) are swapped in at runtime via the SecurityChecker
    orchestrator in checker.py. This allows the verification backend to be
    upgraded (e.g., from a simple allowlist to a Docker sandbox + VirusTotal
    scan) without touching any other part of the system.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class RiskLevel(Enum):
    """
    Represents the assessed risk level of a package after verification.
    Ordered from lowest to highest risk for easy comparison.
    """
    SAFE = "safe"
    UNKNOWN = "unknown"      # Not in any list — treat as a yellow flag.
    SUSPICIOUS = "suspicious"  # Pattern matches a known-bad heuristic.
    MALICIOUS = "malicious"    # Confirmed bad (e.g., VirusTotal hit — future).


@dataclass
class VerificationResult:
    """
    Immutable value object returned by every PackageVerifier.

    Attributes:
        is_safe         : True only when risk is SAFE. False blocks execution.
        package_name    : Normalised package name that was verified.
        package_manager : The package manager in use (npm, pip, cargo, …).
        risk_level      : Granular risk classification (see RiskLevel).
        reason          : Human-readable explanation shown to the user.
        confidence      : 0.0–1.0 certainty score for the verdict.
        metadata        : Arbitrary extra data (CVE IDs, scan URLs, etc.).
                          This dict is the integration point for future
                          enrichment modules (VirusTotal, OSV, Snyk, …).
    """
    is_safe: bool
    package_name: str
    package_manager: str
    risk_level: RiskLevel
    reason: str
    confidence: float = 1.0
    # Future enrichment modules will populate this dict.
    # e.g., {"virustotal_url": "...", "cve_ids": [...], "sandbox_report": "..."}
    metadata: dict = field(default_factory=dict)


class PackageVerifier(ABC):
    """
    Abstract base class (the Strategy Interface) for all package verifiers.

    Every concrete verifier must implement `verify()` and expose a `name`
    property so the SecurityChecker can log which engine produced a verdict.

    ─────────────────────────────────────────────────
    FUTURE INJECTION POINT — Docker / Deep Scan
    ─────────────────────────────────────────────────
    When the DeepScanVerifier is implemented, it will:
      1. Pull the package tarball into a throwaway Docker container.
      2. Run static analysis (ast-grep, Semgrep rules).
      3. Execute the package install in a sandboxed network namespace and
         record all syscalls with strace / Falco.
      4. Submit file hashes to the VirusTotal public API.
      5. Aggregate all signals and return a VerificationResult with a
         populated `metadata` dict containing scan artefacts.
    That entire logic lives inside DeepScanVerifier.verify() — nothing
    outside that class needs to change.
    ─────────────────────────────────────────────────
    """

    @abstractmethod
    def verify(self, package_name: str, package_manager: str) -> VerificationResult:
        """
        Verify whether a package is safe to install.

        Args:
            package_name    : The package name as parsed from the install command.
            package_manager : Normalised manager string, e.g. "npm", "pip".

        Returns:
            A VerificationResult describing the verdict and rationale.
        """
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable identifier for this verifier engine."""
        ...

    def supports(self, package_manager: str) -> bool:
        """
        Optional override: declare which package managers this verifier
        handles. Returning True (default) means it will be tried for all
        managers. Override in specialised verifiers (e.g., a verifier that
        only understands npm ecosystems).
        """
        return True
