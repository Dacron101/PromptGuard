"""
security_engine/checker.py

SecurityChecker — the Strategy Pattern orchestrator.
──────────────────────────────────────────────────────
This class owns the verifier chain and decides which PackageVerifier
implementation(s) to invoke for a given package. It implements a
Chain-of-Responsibility on top of the Strategy Pattern:

  1. The PRIMARY verifier (BasicVerifier by default) is always tried first.
  2. If the result is UNKNOWN AND a FALLBACK verifier is configured, the
     fallback is tried next (e.g., DeepScanVerifier once implemented).
  3. The most definitive result is returned to the caller (TTYWrapper).

This means upgrading from BasicVerifier to DeepScanVerifier requires only
changing how SecurityChecker is constructed — no other code changes.
"""

import logging
from typing import Optional

from .base import PackageVerifier, VerificationResult, RiskLevel
from .basic_verifier import BasicVerifier

logger = logging.getLogger(__name__)


class SecurityChecker:
    """
    Orchestrates one or more PackageVerifier strategies.

    Args:
        primary_verifier  : The first verifier to consult. Defaults to
                            BasicVerifier (offline, no network required).
        fallback_verifier : Optional second verifier, consulted when the
                            primary returns UNKNOWN. Defaults to None.
                            Pass a DeepScanVerifier instance here once it
                            is implemented.

    Usage:
        # Default (BasicVerifier only)
        checker = SecurityChecker()

        # Future usage with deep scan fallback:
        #   from security_engine.deep_scan_verifier import DeepScanVerifier
        #   checker = SecurityChecker(
        #       primary_verifier=BasicVerifier(),
        #       fallback_verifier=DeepScanVerifier(virustotal_key="…"),
        #   )

        result = checker.check("requests", "pip")
        if not result.is_safe:
            print(f"BLOCKED: {result.reason}")
    """

    def __init__(
        self,
        primary_verifier: Optional[PackageVerifier] = None,
        fallback_verifier: Optional[PackageVerifier] = None,
    ) -> None:
        self._primary = primary_verifier or BasicVerifier()
        self._fallback = fallback_verifier  # None until DeepScanVerifier is ready

        logger.debug(
            "SecurityChecker initialised | primary=%s | fallback=%s",
            self._primary.name,
            self._fallback.name if self._fallback else "none",
        )

    def check(self, package_name: str, package_manager: str) -> VerificationResult:
        """
        Run the verifier chain and return the most authoritative verdict.

        The chain logic:
          - Primary verifier always runs.
          - If the result is UNKNOWN and a fallback exists, run the fallback.
          - The fallback's result supersedes UNKNOWN verdicts from the primary.
          - SAFE and SUSPICIOUS/MALICIOUS results from the primary are final.

        Args:
            package_name    : Package name extracted from the install command.
            package_manager : The package manager (npm, pip, cargo, …).

        Returns:
            The most authoritative VerificationResult from the chain.
        """
        logger.info(
            "[%s] Checking package '%s' for manager '%s'",
            self._primary.name, package_name, package_manager,
        )

        # ── Primary verification pass ─────────────────────────────────────────
        result = self._primary.verify(package_name, package_manager)

        logger.info(
            "[%s] Result: is_safe=%s risk=%s reason=%s",
            self._primary.name, result.is_safe, result.risk_level.value, result.reason,
        )

        # ── Fallback pass (only for UNKNOWN results) ──────────────────────────
        # UNKNOWN means "not in allowlist but no explicit red flags". We give
        # the fallback verifier a chance to make a more definitive call.
        #
        # FUTURE INJECTION POINT — DeepScanVerifier chain:
        #   Once DeepScanVerifier is implemented, pass it as `fallback_verifier`
        #   to the SecurityChecker constructor. The logic below will automatically
        #   invoke it for UNKNOWN packages, requiring zero changes here.
        if result.risk_level == RiskLevel.UNKNOWN and self._fallback is not None:
            if self._fallback.supports(package_manager):
                logger.info(
                    "Primary returned UNKNOWN — escalating to fallback verifier [%s]",
                    self._fallback.name,
                )
                try:
                    fallback_result = self._fallback.verify(package_name, package_manager)
                    logger.info(
                        "[%s] Fallback result: is_safe=%s risk=%s",
                        self._fallback.name,
                        fallback_result.is_safe,
                        fallback_result.risk_level.value,
                    )
                    # Merge metadata from both passes into the final result
                    merged_metadata = {**result.metadata, **fallback_result.metadata}
                    return VerificationResult(
                        is_safe=fallback_result.is_safe,
                        package_name=fallback_result.package_name,
                        package_manager=fallback_result.package_manager,
                        risk_level=fallback_result.risk_level,
                        reason=fallback_result.reason,
                        confidence=fallback_result.confidence,
                        metadata=merged_metadata,
                    )
                except Exception as exc:
                    # Fallback failure must NOT silently pass the package.
                    # We return the conservative UNKNOWN result from the primary.
                    logger.error(
                        "Fallback verifier [%s] raised an exception: %s. "
                        "Defaulting to primary result (UNKNOWN → blocked).",
                        self._fallback.name, exc,
                    )

        return result
