"""
security_engine/basic_verifier.py

Concrete Strategy: BasicVerifier
────────────────────────────────
Provides lightweight, offline package verification using two mechanisms:

  1. An allowlist of well-known, trusted packages per ecosystem.
  2. A set of heuristic regex patterns that flag suspicious names
     (typosquatting simulation, obfuscated names, suspicious keywords).

This verifier runs synchronously, requires no external network calls, and
is always available as a first-pass filter. Any package that passes here
but is not in the allowlist is still flagged as UNKNOWN — the SecurityChecker
can chain a deeper verifier for those cases.

FUTURE INJECTION POINT — Real allowlist data source:
    The SAFE_PACKAGES dict below is hardcoded for demonstration. In production
    it should be loaded from a versioned JSON/YAML file (committed to the repo)
    that is periodically synced from trusted sources like:
      - npm audit advisories
      - PyPA advisory DB (https://github.com/pypa/advisory-database)
      - GitHub Advisory Database
    Replace `_load_safe_packages()` below to pull from that source.
"""

import re
from typing import FrozenSet, Dict

from .base import PackageVerifier, VerificationResult, RiskLevel


# ─────────────────────────────────────────────────────────────────────────────
# Allowlist data
# Each key is a normalised package-manager name; each value is a frozenset of
# known-good package names (lowercase). This is intentionally NOT exhaustive —
# its purpose is to let common packages through fast without any heuristic check.
# ─────────────────────────────────────────────────────────────────────────────
SAFE_PACKAGES: Dict[str, FrozenSet[str]] = {
    "npm": frozenset({
        # Frameworks / runtimes
        "react", "react-dom", "react-router", "react-router-dom",
        "next", "nuxt", "vue", "@vue/cli",
        "express", "fastify", "koa", "hapi",
        # Tooling
        "typescript", "ts-node", "eslint", "prettier",
        "webpack", "vite", "esbuild", "rollup", "parcel",
        "jest", "vitest", "mocha", "chai", "supertest",
        "babel", "@babel/core", "@babel/preset-env",
        # Utilities
        "lodash", "underscore", "ramda", "date-fns", "moment",
        "axios", "node-fetch", "got", "ky",
        "dotenv", "zod", "yup", "joi",
        "uuid", "nanoid", "crypto-js",
        "socket.io", "ws", "ioredis", "mongoose", "sequelize", "prisma",
        "winston", "pino", "chalk", "commander", "inquirer",
        "sharp", "multer", "body-parser", "cors", "helmet", "morgan",
    }),
    "pip": frozenset({
        # Science / data
        "numpy", "pandas", "scipy", "matplotlib", "seaborn", "plotly",
        "scikit-learn", "sklearn", "statsmodels",
        "tensorflow", "torch", "torchvision", "keras",
        "transformers", "huggingface-hub",
        # Web
        "flask", "django", "fastapi", "starlette", "uvicorn", "gunicorn",
        "aiohttp", "httpx", "requests", "urllib3", "httplib2",
        # Tooling / utilities
        "boto3", "google-cloud-storage", "azure-identity",
        "sqlalchemy", "alembic", "psycopg2", "pymysql", "motor",
        "pydantic", "marshmallow", "cerberus",
        "celery", "rq", "kombu",
        "pytest", "unittest2", "coverage", "hypothesis",
        "black", "flake8", "mypy", "pylint", "isort",
        "click", "typer", "rich", "tqdm",
        "pillow", "opencv-python", "imageio",
        "pyyaml", "toml", "python-dotenv",
        "cryptography", "bcrypt", "passlib", "pyotp",
        "paramiko", "fabric", "ansible",
        "pexpect", "ptyprocess", "colorama",
    }),
    "yarn": frozenset({
        # yarn shares npm's registry — reuse the npm set
        "react", "react-dom", "react-router-dom",
        "next", "vue", "express", "typescript", "eslint", "prettier",
        "webpack", "vite", "jest", "lodash", "axios", "dotenv",
    }),
    "brew": frozenset({
        "git", "curl", "wget", "jq", "htop", "tmux", "vim", "neovim",
        "node", "python", "python3", "go", "rust", "ruby",
        "docker", "kubectl", "helm", "terraform", "awscli",
        "postgresql", "mysql", "redis", "mongodb",
        "ffmpeg", "imagemagick", "ghostscript",
        "openssl", "gnupg", "age",
    }),
    "cargo": frozenset({
        "serde", "serde_json", "serde_derive",
        "tokio", "async-std", "actix-web", "axum", "hyper", "warp",
        "reqwest", "ureq", "surf",
        "clap", "structopt", "argh",
        "anyhow", "thiserror", "eyre",
        "log", "tracing", "env_logger",
        "rand", "uuid", "chrono", "regex",
        "sqlx", "diesel", "sea-orm",
        "prost", "tonic", "tarpc",
    }),
    "go": frozenset({
        "github.com/gin-gonic/gin",
        "github.com/gorilla/mux",
        "github.com/labstack/echo",
        "go.uber.org/zap",
        "github.com/sirupsen/logrus",
        "gorm.io/gorm",
        "github.com/go-redis/redis",
        "github.com/spf13/cobra",
        "github.com/spf13/viper",
        "github.com/stretchr/testify",
        "golang.org/x/crypto",
        "golang.org/x/net",
    }),
}


# ─────────────────────────────────────────────────────────────────────────────
# Suspicious-pattern heuristics
# Each tuple is (compiled_regex, human-readable reason).
# Patterns are evaluated in order; the first match wins.
#
# FUTURE INJECTION POINT — ML-based typosquatting detector:
#   Replace (or augment) these patterns with a call to a trained model that
#   computes edit-distance / Levenshtein similarity against the allowlist.
#   The model can be loaded once at startup and called inside verify().
# ─────────────────────────────────────────────────────────────────────────────
SUSPICIOUS_PATTERNS = [
    # Obfuscated/encoded payloads
    (re.compile(r'(?i)(base64|b64|eval|exec|__import__)'), "contains code-execution keyword"),

    # Credential / exfiltration indicators
    (re.compile(r'(?i)(steal|exfil|harvest|keylog|ransomware|cryptominer|miner|backdoor|trojan|rootkit|malware|spyware)'),
     "name contains malware-family keyword"),

    # Typosquatting simulation: packages that look like common names with digits or hyphens inserted
    (re.compile(r'(?i)^(reqqests|reqeusts|reequests|reqests)$'), "likely typosquat of 'requests'"),
    (re.compile(r'(?i)^(lo0dash|1odash|lod4sh)$'), "likely typosquat of 'lodash'"),
    (re.compile(r'(?i)^(cros$|crojs|cor5)$'), "likely typosquat of 'cors'"),
    (re.compile(r'(?i)^(npminstall|npm-install)$'), "suspicious meta-package name"),

    # Very short, non-scoped names are a common attack vector
    (re.compile(r'^[a-zA-Z0-9]{1,2}$'), "extremely short package name (high typosquat risk)"),

    # Packages with IP addresses or raw URLs embedded
    (re.compile(r'(?:\d{1,3}\.){3}\d{1,3}'), "package name contains an IP address"),

    # Excessive digits — unusual for legitimate packages
    (re.compile(r'\d{5,}'), "package name contains an unusually long numeric sequence"),

    # Names that are just common tools prefixed/suffixed with 'free', 'crack', 'hack'
    (re.compile(r'(?i)(free|crack|hack|keygen|nulled)'), "name contains software-cracking keyword"),
]


class BasicVerifier(PackageVerifier):
    """
    Offline, zero-dependency verifier using an allowlist + heuristic patterns.

    Decision logic (in order):
      1. If the package name is in the allowlist for its ecosystem → SAFE.
      2. If the name matches any suspicious pattern → SUSPICIOUS (blocked).
      3. Otherwise → UNKNOWN (conservative: blocked with informational message).

    The caller (SecurityChecker) decides what to do with UNKNOWN results — it
    may chain a more thorough verifier or prompt the user for manual approval.
    """

    @property
    def name(self) -> str:
        return "BasicVerifier"

    def verify(self, package_name: str, package_manager: str) -> VerificationResult:
        """
        Verify a single package name against the allowlist and heuristics.

        Args:
            package_name    : Raw package name extracted from the install command.
            package_manager : Normalised manager string (npm, pip, cargo, …).

        Returns:
            VerificationResult with a conservative verdict.
        """
        normalised_name = package_name.strip().lower()
        normalised_manager = package_manager.strip().lower()

        # ── Step 1: Allowlist check ──────────────────────────────────────────
        # For npm/yarn, strip leading scope prefix (@org/pkg → pkg) for the
        # initial allowlist lookup, then also try the full scoped name.
        lookup_name = self._strip_scope(normalised_name) if normalised_manager in ("npm", "yarn") else normalised_name

        manager_allowlist = SAFE_PACKAGES.get(normalised_manager, frozenset())
        if normalised_name in manager_allowlist or lookup_name in manager_allowlist:
            return VerificationResult(
                is_safe=True,
                package_name=package_name,
                package_manager=package_manager,
                risk_level=RiskLevel.SAFE,
                reason=f"Package '{package_name}' is in the {self.name} trusted allowlist.",
                confidence=0.85,  # High but not 1.0 — allowlists can be stale.
            )

        # ── Step 2: Heuristic / suspicious-pattern check ─────────────────────
        for pattern, reason in SUSPICIOUS_PATTERNS:
            if pattern.search(normalised_name):
                return VerificationResult(
                    is_safe=False,
                    package_name=package_name,
                    package_manager=package_manager,
                    risk_level=RiskLevel.SUSPICIOUS,
                    reason=f"Heuristic match — {reason}.",
                    confidence=0.80,
                    metadata={"matched_pattern": pattern.pattern},
                )

        # ── Step 3: Not in allowlist, not obviously suspicious → UNKNOWN ─────
        # We err on the side of caution: unknown packages are blocked and the
        # user is prompted to review manually.
        #
        # FUTURE INJECTION POINT — Chained deep-scan:
        #   If SecurityChecker is configured with a DeepScanVerifier as a
        #   fallback, unknown packages will be forwarded to it automatically.
        #   The UNKNOWN result here signals that chain-of-responsibility should
        #   continue rather than immediately blocking.
        return VerificationResult(
            is_safe=False,
            package_name=package_name,
            package_manager=package_manager,
            risk_level=RiskLevel.UNKNOWN,
            reason=(
                f"Package '{package_name}' is not in the trusted allowlist for "
                f"'{package_manager}'. Manual review required."
            ),
            confidence=0.50,
        )

    # ── Private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _strip_scope(name: str) -> str:
        """Remove npm scope prefix: '@org/package' → 'package'."""
        if name.startswith("@") and "/" in name:
            return name.split("/", 1)[1]
        return name
