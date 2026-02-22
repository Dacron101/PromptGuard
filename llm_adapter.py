"""
llm_adapter.py — Pluggable LLM backend for the hallucination experiment.

Supported providers
-------------------
  mock       Read round-robin from ./samples/*.txt  (no network, no keys)
  openai     OpenAI-compatible chat completions     (requires OPENAI_API_KEY)
  anthropic  Anthropic Messages API                 (requires ANTHROPIC_API_KEY)

Adding a new provider: subclass LLMAdapter and implement complete().
"""

from __future__ import annotations

import glob
import os
import time
from abc import ABC, abstractmethod
from pathlib import Path


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------


class LLMAdapter(ABC):
    """Minimal interface every backend must satisfy."""

    @abstractmethod
    def complete(self, prompt: str) -> str:
        """Send *prompt* to the model; return the full response text."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        ...

    @property
    @abstractmethod
    def model_name(self) -> str:
        ...


# ---------------------------------------------------------------------------
# Mock adapter (no API key required)
# ---------------------------------------------------------------------------


class MockAdapter(LLMAdapter):
    """
    Returns pre-saved model outputs from ./samples/*.txt, cycling round-robin.

    Place one .txt file per saved response in the samples directory.
    Each file should contain a realistic LLM response recommending Python
    packages (as they would appear in a real chat completion).
    """

    def __init__(self, samples_dir: str = "./samples") -> None:
        self._dir = Path(samples_dir)
        self._files: list[Path] = sorted(self._dir.glob("*.txt"))
        self._idx = 0

        if not self._files:
            raise FileNotFoundError(
                f"No .txt files found in {self._dir!r}. "
                "Create sample files or use --provider openai/anthropic."
            )

    @property
    def provider_name(self) -> str:
        return "mock"

    @property
    def model_name(self) -> str:
        return "mock"

    def complete(self, prompt: str) -> str:  # noqa: ARG002
        path = self._files[self._idx % len(self._files)]
        self._idx += 1
        return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# OpenAI / OpenAI-compatible adapter
# ---------------------------------------------------------------------------


class OpenAIAdapter(LLMAdapter):
    """
    Uses the openai Python SDK (v1+).  Works with any OpenAI-compatible
    endpoint (e.g. Azure OpenAI, local Ollama) via base_url.
    """

    _SYSTEM = (
        "You are a helpful Python expert. "
        "When asked for library recommendations always include the exact "
        "pip install command(s) so the user can get started immediately."
    )

    def __init__(
        self,
        model: str = "gpt-4o-mini",
        api_key: str | None = None,
        base_url: str | None = None,
        max_tokens: int = 600,
        temperature: float = 0.7,
        rate_limit_delay: float = 1.0,
    ) -> None:
        try:
            import openai  # local import so the dep is optional
        except ImportError as exc:
            raise ImportError("Run: pip install openai") from exc

        self._model = model
        self._max_tokens = max_tokens
        self._temperature = temperature
        self._delay = rate_limit_delay
        self._client = openai.OpenAI(
            api_key=api_key or os.environ.get("OPENAI_API_KEY"),
            **({"base_url": base_url} if base_url else {}),
        )

    @property
    def provider_name(self) -> str:
        return "openai"

    @property
    def model_name(self) -> str:
        return self._model

    def complete(self, prompt: str) -> str:
        time.sleep(self._delay)
        resp = self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": self._SYSTEM},
                {"role": "user", "content": prompt},
            ],
            max_tokens=self._max_tokens,
            temperature=self._temperature,
        )
        return resp.choices[0].message.content or ""


# ---------------------------------------------------------------------------
# Anthropic adapter
# ---------------------------------------------------------------------------


class AnthropicAdapter(LLMAdapter):
    """Uses the anthropic Python SDK."""

    _SYSTEM = (
        "You are a helpful Python expert. "
        "When asked for library recommendations always include the exact "
        "pip install command(s) so the user can get started immediately."
    )

    def __init__(
        self,
        model: str = "claude-haiku-4-5-20251001",
        api_key: str | None = None,
        max_tokens: int = 600,
        rate_limit_delay: float = 0.5,
    ) -> None:
        try:
            import anthropic  # local import so the dep is optional
        except ImportError as exc:
            raise ImportError("Run: pip install anthropic") from exc

        self._model = model
        self._max_tokens = max_tokens
        self._delay = rate_limit_delay
        self._client = anthropic.Anthropic(
            api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"),
        )

    @property
    def provider_name(self) -> str:
        return "anthropic"

    @property
    def model_name(self) -> str:
        return self._model

    def complete(self, prompt: str) -> str:
        time.sleep(self._delay)
        msg = self._client.messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            system=self._SYSTEM,
            messages=[{"role": "user", "content": prompt}],
        )
        block = msg.content[0]
        return block.text if hasattr(block, "text") else str(block)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def get_adapter(
    provider: str,
    model: str | None = None,
    **kwargs,
) -> LLMAdapter:
    """
    Return the appropriate LLMAdapter for *provider*.

    provider options: "mock", "openai", "anthropic"
    model: optional override (e.g. "gpt-4o", "claude-sonnet-4-6")
    """
    p = provider.lower().strip()

    if p == "mock":
        return MockAdapter(**kwargs)

    if p == "openai":
        return OpenAIAdapter(model=model or "gpt-4o-mini", **kwargs)

    if p == "anthropic":
        return AnthropicAdapter(model=model or "claude-haiku-4-5-20251001", **kwargs)

    raise ValueError(
        f"Unknown provider {provider!r}. Choose from: mock, openai, anthropic"
    )
