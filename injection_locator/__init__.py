"""
injection_locator — Prompt injection locator pipeline.

Exports:
    InjectionLocator          : Slow but thorough two-phase LLM re-prompting locator.
    EmbeddingInjectionLocator : Lightning-fast cosine-similarity embedding locator.
    InjectionReport           : Dataclass with the locator's findings.
    ContextEntry              : Structured conversation log entry.
    SourceMapper              : Maps context segments back to original input sources.
"""

from .models import InjectionReport, ContextEntry
from .injection_locator import InjectionLocator
from .embedding_locator import EmbeddingInjectionLocator
from .source_mapper import SourceMapper

__all__ = [
    "InjectionLocator",
    "EmbeddingInjectionLocator",
    "InjectionReport",
    "ContextEntry",
    "SourceMapper",
]
