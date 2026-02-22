"""
injection_locator/embedding_locator.py

Lightning-fast embedding-based injection locator.
──────────────────────────────────────────────────
Instead of re-prompting the LLM (O(N) API calls), this locator:

  1. Embeds the malicious tool call into a vector — the "crime vector".
  2. Chunks each ContextEntry into sentence-level fragments and embeds them
     all in a single batch call to a tiny, fast embedding model.
  3. Computes cosine similarity between the crime vector and every chunk:

         cos(A, B) = (A · B) / (‖A‖ · ‖B‖)

  4. Returns the chunk(s) above a similarity threshold as the injection source.

Searching by mathematical intent rather than raw text means the locator
catches paraphrased instructions and adversarially obfuscated payloads
that literal string search would miss.

Two embedding backends are supported:
  - "openai" : OpenAI text-embedding-3-small (requires OPENAI_API_KEY).
  - "local"  : sentence-transformers all-MiniLM-L6-v2 (fully offline, ~80 MB).

Backend auto-selection: OpenAI if OPENAI_API_KEY is set in the environment,
otherwise the local model is used.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import sys
from dataclasses import dataclass

import numpy as np

from .models import ContextEntry, InjectionReport

logger = logging.getLogger(__name__)

# Terminal colours (same palette as injection_locator.py)
_TAG = "\033[36m[PromptGate]\033[0m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RESET = "\033[0m"
_BG_RED = "\033[41m\033[97m"  # Red background + white text

# Minimum cosine similarity to flag a chunk as the injection source.
DEFAULT_THRESHOLD = 0.60

# Number of top-matching chunks to include in the search_path debug log.
TOP_N_LOG = 5

# Sentence splitter: splits on whitespace that follows terminal punctuation,
# or on two-or-more consecutive newlines (paragraph breaks).
_SENT_SPLIT = re.compile(r"(?<=[.!?\n])\s+|\n{2,}")

# Strips raw ANSI/VT100 escape sequences produced by the PTY (cursor moves,
# colour codes, box-drawing, etc.) so the displayed text is readable.
_ANSI_ESC = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

# Minimum chunk character length — discard whitespace-only or trivial fragments.
_MIN_CHUNK_LEN = 15

# Loggers that print noise while sentence-transformers loads model weights.
_NOISY_LOGGERS = (
    "transformers",
    "sentence_transformers",
    "tokenizers",
    "huggingface_hub",
    "filelock",
)


@contextlib.contextmanager
def _silent_model_load():
    """
    Suppress all output produced while loading sentence-transformers weights.

    - Raises every noisy library logger to ERROR so INFO/WARNING is hidden.
    - Redirects sys.stderr to /dev/null to swallow tqdm bars and any direct
      stderr writes (e.g. from the Rust tokenizers extension).
    """
    orig_levels = {}
    for name in _NOISY_LOGGERS:
        lgr = logging.getLogger(name)
        orig_levels[name] = lgr.level
        lgr.setLevel(logging.ERROR)

    old_stderr = sys.stderr
    try:
        sys.stderr = open(os.devnull, "w")
        yield
    finally:
        sys.stderr.close()
        sys.stderr = old_stderr
        for name, lvl in orig_levels.items():
            logging.getLogger(name).setLevel(lvl)


@dataclass
class _Chunk:
    """A sentence-level fragment linked back to its source ContextEntry."""
    text: str
    entry: ContextEntry
    entry_index: int


class EmbeddingInjectionLocator:
    """
    Cosine-similarity injection locator using a fast embedding model.

    Replaces the slow two-phase LLM re-prompting approach with instant
    semantic search: embed once, compare everywhere.

    Args:
        context_log     : Captured conversation entries from TTYWrapper.
        blocked_command : The malicious command that was blocked
                          (e.g. "pip install evil-pkg").
        backend         : "openai", "local", or "auto" (default).
                          "auto" picks OpenAI when OPENAI_API_KEY is set,
                          otherwise falls back to the local model.
        threshold       : Cosine similarity threshold in [0, 1]. Chunks
                          below this score are not reported. Default 0.60.
        openai_model    : OpenAI model name.
                          Default "text-embedding-3-small".
        local_model     : sentence-transformers model name.
                          Default "all-MiniLM-L6-v2".
    """

    def __init__(
        self,
        context_log: list[ContextEntry],
        blocked_command: str,
        backend: str = "auto",
        threshold: float = DEFAULT_THRESHOLD,
        openai_model: str = "text-embedding-3-small",
        local_model: str = "all-MiniLM-L6-v2",
    ) -> None:
        self._context = context_log
        self._blocked_command = blocked_command
        self._threshold = threshold
        self._openai_model = openai_model
        self._local_model = local_model
        self._backend = self._resolve_backend(backend)

    # ── Public API ─────────────────────────────────────────────────────────────

    def locate(self) -> InjectionReport:
        """
        Run the embedding similarity search and return the result.

        Steps:
          1. Chunk every ContextEntry into sentence-level fragments.
          2. Embed [blocked_command] + [all chunks] in a single batch call.
          3. Compute cosine similarity between the crime vector (index 0) and
             every chunk vector.
          4. Return the highest-scoring chunk if it exceeds the threshold.

        Returns:
            InjectionReport identifying the injection source, or a not-found
            report if no chunk exceeds the similarity threshold.
        """
        if not self._context:
            return InjectionReport(
                found=False,
                search_path=["No context entries found"],
            )

        print(
            f"{_TAG} ⚡ Embedding locator ({self._backend} backend) — "
            f"{len(self._context)} context entries"
        )
        print(
            f"{_TAG} Looking for semantic match to: "
            f"{_YELLOW}{self._blocked_command}{_RESET}"
        )

        # Step 1: chunk the context into sentence-level fragments
        chunks = self._chunk_context()
        if not chunks:
            return InjectionReport(
                found=False,
                search_path=["Context produced no embeddable chunks"],
            )

        # Step 2: embed blocked command + all chunks in one batch
        all_texts = [self._blocked_command] + [c.text for c in chunks]
        embeddings = self._embed_batch(all_texts)

        crime_vec = embeddings[0]       # shape (D,)
        chunk_vecs = embeddings[1:]     # shape (N, D)

        # Step 3: cosine similarity between crime vector and every chunk
        similarities = self._cosine_similarity_batch(crime_vec, chunk_vecs)

        # Step 4: rank by similarity (descending)
        ranked = sorted(
            zip(similarities, chunks),
            key=lambda x: x[0],
            reverse=True,
        )

        # Build a debug log of the top-N matches
        search_path: list[str] = []
        for sim, chunk in ranked[:TOP_N_LOG]:
            preview = chunk.text[:80].replace("\n", " ")
            search_path.append(
                f"[entry {chunk.entry_index}] sim={sim:.3f}  \"{preview}…\""
            )

        best_sim, best_chunk = ranked[0]

        print(f"{_TAG} Best match  sim={best_sim:.3f}")
        print(f"{_TAG}   [{best_chunk.entry_index}] {best_chunk.text[:120]!r}")

        if best_sim < self._threshold:
            print(
                f"{_TAG} {_YELLOW}⚠ No chunk exceeded threshold "
                f"({self._threshold:.2f}).{_RESET}"
            )
            return InjectionReport(
                found=False,
                segment_text=best_chunk.text,
                confidence=float(best_sim),
                search_path=search_path,
            )

        source_entry = best_chunk.entry
        print(f"{_TAG} {_BOLD}🎯 Injection source located!{_RESET}")

        # Display a short snippet: a few words of context before and after the
        # malicious chunk, with the chunk itself in red background.
        print(f"{_TAG}")
        print(f"{_TAG} Malicious part (highlighted in {_BG_RED}red background{_RESET}):")
        print(f"{_TAG}")
        clean_content = self._strip_ansi(source_entry.content)
        clean_chunk = self._strip_ansi(best_chunk.text)
        snippet = self._snippet_with_highlight(clean_content, clean_chunk)
        print(snippet)
        print(f"{_TAG}")

        return InjectionReport(
            found=True,
            segment_text=best_chunk.text,
            segment_index=best_chunk.entry_index,
            source_type=source_entry.source_type,
            original_source=(
                source_entry.source_ref
                or f"Context entry {best_chunk.entry_index}"
            ),
            line_range=(
                (source_entry.line_start, source_entry.line_end)
                if source_entry.line_start is not None
                else None
            ),
            confidence=float(best_sim),
            iterations_used=0,      # No LLM re-prompting at all
            search_path=search_path,
        )

    # ── Private helpers ────────────────────────────────────────────────────────

    def _chunk_context(self) -> list[_Chunk]:
        """
        Split every ContextEntry into sentence-level chunks.

        Each entry's content is split on sentence-terminal punctuation
        followed by whitespace, and on paragraph breaks (≥2 newlines).
        Fragments shorter than _MIN_CHUNK_LEN characters are discarded.

        Returns a flat list of _Chunk objects with back-references to
        their source ContextEntry and its index in the original context log.
        """
        chunks: list[_Chunk] = []
        for idx, entry in enumerate(self._context):
            sentences = _SENT_SPLIT.split(entry.content)
            for sent in sentences:
                text = sent.strip()
                if len(text) >= _MIN_CHUNK_LEN:
                    chunks.append(_Chunk(text=text, entry=entry, entry_index=idx))
        return chunks

    def _embed_batch(self, texts: list[str]) -> np.ndarray:
        """
        Embed a list of texts and return a (N, D) float32 array.

        The first element (index 0) is always the blocked command (the
        "crime vector"); the remaining elements are the context chunks.

        Routes to the appropriate backend based on self._backend.
        """
        if self._backend == "openai":
            return self._embed_openai(texts)
        return self._embed_local(texts)

    def _embed_openai(self, texts: list[str]) -> np.ndarray:
        """
        Call the OpenAI Embeddings API.

        Uses text-embedding-3-small by default (1536-dim, very fast, cheap).
        Reads OPENAI_API_KEY from the environment automatically.
        """
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise ImportError(
                "openai package is required for the OpenAI backend: "
                "pip install openai"
            ) from exc

        client = OpenAI()
        response = client.embeddings.create(
            model=self._openai_model,
            input=texts,
            encoding_format="float",
        )
        vecs = [item.embedding for item in response.data]
        return np.array(vecs, dtype=np.float32)

    def _embed_local(self, texts: list[str]) -> np.ndarray:
        """
        Use sentence-transformers all-MiniLM-L6-v2 (fully offline, ~80 MB).

        The model is downloaded on first use and cached by sentence-transformers.
        Embedding a typical context window takes milliseconds on CPU.
        """
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise ImportError(
                "sentence-transformers is required for the local backend: "
                "pip install sentence-transformers"
            ) from exc

        # model = SentenceTransformer(self._local_model)
        with _silent_model_load():                                   
            model = SentenceTransformer(self._local_model) 
        vecs = model.encode(texts, convert_to_numpy=True, show_progress_bar=False)
        return vecs.astype(np.float32)

    @staticmethod
    def _cosine_similarity_batch(
        query: np.ndarray,
        candidates: np.ndarray,
    ) -> np.ndarray:
        """
        Compute cosine similarity between a single query vector and N candidates.

            cos(A, B) = (A · B) / (‖A‖ · ‖B‖)

        Args:
            query      : Shape (D,) — the crime vector.
            candidates : Shape (N, D) — one vector per context chunk.

        Returns:
            Shape (N,) array of cosine similarities in [-1, 1].
        """
        query_norm = query / (np.linalg.norm(query) + 1e-10)
        candidate_norms = candidates / (
            np.linalg.norm(candidates, axis=1, keepdims=True) + 1e-10
        )
        return (candidate_norms @ query_norm).astype(np.float32)

    @staticmethod
    def _highlight_in_text(full_text: str, malicious_part: str) -> str:
        """
        Return full_text with malicious_part wrapped in red-background ANSI codes.

        Falls back to a case-insensitive search, and if the substring still
        cannot be found, wraps the entire text in the highlight.
        """
        idx = full_text.find(malicious_part)
        if idx == -1:
            idx = full_text.lower().find(malicious_part.lower())
        if idx == -1:
            return f"{_BG_RED}{full_text}{_RESET}"
        before = full_text[:idx]
        match = full_text[idx: idx + len(malicious_part)]
        after = full_text[idx + len(malicious_part):]
        return before + _BG_RED + match + _RESET + after

    @staticmethod
    def _snippet_with_highlight(full_text: str, malicious_part: str, context_words: int = 8) -> str:
        """
        Return a short snippet: up to context_words words of surrounding text
        before and after malicious_part, with malicious_part in red background.

        Falls back to highlighting the bare malicious text if it cannot be
        located inside full_text.
        """
        idx = full_text.find(malicious_part)
        if idx == -1:
            idx = full_text.lower().find(malicious_part.lower())
        if idx == -1:
            return f"{_BG_RED}{malicious_part}{_RESET}"

        before_words = full_text[:idx].split()
        after_words = full_text[idx + len(malicious_part):].split()

        prefix = "…" if len(before_words) > context_words else ""
        context_before = " ".join(before_words[-context_words:])
        context_after = " ".join(after_words[:context_words])
        suffix = "…" if len(after_words) > context_words else ""

        # Use the exact slice from full_text to preserve original casing/spacing
        match = full_text[idx: idx + len(malicious_part)]

        parts = []
        if prefix or context_before:
            parts.append(f"{prefix}{context_before} ")
        parts.append(f"{_BG_RED}{match}{_RESET}")
        if context_after or suffix:
            parts.append(f" {context_after}{suffix}")
        return "".join(parts)

    @staticmethod
    def _strip_ansi(text: str) -> str:
        """Remove ANSI/VT100 escape sequences from raw PTY output."""
        return _ANSI_ESC.sub("", text)

    def _resolve_backend(self, backend: str) -> str:
        """Resolve "auto" to a concrete backend name."""
        if backend == "openai":
            return "openai"
        if backend == "local":
            return "local"
        # "auto": prefer OpenAI when the API key is present
        return "openai" if os.getenv("OPENAI_API_KEY") else "local"
