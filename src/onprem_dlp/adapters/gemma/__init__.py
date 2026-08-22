"""Small Google Gemma model on CPU — the optional context-aware second pass.

Two transports for the same behaviour:

* :class:`OllamaGemmaClient`  — talks to a local Ollama server (default
  ``gemma3:1b``, ~815 MB quantised, runs comfortably on CPU) using stdlib urllib;
* :class:`LlamaCppGemmaClient` — loads a Gemma GGUF directly via ``llama-cpp-python``
  for fully air-gapped hosts with no daemon.

Both implement the ``NerAnalyzer`` and ``LlmAdjudicator`` ports. Everything they emit
is advisory: NER candidates get confidence-capped by the detection service, and column
verdicts only nudge the deterministic score inside a bounded band.
"""

from .llamacpp_client import LlamaCppGemmaClient
from .ollama_client import OllamaGemmaClient

__all__ = ["LlamaCppGemmaClient", "OllamaGemmaClient"]
