"""Gemma via llama-cpp-python: in-process GGUF inference for air-gapped hosts.

Install the extra and fetch a quantised Gemma once:

    pip install 'onprem-dlp[llamacpp]'
    # e.g. gemma-3-1b-it Q4_K_M GGUF (~800 MB) copied to the host

The ``llama_cpp`` import happens inside ``_llm`` so this module can be imported (and
contract-tested) without the wheel installed.
"""

from __future__ import annotations

from collections.abc import Sequence

from ...adapter_settings import AdapterSettings
from ...domain.models import AdjudicationVerdict, Finding
from .prompts import (
    build_column_prompt,
    build_ner_prompt,
    parse_column_response,
    parse_ner_response,
)


class LlamaCppGemmaClient:
    def __init__(
        self,
        settings: AdapterSettings,
    ) -> None:
        self.model_path = str(settings.require("model_path"))
        self.n_ctx = int(settings.get("n_ctx", 8192))
        self.n_threads = settings.get("n_threads")
        self.max_chars = int(settings.get("max_chars", 6000))
        self._model = None

    @property
    def engine_name(self) -> str:
        return "llm:llamacpp/gemma"

    def _llm(self):
        if self._model is None:
            from llama_cpp import Llama  # lazy: optional heavy dependency

            self._model = Llama(
                model_path=self.model_path,
                n_ctx=self.n_ctx,
                n_threads=self.n_threads,
                verbose=False,
            )
        return self._model

    def _generate(self, prompt: str) -> str | None:
        try:
            out = self._llm().create_chat_completion(
                messages=[{"role": "user", "content": prompt}],
                temperature=0,
                max_tokens=768,
                response_format={"type": "json_object"},
            )
        except Exception:  # fail soft, same contract as the Ollama transport
            return None
        choices = out.get("choices") or []
        if not choices:
            return None
        return choices[0].get("message", {}).get("content")

    def analyze(self, text: str) -> Sequence[Finding]:
        raw = self._generate(build_ner_prompt(text[: self.max_chars]))
        if raw is None:
            return ()
        return tuple(parse_ner_response(raw, text, self.engine_name))

    def adjudicate_column(
        self,
        table: str,
        column: str,
        profile_summary: str,  # noqa: ARG002
    ) -> AdjudicationVerdict | None:
        raw = self._generate(build_column_prompt(profile_summary))
        return parse_column_response(raw) if raw is not None else None
