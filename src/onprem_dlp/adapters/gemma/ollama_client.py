"""Gemma via a local Ollama server. Stdlib HTTP only — no SDK required.

Setup on the DLP host (once, while it still has registry access, or from a mirrored
model store):

    ollama pull gemma3:1b     # ~815 MB Q4, CPU-friendly
    # or gemma3:4b for better recall if the host has ~8 GB RAM to spare

The adapter fails SOFT by design: if Ollama is down, NER returns no extra candidates
and adjudication returns None (column stays needs_review). The deterministic pipeline
keeps working; the gate never depends on the model being up.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Sequence

from ...adapter_settings import AdapterSettings
from ...domain.models import AdjudicationVerdict, Finding
from .prompts import (
    build_column_prompt,
    build_ner_prompt,
    parse_column_response,
    parse_ner_response,
)


class OllamaGemmaClient:
    def __init__(
        self,
        settings: AdapterSettings,
    ) -> None:
        self.base_url = str(settings.get("base_url", "http://127.0.0.1:11434")).rstrip("/")
        self.model = str(settings.get("model", "gemma3:1b"))
        self.timeout_seconds = float(settings.get("timeout_seconds", 60.0))
        self.max_chars = int(settings.get("max_chars", 6000))

    @property
    def engine_name(self) -> str:
        return f"llm:ollama/{self.model}"

    # ------------------------------------------------------------------ NerAnalyzer

    def analyze(self, text: str) -> Sequence[Finding]:
        raw = self._generate(build_ner_prompt(text[: self.max_chars]))
        if raw is None:
            return ()
        return tuple(parse_ner_response(raw, text, self.engine_name))

    # --------------------------------------------------------------- LlmAdjudicator

    def adjudicate_column(
        self,
        table: str,
        column: str,
        profile_summary: str,  # noqa: ARG002
    ) -> AdjudicationVerdict | None:
        raw = self._generate(build_column_prompt(profile_summary))
        return parse_column_response(raw) if raw is not None else None

    # ------------------------------------------------------------------- transport

    def _generate(self, prompt: str) -> str | None:
        payload = json.dumps(
            {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "format": "json",
                "options": {"temperature": 0, "num_predict": 768},
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
            return None  # fail soft: deterministic pipeline continues without Gemma
        return body.get("response")
