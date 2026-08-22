"""Deterministic text detection: run recognizers, merge engines, resolve overlaps."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from .models import Finding, TextScanResult
from .recognizers import Recognizer, default_recognizers, run_recognizer

#: Findings from model engines (NER / LLM) are advisory: their confidence is capped so
#: a hallucinated span can never outrank a checksum-validated deterministic match.
MODEL_CONFIDENCE_CAP = 0.85


@dataclass(frozen=True, slots=True)
class TextDetectionService:
    """Same text in -> same findings out. No I/O, no models, no clock."""

    recognizers: tuple[Recognizer, ...] = field(default_factory=default_recognizers)
    min_confidence: float = 0.35

    def scan(
        self,
        text: str,
        source_id: str = "",
        extra_findings: Sequence[Finding] = (),
        extra_engines: Sequence[str] = (),
    ) -> TextScanResult:
        """Scan ``text``; ``extra_findings`` are candidates from optional adapters
        (Presidio NER, Gemma) that get capped, filtered and deduplicated here."""
        findings: list[Finding] = []
        for rec in self.recognizers:
            findings.extend(run_recognizer(rec, text))
        findings.extend(self._sanitize_model_findings(extra_findings, text))
        kept = self._resolve(f for f in findings if f.confidence >= self.min_confidence)
        engines = tuple(dict.fromkeys(["regex", *extra_engines]))
        return TextScanResult(
            source_id=source_id,
            text_length=len(text),
            findings=tuple(kept),
            engines=engines,
        )

    def _sanitize_model_findings(self, extras: Sequence[Finding], text: str) -> list[Finding]:
        out: list[Finding] = []
        for f in extras:
            if not (0 <= f.start < f.end <= len(text)):
                continue  # model returned an offset outside the document: discard
            capped = min(f.confidence, MODEL_CONFIDENCE_CAP)
            out.append(
                Finding(
                    entity_type=f.entity_type,
                    start=f.start,
                    end=f.end,
                    text=text[f.start : f.end],
                    confidence=round(capped, 4),
                    recognizer=f.recognizer,
                    validated=False,
                    context_boosted=f.context_boosted,
                )
            )
        return out

    @staticmethod
    def _resolve(findings: Iterable[Finding]) -> list[Finding]:
        """Overlap resolution: prefer validated, then higher confidence, then longer."""
        ranked = sorted(
            findings,
            key=lambda f: (not f.validated, -f.confidence, -(f.end - f.start), f.start),
        )
        kept: list[Finding] = []
        for f in ranked:
            if not any(f.overlaps(k) for k in kept):
                kept.append(f)
        kept.sort(key=lambda f: (f.start, f.end))
        return kept
