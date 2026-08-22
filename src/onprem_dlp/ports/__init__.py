"""Ports: the hexagon boundary. Every external capability is a typing.Protocol.

Adapters register here by shape, not inheritance — the contract test asserts each
shipped adapter satisfies its Protocol at runtime.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from ..domain.models import AdjudicationVerdict, AuditEvent, Finding, OcrResult, PixelBox

__all__ = [
    "AuditSink",
    "ColumnSampler",
    "ImageRedactor",
    "LlmAdjudicator",
    "NerAnalyzer",
    "OcrEngine",
]


@runtime_checkable
class NerAnalyzer(Protocol):
    """Adds model-based findings (PERSON_NAME, ADDRESS, ...) the regexes cannot see."""

    @property
    def engine_name(self) -> str: ...

    def analyze(self, text: str) -> Sequence[Finding]: ...


@runtime_checkable
class OcrEngine(Protocol):
    """Extracts word-level text + pixel boxes from an image on the local machine."""

    def extract(self, image_path: str) -> OcrResult: ...


@runtime_checkable
class ImageRedactor(Protocol):
    """Paints opaque boxes over PII regions and writes the sanitised copy."""

    def redact(self, image_path: str, boxes: Sequence[PixelBox], output_path: str) -> str: ...


@runtime_checkable
class LlmAdjudicator(Protocol):
    """Small local model (Gemma) giving ADVISORY verdicts on ambiguous cases only."""

    def adjudicate_column(
        self, table: str, column: str, profile_summary: str
    ) -> AdjudicationVerdict | None: ...


@runtime_checkable
class ColumnSampler(Protocol):
    """Reads column samples from a structured source (CSV, SQLite, Postgres, ...)."""

    @property
    def source_name(self) -> str: ...

    def tables(self) -> Sequence[str]: ...

    def columns(self, table: str) -> Sequence[str]: ...

    def sample(self, table: str, column: str, limit: int) -> Sequence[str | None]: ...


@runtime_checkable
class AuditSink(Protocol):
    """Append-only audit trail for every scan and egress decision."""

    def record(self, event: AuditEvent) -> None: ...
