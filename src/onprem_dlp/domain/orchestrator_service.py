"""Orchestrator: composes the deterministic services with the optional ports.

This is the only domain object that talks to ports (as ``typing.Protocol`` instances
injected by the container) — and it only ever treats their output as candidates or
advisory verdicts for the deterministic services to weigh.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .column_classifier_service import ColumnClassifierService
from .column_profile_service import ColumnProfileService
from .detection_service import TextDetectionService
from .egress_policy_service import EgressPolicyService
from .models import (
    AuditEvent,
    ColumnClassification,
    DatasetClassification,
    EgressDecision,
    Finding,
    ImageScanResult,
    OcrResult,
    PixelBox,
    RedactedText,
    TextScanResult,
)
from .redaction_service import RedactionService

if TYPE_CHECKING:  # ports are Protocols; import only for type checkers
    from ..ports import AuditSink, ColumnSampler, LlmAdjudicator, NerAnalyzer, OcrEngine


@dataclass(frozen=True, slots=True)
class DlpOrchestrator:
    detection: TextDetectionService = field(default_factory=TextDetectionService)
    redaction: RedactionService = field(default_factory=RedactionService)
    profiler: ColumnProfileService = field(default_factory=ColumnProfileService)
    classifier: ColumnClassifierService = field(default_factory=ColumnClassifierService)
    egress: EgressPolicyService = field(default_factory=EgressPolicyService)
    ner: NerAnalyzer | None = None
    adjudicator: LlmAdjudicator | None = None
    audit: AuditSink | None = None

    # ------------------------------------------------------------- unstructured text

    def scan_text(self, text: str, source_id: str = "text") -> TextScanResult:
        extra: list[Finding] = []
        engines: list[str] = []
        if self.ner is not None:
            extra.extend(self.ner.analyze(text))
            engines.append(self.ner.engine_name)
        scan = self.detection.scan(
            text, source_id=source_id, extra_findings=extra, extra_engines=engines
        )
        self._audit("scan_text", source_id, {"findings": scan.entity_counts})
        return scan

    def redact_text(self, text: str, source_id: str = "text") -> RedactedText:
        scan = self.scan_text(text, source_id)
        redacted = self.redaction.redact(text, scan)
        self._audit("redact_text", source_id, {"applied": len(redacted.applied)})
        return redacted

    def decide_egress(self, text: str, source_id: str = "text") -> EgressDecision:
        decision = self.egress.decide(self.scan_text(text, source_id))
        self._audit(
            "egress_decision",
            source_id,
            {"action": decision.action.value, "escalates": decision.escalates},
        )
        return decision

    # ------------------------------------------------------------------------ images

    def scan_image(
        self, image_path: str, ocr: OcrEngine, source_id: str | None = None
    ) -> ImageScanResult:
        """OCR the image, scan the concatenated text, map findings back to boxes."""
        source_id = source_id or image_path
        ocr_result = ocr.extract(image_path)
        text, offsets = self._join_words(ocr_result)
        scan = self.scan_text(text, source_id=source_id)
        boxes = self._boxes_for_findings(scan, ocr_result, offsets)
        self._audit("scan_image", source_id, {"findings": scan.entity_counts, "boxes": len(boxes)})
        return ImageScanResult(source_id=source_id, scan=scan, boxes=boxes)

    @staticmethod
    def _join_words(ocr_result: OcrResult) -> tuple[str, list[tuple[int, int]]]:
        """Concatenate OCR words with spaces; return (text, per-word [start,end))."""
        parts: list[str] = []
        offsets: list[tuple[int, int]] = []
        pos = 0
        for w in ocr_result.words:
            if parts:
                pos += 1  # separating space
            start = pos
            parts.append(w.text)
            pos += len(w.text)
            offsets.append((start, pos))
        return " ".join(parts), offsets

    @staticmethod
    def _boxes_for_findings(
        scan: TextScanResult, ocr_result: OcrResult, offsets: list[tuple[int, int]]
    ) -> tuple[PixelBox, ...]:
        boxes: list[PixelBox] = []
        for f in scan.findings:
            for (start, end), word in zip(offsets, ocr_result.words, strict=True):
                if start < f.end and f.start < end:  # word overlaps the finding
                    boxes.append(PixelBox(word.left, word.top, word.width, word.height))
        # dedupe, preserve order
        seen: set[tuple[int, int, int, int]] = set()
        unique: list[PixelBox] = []
        for b in boxes:
            key = (b.left, b.top, b.width, b.height)
            if key not in seen:
                seen.add(key)
                unique.append(b)
        return tuple(unique)

    # ------------------------------------------------------------------- structured

    def classify_columns(
        self, sampler: ColumnSampler, sample_limit: int = 500
    ) -> DatasetClassification:
        results: list[ColumnClassification] = []
        for table in sampler.tables():
            for column in sampler.columns(table):
                values = sampler.sample(table, column, sample_limit)
                profile = self.profiler.profile(table, column, values)
                provisional = self.classifier.classify(profile)
                adjudication = None
                if provisional.needs_review and self.adjudicator is not None:
                    verdict = self.adjudicator.adjudicate_column(
                        table=table,
                        column=column,
                        profile_summary=self._profile_summary(profile),
                    )
                    if verdict is not None:
                        adjudication = (verdict.is_pii, verdict.confidence, verdict.rationale)
                results.append(self.classifier.classify(profile, adjudication))
        dataset = DatasetClassification(source=sampler.source_name, columns=tuple(results))
        self._audit(
            "classify_columns",
            sampler.source_name,
            {
                "columns": len(dataset.columns),
                "pii": [c.profile.name for c in dataset.pii_columns],
                "needs_review": [c.profile.name for c in dataset.columns if c.needs_review],
            },
        )
        return dataset

    @staticmethod
    def _profile_summary(profile) -> str:  # noqa: ANN001 - domain model
        best = profile.best_pattern()
        return (
            f"table={profile.table} column={profile.name} type={profile.inferred_type} "
            f"cardinality_ratio={profile.cardinality_ratio:.2f} "
            f"null_ratio={profile.null_ratio:.2f} "
            f"avg_length={profile.avg_length} digit_ratio={profile.digit_ratio:.2f} "
            f"best_pattern={best[0].value + ':' + format(best[1], '.0%') if best else 'none'}"
        )

    # ------------------------------------------------------------------------- audit

    def _audit(self, kind: str, source_id: str, payload: dict) -> None:
        if self.audit is not None:
            self.audit.record(AuditEvent(kind=kind, source_id=source_id, payload=payload))
