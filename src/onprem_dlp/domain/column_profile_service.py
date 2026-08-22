"""Deterministic column profiling: the statistics the classifier reasons over."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field

from .models import ColumnProfile, EntityType
from .recognizers import Recognizer, default_recognizers, match_ratio

_NUMERIC_RE = re.compile(r"[+-]?\d+(?:\.\d+)?")
_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}|\d{1,2}[/-]\d{1,2}[/-]\d{2,4}")
_BOOL_VALUES = frozenset({"true", "false", "yes", "no", "y", "n", "0", "1", "t", "f"})

#: Only report pattern hits at or above this ratio; below it the signal is noise.
_MIN_HIT_RATIO = 0.3


@dataclass(frozen=True, slots=True)
class ColumnProfileService:
    """Profile a sample of raw string values. Same sample in -> same profile out."""

    recognizers: tuple[Recognizer, ...] = field(default_factory=default_recognizers)
    max_pattern_sample: int = 500

    def profile(
        self,
        table: str,
        name: str,
        values: Sequence[str | None],
    ) -> ColumnProfile:
        total = len(values)
        non_null = [str(v).strip() for v in values if v is not None and str(v).strip() != ""]
        null_count = total - len(non_null)
        distinct = len(set(non_null))
        lengths = [len(v) for v in non_null]
        chars = "".join(non_null[: self.max_pattern_sample])
        digit_ratio = sum(c.isdigit() for c in chars) / len(chars) if chars else 0.0
        alpha_ratio = sum(c.isalpha() for c in chars) / len(chars) if chars else 0.0

        pattern_sample = non_null[: self.max_pattern_sample]
        hits: list[tuple[EntityType, float]] = []
        for rec in self.recognizers:
            ratio = match_ratio(rec, pattern_sample)
            if ratio >= _MIN_HIT_RATIO:
                hits.append((rec.entity_type, round(ratio, 4)))
        # keep only the best ratio per entity type, best-first
        best: dict[EntityType, float] = {}
        for etype, ratio in hits:
            best[etype] = max(best.get(etype, 0.0), ratio)
        ordered = tuple(sorted(best.items(), key=lambda p: -p[1]))

        return ColumnProfile(
            table=table,
            name=name,
            total_count=total,
            null_count=null_count,
            distinct_count=distinct,
            sample_size=len(pattern_sample),
            avg_length=round(sum(lengths) / len(lengths), 2) if lengths else 0.0,
            digit_ratio=round(digit_ratio, 4),
            alpha_ratio=round(alpha_ratio, 4),
            inferred_type=self._infer_type(non_null),
            pattern_hits=ordered,
        )

    @staticmethod
    def _infer_type(values: list[str]) -> str:
        if not values:
            return "empty"
        sample = values[:200]
        if all(v.lower() in _BOOL_VALUES for v in sample):
            return "boolean"
        if all(_DATE_RE.fullmatch(v) for v in sample):
            return "date"
        if all(_NUMERIC_RE.fullmatch(v.replace(",", "")) for v in sample):
            return "numeric"
        return "text"
