"""The reusable, vertical-neutral kernel: detection, redaction, decision and evidence types.

This module is the half of the domain a fork inherits untouched. It carries the deterministic
machinery SPEC.md names: the detected-span and scan-result evidence model, the redaction
strategies and their applied record, the OCR/pixel geometry, the column profile and
classification structures, the egress action/reason/decision types, the advisory LLM verdict
envelope, the shared severity scale and the audit event.

It is stdlib-only and, by design, **imports nothing from this package**. That is the whole
point of the split and ``tests/unit/test_kernel_boundary.py`` proves it by execution: a fresh
interpreter importing this module must never pull ``onprem_dlp.domain.models`` in. The
jurisdiction label pack, the identifiability judgement over it and the bank egress policy are
adopter-owned and live in ``models.py``, which imports this module and re-exports every name
here so no call site has to know where a type lives.

Entity labels are typed against :class:`OpenLabel`, the member-less open taxonomy base that a
vertical subclasses with its own jurisdiction labels. The kernel therefore never names a
jurisdiction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum


def utcnow() -> datetime:
    """Timezone-aware current instant. One clock for every audit and evidence record."""
    return datetime.now(UTC)


class OpenLabel(StrEnum):
    """Open, config-extensible uppercase label taxonomy.

    Deliberately member-less: the vertical subclasses it and supplies the jurisdiction labels.
    The extension rule (a safe uppercase alphanumeric/underscore string becomes a stable
    pseudo-member) is kernel behaviour, so an adopter's configured label works everywhere the
    built-in ones do without editing the kernel.
    """

    @classmethod
    def _missing_(cls, value: object) -> OpenLabel | None:
        """Create a stable pseudo-member for a safe config-only uppercase extension."""
        if not isinstance(value, str) or not value or not value.replace("_", "").isalnum():
            return None
        normalized = value.upper()
        member = str.__new__(cls, normalized)
        member._name_ = normalized
        member._value_ = normalized
        cls._value2member_map_[normalized] = member
        return member


class Severity(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True, slots=True)
class Finding:
    """One detected PII span with full provenance.

    ``recognizer`` records which engine produced it (``regex:sg_nric``,
    ``ner:presidio``, ``llm:gemma-ollama``) so every downstream decision is auditable.
    """

    entity_type: OpenLabel
    start: int
    end: int
    text: str
    confidence: float
    recognizer: str
    validated: bool = False  # a checksum/structural validator confirmed the match
    context_boosted: bool = False

    def overlaps(self, other: Finding) -> bool:
        return self.start < other.end and other.start < self.end


@dataclass(frozen=True, slots=True)
class TextScanResult:
    """Outcome of scanning one unit of text (document, prompt, OCR extract)."""

    source_id: str
    text_length: int
    findings: tuple[Finding, ...]
    engines: tuple[str, ...]  # every engine consulted, even if it found nothing

    @property
    def entity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.entity_type.value] = counts.get(f.entity_type.value, 0) + 1
        return counts


class RedactionStrategy(StrEnum):
    TAG = "tag"  # replace with <ENTITY_TYPE>
    MASK = "mask"  # keep last 4 chars, star the rest
    HASH = "hash"  # salted SHA-256 token, stable within a salt
    REMOVE = "remove"  # delete the span


@dataclass(frozen=True, slots=True)
class AppliedRedaction:
    finding: Finding
    strategy: RedactionStrategy
    replacement: str


@dataclass(frozen=True, slots=True)
class RedactedText:
    text: str
    applied: tuple[AppliedRedaction, ...]


# --------------------------------------------------------------------------- images


@dataclass(frozen=True, slots=True)
class OcrWord:
    """One OCR token with its pixel bounding box."""

    text: str
    left: int
    top: int
    width: int
    height: int
    confidence: float


@dataclass(frozen=True, slots=True)
class OcrResult:
    words: tuple[OcrWord, ...]

    @property
    def full_text(self) -> str:
        return " ".join(w.text for w in self.words)


@dataclass(frozen=True, slots=True)
class PixelBox:
    left: int
    top: int
    width: int
    height: int


@dataclass(frozen=True, slots=True)
class ImageScanResult:
    source_id: str
    scan: TextScanResult
    boxes: tuple[PixelBox, ...]  # pixel regions containing the findings


# ----------------------------------------------------------------- structured columns


@dataclass(frozen=True, slots=True)
class ColumnProfile:
    """Deterministic statistics computed from a sample of one column's values."""

    table: str
    name: str
    total_count: int
    null_count: int
    distinct_count: int
    sample_size: int
    avg_length: float
    digit_ratio: float  # fraction of characters that are digits
    alpha_ratio: float
    inferred_type: str  # "numeric" | "text" | "date" | "boolean" | "empty"
    pattern_hits: tuple[tuple[OpenLabel, float], ...]  # entity -> full-match ratio

    @property
    def non_null_count(self) -> int:
        return self.total_count - self.null_count

    @property
    def cardinality_ratio(self) -> float:
        """distinct / non-null. 1.0 means every value is unique (identifier-like)."""
        return self.distinct_count / self.non_null_count if self.non_null_count else 0.0

    @property
    def null_ratio(self) -> float:
        return self.null_count / self.total_count if self.total_count else 0.0

    def best_pattern(self) -> tuple[OpenLabel, float] | None:
        return max(self.pattern_hits, key=lambda p: p[1], default=None)


class ColumnCategory(StrEnum):
    PII_DIRECT = "PII_DIRECT"  # identifies a person on its own
    PII_QUASI = "PII_QUASI"  # identifying in combination (dob, postcode, ...)
    SENSITIVE = "SENSITIVE"  # special-category data (health, religion, salary)
    NON_PII = "NON_PII"


@dataclass(frozen=True, slots=True)
class Signal:
    """One weighted, explainable contribution to a column classification."""

    code: str  # e.g. "name_match:email", "pattern:SG_NRIC", "cardinality:unique"
    weight: float  # signed contribution to the PII score
    detail: str


@dataclass(frozen=True, slots=True)
class ColumnClassification:
    profile: ColumnProfile
    category: ColumnCategory
    score: float  # 0..1 PII likelihood the deterministic engine computed
    signals: tuple[Signal, ...]
    entity_type: OpenLabel | None  # best guess at what the column holds
    recommended_action: str
    needs_review: bool = False  # ambiguous and no adjudicator available
    llm_adjudicated: bool = False
    llm_rationale: str | None = None


@dataclass(frozen=True, slots=True)
class DatasetClassification:
    source: str
    columns: tuple[ColumnClassification, ...]

    @property
    def pii_columns(self) -> tuple[ColumnClassification, ...]:
        return tuple(
            c
            for c in self.columns
            if c.category in (ColumnCategory.PII_DIRECT, ColumnCategory.SENSITIVE)
        )

    @property
    def escalates(self) -> bool:
        return any(c.needs_review for c in self.columns)


# ------------------------------------------------------------------------ egress gate


class EgressAction(StrEnum):
    ALLOW = "ALLOW"
    REDACT = "REDACT"  # allow only the redacted rendering
    BLOCK = "BLOCK"  # hold; a human must release


@dataclass(frozen=True, slots=True)
class EgressReason:
    severity: Severity
    summary: str
    detail: str


@dataclass(frozen=True, slots=True)
class EgressDecision:
    source_id: str
    action: EgressAction
    reasons: tuple[EgressReason, ...]
    findings_considered: int

    @property
    def escalates(self) -> bool:
        """BLOCK never auto-releases: it flips the case to human review."""
        return self.action is EgressAction.BLOCK


# ------------------------------------------------------------------- LLM advisory I/O


@dataclass(frozen=True, slots=True)
class AdjudicationVerdict:
    """Advisory verdict from the optional small-model (Gemma) adjudicator.

    The deterministic services translate this into a bounded confidence adjustment;
    the verdict itself never redacts, blocks, or classifies anything.
    """

    is_pii: bool
    confidence: float
    rationale: str


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """Flat, JSON-serialisable audit record for every scan/decision."""

    kind: str
    source_id: str
    payload: dict = field(default_factory=dict)
