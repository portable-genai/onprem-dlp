"""Deterministic egress gate: ALLOW / REDACT / BLOCK, never decided by a model."""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import (
    EgressAction,
    EgressDecision,
    EgressPolicy,
    EgressReason,
    Severity,
    TextScanResult,
)


@dataclass(frozen=True, slots=True)
class EgressPolicyService:
    """Applies an :class:`EgressPolicy` to a scan result.

    BLOCK is a soft stop: the decision's ``escalates`` property flips the payload to
    human review — nothing here auto-releases or auto-destroys data.
    """

    policy: EgressPolicy = field(default_factory=EgressPolicy.default)

    def decide(self, scan: TextScanResult) -> EgressDecision:
        # Fail-closed on the highest-risk category: block-listed findings are honoured
        # regardless of policy.min_confidence (they already cleared the detection floor).
        # Otherwise a format-only block entity like PASSPORT — whose confidence ceiling
        # is ~0.6 — would silently fall through to ALLOW the moment an operator raised
        # the floor above it. Redaction still respects the floor: that knob tunes
        # redaction noise, not whether a national ID may leave the estate.
        floor = self.policy.min_confidence
        blockers = [f for f in scan.findings if f.entity_type in self.policy.block_entities]
        redactables = [
            f
            for f in scan.findings
            if f.entity_type in self.policy.redact_entities and f.confidence >= floor
        ]
        relevant = blockers + redactables

        reasons: list[EgressReason] = []
        for f in blockers:
            reasons.append(
                EgressReason(
                    severity=Severity.HIGH,
                    summary=f"{f.entity_type.value} detected (confidence {f.confidence:.2f})",
                    detail=(
                        f"span [{f.start}:{f.end}] via {f.recognizer}"
                        + ("; checksum-validated" if f.validated else "")
                    ),
                )
            )
        for f in redactables:
            reasons.append(
                EgressReason(
                    severity=Severity.MEDIUM,
                    summary=f"{f.entity_type.value} detected (confidence {f.confidence:.2f})",
                    detail=f"span [{f.start}:{f.end}] via {f.recognizer}; redacted before egress",
                )
            )
        reasons.sort(key=lambda r: (r.severity is not Severity.HIGH, r.summary))

        if len(blockers) >= self.policy.block_at_or_above:
            action = EgressAction.BLOCK
        elif redactables:
            action = EgressAction.REDACT
        else:
            action = EgressAction.ALLOW
            if not relevant:
                reasons.append(
                    EgressReason(
                        severity=Severity.LOW,
                        summary="no findings at or above the confidence floor",
                        detail=f"min_confidence={self.policy.min_confidence}",
                    )
                )
        return EgressDecision(
            source_id=scan.source_id,
            action=action,
            reasons=tuple(reasons),
            findings_considered=len(relevant),
        )
