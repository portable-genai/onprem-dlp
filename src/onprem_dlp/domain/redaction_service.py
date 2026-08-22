"""Deterministic redaction: apply a per-entity strategy to detected spans."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .models import (
    AppliedRedaction,
    EntityType,
    Finding,
    RedactedText,
    RedactionStrategy,
    TextScanResult,
)


@dataclass(frozen=True, slots=True)
class RedactionService:
    """Replaces findings right-to-left so earlier offsets stay valid.

    ``hash_salt`` is a parameter, not a clock or random read: the same salt gives the
    same token for the same value, which preserves joinability across documents while
    keeping the raw value on-prem.
    """

    strategies: dict[EntityType, RedactionStrategy] = field(default_factory=dict)
    default_strategy: RedactionStrategy = RedactionStrategy.TAG
    hash_salt: str = "onprem-dlp"
    mask_char: str = "*"
    mask_keep_last: int = 4

    def redact(self, text: str, scan: TextScanResult) -> RedactedText:
        applied: list[AppliedRedaction] = []
        out = text
        for finding in sorted(scan.findings, key=lambda f: f.start, reverse=True):
            strategy = self.strategies.get(finding.entity_type, self.default_strategy)
            replacement = self._render(finding, strategy)
            out = out[: finding.start] + replacement + out[finding.end :]
            applied.append(AppliedRedaction(finding, strategy, replacement))
        applied.reverse()  # report in document order
        return RedactedText(text=out, applied=tuple(applied))

    def _render(self, finding: Finding, strategy: RedactionStrategy) -> str:
        if strategy is RedactionStrategy.TAG:
            return f"<{finding.entity_type.value}>"
        if strategy is RedactionStrategy.MASK:
            keep = self.mask_keep_last
            body = finding.text
            if len(body) <= keep:
                return self.mask_char * len(body)
            return self.mask_char * (len(body) - keep) + body[-keep:]
        if strategy is RedactionStrategy.HASH:
            digest = hashlib.sha256((self.hash_salt + finding.text).encode("utf-8")).hexdigest()[
                :12
            ]
            return f"<{finding.entity_type.value}#{digest}>"
        return ""  # REMOVE
