"""No-op model engines: honest placeholders when no NER/LLM is installed.

With these bound, detection is regex+checksum only — PERSON_NAME/ADDRESS recall drops
and ambiguous columns escalate to a human instead of a model. That degradation is
deliberate and documented, never silent.
"""

from __future__ import annotations

from collections.abc import Sequence

from ...adapter_settings import AdapterSettings
from ...domain.models import AdjudicationVerdict, Finding


class NullNer:
    engine_name = "ner:none"

    def __init__(self, settings: AdapterSettings) -> None:
        self.settings = settings

    def analyze(self, text: str) -> Sequence[Finding]:  # noqa: ARG002
        return ()


class NullAdjudicator:
    def __init__(self, settings: AdapterSettings) -> None:
        self.settings = settings

    def adjudicate_column(
        self,
        table: str,
        column: str,
        profile_summary: str,  # noqa: ARG002
    ) -> AdjudicationVerdict | None:
        return None
