"""Microsoft Presidio (spaCy NER) adapter — CPU-only, fully on-prem.

Install once:

    pip install 'onprem-dlp[ner]'
    python -m spacy download en_core_web_lg

Presidio contributes PERSON/LOCATION/ORG spans the regex core cannot see. Its results
enter the deterministic pipeline as candidates: capped confidence, overlap-resolved
against checksum-validated matches, and subject to the same egress policy.
"""

from __future__ import annotations

from collections.abc import Sequence

from ...adapter_settings import AdapterSettings
from ...domain.models import EntityType, Finding

_PRESIDIO_TO_ENTITY = {
    "PERSON": EntityType.PERSON_NAME,
    "LOCATION": EntityType.ADDRESS,
    "ORGANIZATION": EntityType.ORGANIZATION,
    "NRP": EntityType.PERSON_NAME,
    "EMAIL_ADDRESS": EntityType.EMAIL_ADDRESS,
    "PHONE_NUMBER": EntityType.PHONE_NUMBER,
    "CREDIT_CARD": EntityType.CREDIT_CARD,
    "IBAN_CODE": EntityType.IBAN,
    "IP_ADDRESS": EntityType.IP_ADDRESS,
    "US_SSN": EntityType.US_SSN,
    "US_PASSPORT": EntityType.PASSPORT,
    "SG_NRIC_FIN": EntityType.SG_NRIC,
    "AU_TFN": EntityType.AU_TFN,
    "AU_ABN": EntityType.AU_ABN,
    "AU_MEDICARE": EntityType.AU_MEDICARE,
    "DATE_TIME": EntityType.DATE_OF_BIRTH,
}

#: DATE_TIME fires on every date; only keep it when Presidio is quite sure.
_MIN_SCORE = {"DATE_TIME": 0.85}


class PresidioNer:
    engine_name = "ner:presidio"

    def __init__(self, settings: AdapterSettings) -> None:
        self.language = str(settings.get("language", "en"))
        self.model_name = settings.get("model_name")
        self._analyzer = None

    def _engine(self):
        if self._analyzer is None:
            from presidio_analyzer import AnalyzerEngine  # lazy: optional dependency

            self._analyzer = AnalyzerEngine()
        return self._analyzer

    def analyze(self, text: str) -> Sequence[Finding]:
        results = self._engine().analyze(text=text, language=self.language)
        findings: list[Finding] = []
        for r in results:
            etype = _PRESIDIO_TO_ENTITY.get(r.entity_type)
            if etype is None or r.score < _MIN_SCORE.get(r.entity_type, 0.4):
                continue
            findings.append(
                Finding(
                    entity_type=etype,
                    start=r.start,
                    end=r.end,
                    text=text[r.start : r.end],
                    confidence=round(float(r.score), 4),
                    recognizer=self.engine_name,
                )
            )
        return tuple(findings)
