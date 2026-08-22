"""The adopter-owned vertical: the jurisdiction label pack and the bank egress policy.

Everything vertical-neutral now lives in :mod:`onprem_dlp.domain.kernel` and is re-exported
below, so every existing import site (``from .models import Finding, ...``) keeps working
unchanged while the dependency arrow points one way only: models -> kernel, never back.

What stays here is precisely what a fork rewrites:

* :class:`EntityType`, the jurisdiction label pack (SG NRIC, HK HKID, JP My Number, AU TFN
  and friends). It subclasses the kernel's :class:`~onprem_dlp.domain.kernel.OpenLabel`, so
  the open-extension behaviour is inherited rather than re-implemented.
* :data:`DIRECT_IDENTIFIERS`, the identifiability judgement over that pack.
* :class:`EgressPolicy`, the bank policy: which labels block, which redact, at what
  confidence and at what count.

Jurisdiction recognizer packs (regexes and checksums) are the other half of the vertical and
live in :mod:`onprem_dlp.domain.recognizers`.
"""

from __future__ import annotations

from dataclasses import dataclass

from .kernel import (
    AdjudicationVerdict as AdjudicationVerdict,
)
from .kernel import (
    AppliedRedaction as AppliedRedaction,
)
from .kernel import (
    AuditEvent as AuditEvent,
)
from .kernel import (
    ColumnCategory as ColumnCategory,
)
from .kernel import (
    ColumnClassification as ColumnClassification,
)
from .kernel import (
    ColumnProfile as ColumnProfile,
)
from .kernel import (
    DatasetClassification as DatasetClassification,
)
from .kernel import (
    EgressAction as EgressAction,
)
from .kernel import (
    EgressDecision as EgressDecision,
)
from .kernel import (
    EgressReason as EgressReason,
)
from .kernel import (
    Finding as Finding,
)
from .kernel import (
    ImageScanResult as ImageScanResult,
)
from .kernel import (
    OcrResult as OcrResult,
)
from .kernel import (
    OcrWord as OcrWord,
)
from .kernel import (
    OpenLabel as OpenLabel,
)
from .kernel import (
    PixelBox as PixelBox,
)
from .kernel import (
    RedactedText as RedactedText,
)
from .kernel import (
    RedactionStrategy as RedactionStrategy,
)
from .kernel import (
    Severity as Severity,
)
from .kernel import (
    Signal as Signal,
)
from .kernel import (
    TextScanResult as TextScanResult,
)
from .kernel import (
    utcnow as utcnow,
)


class EntityType(OpenLabel):
    """Open PII taxonomy. Known values are documented; configured extensions remain strings.

    Adopter-owned: the members below are this deployment's jurisdiction pack. The open
    extension rule is inherited from the kernel's :class:`OpenLabel`.
    """

    EMAIL_ADDRESS = "EMAIL_ADDRESS"
    PHONE_NUMBER = "PHONE_NUMBER"
    CREDIT_CARD = "CREDIT_CARD"
    IBAN = "IBAN"
    IP_ADDRESS = "IP_ADDRESS"
    SG_NRIC = "SG_NRIC"
    HK_HKID = "HK_HKID"
    JP_MY_NUMBER = "JP_MY_NUMBER"
    AU_TFN = "AU_TFN"
    AU_ABN = "AU_ABN"
    AU_MEDICARE = "AU_MEDICARE"
    US_SSN = "US_SSN"
    PASSPORT = "PASSPORT"
    DATE_OF_BIRTH = "DATE_OF_BIRTH"
    PERSON_NAME = "PERSON_NAME"
    ADDRESS = "ADDRESS"
    ORGANIZATION = "ORGANIZATION"
    GENERIC_ID = "GENERIC_ID"


#: Entities whose presence alone identifies a natural person (or grants account access).
DIRECT_IDENTIFIERS: frozenset[EntityType] = frozenset(
    {
        EntityType.EMAIL_ADDRESS,
        EntityType.CREDIT_CARD,
        EntityType.IBAN,
        EntityType.SG_NRIC,
        EntityType.HK_HKID,
        EntityType.JP_MY_NUMBER,
        EntityType.AU_TFN,
        EntityType.AU_MEDICARE,
        EntityType.US_SSN,
        EntityType.PASSPORT,
        EntityType.PERSON_NAME,
    }
)


@dataclass(frozen=True, slots=True)
class EgressPolicy:
    """Deterministic egress rules. Tunables live in config, never in code paths."""

    block_entities: frozenset[EntityType]
    redact_entities: frozenset[EntityType]
    min_confidence: float = 0.5
    block_at_or_above: int = 1  # findings from block_entities that force BLOCK

    @staticmethod
    def default() -> EgressPolicy:
        return EgressPolicy(
            block_entities=frozenset(
                {
                    EntityType.CREDIT_CARD,
                    EntityType.SG_NRIC,
                    EntityType.HK_HKID,
                    EntityType.JP_MY_NUMBER,
                    EntityType.AU_TFN,
                    EntityType.AU_MEDICARE,
                    EntityType.US_SSN,
                    EntityType.PASSPORT,
                }
            ),
            redact_entities=frozenset(
                {
                    EntityType.EMAIL_ADDRESS,
                    EntityType.PHONE_NUMBER,
                    EntityType.IBAN,
                    EntityType.IP_ADDRESS,
                    EntityType.DATE_OF_BIRTH,
                    EntityType.PERSON_NAME,
                    EntityType.ADDRESS,
                    EntityType.AU_ABN,
                    EntityType.GENERIC_ID,
                }
            ),
        )
