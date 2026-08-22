"""Deterministic PII classification of structured columns.

Three explainable signal families, combined into a score an auditor can recompute:

1. name signals   — the column name against a multilingual synonym dictionary;
2. pattern signals — the fraction of sampled values matching the SAME recognizers the
   unstructured pipeline uses (one shared PII definition across both solutions);
3. shape signals  — cardinality ratio, inferred type and length statistics, which
   separate direct identifiers (unique), quasi-identifiers (low-cardinality
   demographics like gender/postcode/birth-year) and free-text risk columns.

Ambiguous scores fall into an adjudication band: if a small-model adjudicator (Gemma)
is wired in, its verdict nudges the score by a BOUNDED amount; otherwise the column is
flagged ``needs_review`` for a human. The engine, not the model, always assigns the
category.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import (
    DIRECT_IDENTIFIERS,
    ColumnCategory,
    ColumnClassification,
    ColumnProfile,
    EntityType,
    Signal,
)

# column-name synonyms -> (entity hint, category hint, weight)
_NAME_RULES: tuple[tuple[tuple[str, ...], EntityType | None, ColumnCategory, float], ...] = (
    (
        ("email", "e_mail", "mail_address"),
        EntityType.EMAIL_ADDRESS,
        ColumnCategory.PII_DIRECT,
        0.45,
    ),
    (("nric", "fin_no", "uin"), EntityType.SG_NRIC, ColumnCategory.PII_DIRECT, 0.45),
    (("hkid",), EntityType.HK_HKID, ColumnCategory.PII_DIRECT, 0.45),
    (
        ("mynumber", "my_number", "kojin_bango"),
        EntityType.JP_MY_NUMBER,
        ColumnCategory.PII_DIRECT,
        0.45,
    ),
    (("tfn", "tax_file"), EntityType.AU_TFN, ColumnCategory.PII_DIRECT, 0.45),
    (("medicare",), EntityType.AU_MEDICARE, ColumnCategory.PII_DIRECT, 0.45),
    (("ssn", "social_security"), EntityType.US_SSN, ColumnCategory.PII_DIRECT, 0.45),
    (("passport",), EntityType.PASSPORT, ColumnCategory.PII_DIRECT, 0.45),
    (
        ("credit_card", "card_number", "card_no", "pan"),
        EntityType.CREDIT_CARD,
        ColumnCategory.PII_DIRECT,
        0.45,
    ),
    (
        ("iban", "account_number", "account_no", "acct_no"),
        EntityType.IBAN,
        ColumnCategory.PII_DIRECT,
        0.4,
    ),
    (
        ("phone", "mobile", "msisdn", "telephone", "contact_no", "handphone"),
        EntityType.PHONE_NUMBER,
        ColumnCategory.PII_DIRECT,
        0.4,
    ),
    (
        (
            "name",
            "first_name",
            "last_name",
            "surname",
            "given_name",
            "full_name",
            "customer_name",
            "shimei",
        ),
        EntityType.PERSON_NAME,
        ColumnCategory.PII_DIRECT,
        0.35,
    ),
    (
        ("address", "street", "addr", "jusho", "residential"),
        EntityType.ADDRESS,
        ColumnCategory.PII_DIRECT,
        0.35,
    ),
    (
        ("dob", "date_of_birth", "birth_date", "birthdate", "birthday", "seinengappi"),
        EntityType.DATE_OF_BIRTH,
        ColumnCategory.PII_QUASI,
        0.4,
    ),
    (
        ("customer_id", "user_id", "member_id", "cust_id", "client_id", "employee_id"),
        EntityType.GENERIC_ID,
        ColumnCategory.PII_QUASI,
        0.25,
    ),
    (("postcode", "postal_code", "zip", "zipcode"), None, ColumnCategory.PII_QUASI, 0.3),
    (
        (
            "gender",
            "sex",
        ),
        None,
        ColumnCategory.PII_QUASI,
        0.3,
    ),
    (("nationality", "citizenship", "country_of_birth"), None, ColumnCategory.PII_QUASI, 0.3),
    (("age", "birth_year"), None, ColumnCategory.PII_QUASI, 0.25),
    (("ip_address", "ip_addr", "client_ip"), EntityType.IP_ADDRESS, ColumnCategory.PII_QUASI, 0.35),
    (("salary", "income", "remuneration", "wage"), None, ColumnCategory.SENSITIVE, 0.4),
    # bare "condition" is too ambiguous (condition_code, order_condition); require a
    # health-qualified phrase instead. "health"/"medical" tokens still match on their own.
    (
        (
            "health",
            "diagnosis",
            "medical",
            "disease",
            "icd",
            "health_condition",
            "medical_condition",
        ),
        None,
        ColumnCategory.SENSITIVE,
        0.45,
    ),
    (
        (
            "religion",
            "religious",
        ),
        None,
        ColumnCategory.SENSITIVE,
        0.45,
    ),
    (
        (
            "ethnicity",
            "race",
        ),
        None,
        ColumnCategory.SENSITIVE,
        0.45,
    ),
    (
        (
            "union",
            "political",
        ),
        None,
        ColumnCategory.SENSITIVE,
        0.35,
    ),
    (
        (
            "biometric",
            "fingerprint",
        ),
        None,
        ColumnCategory.SENSITIVE,
        0.45,
    ),
)

_ACTIONS = {
    ColumnCategory.PII_DIRECT: "tokenize or mask before any cloud egress",
    ColumnCategory.PII_QUASI: "generalise/bucket (k-anonymity) before analytics egress",
    ColumnCategory.SENSITIVE: "block by default; requires explicit DPO approval",
    ColumnCategory.NON_PII: "allow",
}


def _normalise(name: str) -> str:
    # split camelCase / PascalCase so 'fullName' tokenizes like 'full_name' (word-
    # boundary matching then works on the real words, not one fused token). Two passes:
    #   1. acronym-run end:  'NRICNumber' -> 'NRIC_Number'  (an all-caps run fused to a
    #      capitalised word; without this the name signal fail-opens on such columns);
    #   2. lower/digit -> upper:  'fullName' -> 'full_name'.
    # Standalone acronyms (NRIC, HKID, SSN) have no following capitalised word, so they
    # are left intact.
    spaced = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", name)
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", spaced)
    return "".join(c if c.isalnum() else "_" for c in spaced.lower()).strip("_")


def _phrase_in_tokens(tokens: list[str], phrase: str) -> bool:
    """True if ``phrase`` (``_``-joined) appears as a whole-token run in ``tokens``.

    Matches on word boundaries, not raw substrings: ``name`` matches ``full_name``
    and ``customer_name`` but NOT ``filename``/``username``/``hostname``; the
    multi-token ``date_of_birth`` matches ``customer_date_of_birth`` but ``birth``
    alone does not match ``date_of_birth`` unless it is its own token.
    """
    parts = phrase.split("_")
    if len(parts) == 1:
        return parts[0] in tokens
    span = len(parts)
    return any(tokens[i : i + span] == parts for i in range(len(tokens) - span + 1))


@dataclass(frozen=True, slots=True)
class ColumnClassifierService:
    """Pure scoring. Thresholds are fields so a deployment can tune, tests can pin."""

    pii_threshold: float = 0.6  # >= : classify by the strongest signal family
    review_threshold: float = 0.3  # >= and < pii_threshold : adjudication band
    strong_pattern_ratio: float = 0.6
    adjudicator_nudge: float = 0.15  # bounded influence of the optional LLM verdict

    def classify(
        self,
        profile: ColumnProfile,
        adjudication: tuple[bool, float, str] | None = None,
    ) -> ColumnClassification:
        signals: list[Signal] = []
        entity: EntityType | None = None
        category_hint: ColumnCategory | None = None

        # -- 1. column-name signals ------------------------------------------------
        norm = _normalise(profile.name)
        tokens = norm.split("_")
        for synonyms, ent, cat, weight in _NAME_RULES:
            matched = next(
                (s for s in synonyms if s == norm or _phrase_in_tokens(tokens, s)),
                None,
            )
            if matched:
                signals.append(
                    Signal(
                        code=f"name:{matched}",
                        weight=weight,
                        detail=f"column name '{profile.name}' matches synonym '{matched}'",
                    )
                )
                if entity is None:
                    entity, category_hint = ent, cat
                break

        # -- 2. value-pattern signals (shared recognizers) ---------------------------
        best = profile.best_pattern()
        if (
            best is not None
            and best[0] is EntityType.DATE_OF_BIRTH
            and entity is not EntityType.DATE_OF_BIRTH
        ):
            # Every date column full-matches the DOB pattern; without a birth-ish
            # column name that is weak evidence, not a quasi-identifier verdict.
            etype, ratio = best
            signals.append(
                Signal(
                    code="pattern:date_weak",
                    weight=round(0.15 * ratio, 4),
                    detail=(
                        f"{ratio:.0%} of values are dates, but the name does not suggest birth date"
                    ),
                )
            )
        elif best is not None:
            etype, ratio = best
            weight = 0.45 * ratio if ratio >= self.strong_pattern_ratio else 0.2 * ratio
            signals.append(
                Signal(
                    code=f"pattern:{etype.value}",
                    weight=round(weight, 4),
                    detail=(
                        f"{ratio:.0%} of {profile.sample_size} sampled values match {etype.value}"
                    ),
                )
            )
            if ratio >= self.strong_pattern_ratio:
                entity = entity or etype
                if category_hint is None:
                    category_hint = (
                        ColumnCategory.PII_DIRECT
                        if etype in DIRECT_IDENTIFIERS
                        else ColumnCategory.PII_QUASI
                    )

        # -- 3. shape signals: cardinality & type ------------------------------------
        card = profile.cardinality_ratio
        if profile.non_null_count >= 20:
            if card >= 0.95 and profile.inferred_type == "text" and entity is not None:
                signals.append(
                    Signal(
                        code="cardinality:unique",
                        weight=0.15,
                        detail=f"near-unique values (ratio {card:.2f}) — identifier-shaped",
                    )
                )
            elif card >= 0.95 and entity is None and profile.inferred_type in ("text", "numeric"):
                signals.append(
                    Signal(
                        code="cardinality:unique_unknown",
                        weight=0.1,
                        detail=(
                            f"near-unique values (ratio {card:.2f}) with no known pattern — "
                            "possible internal identifier that joins back to a person"
                        ),
                    )
                )
            elif card <= 0.05 and category_hint is ColumnCategory.PII_QUASI:
                signals.append(
                    Signal(
                        code="cardinality:low_categorical",
                        weight=0.1,
                        detail=(
                            f"low-cardinality categorical (ratio {card:.2f}) "
                            "consistent with a demographic attribute"
                        ),
                    )
                )
            elif card <= 0.02 and entity is None and category_hint is None:
                signals.append(
                    Signal(
                        code="cardinality:low",
                        weight=-0.15,
                        detail=(
                            f"very low cardinality (ratio {card:.2f}) — "
                            "looks like a code/category, not a person identifier"
                        ),
                    )
                )
        if profile.inferred_type == "numeric" and entity is None and category_hint is None:
            signals.append(Signal(code="type:numeric", weight=-0.1, detail="plain numeric measure"))

        score = max(0.0, min(1.0, sum(s.weight for s in signals)))

        # -- adjudication band --------------------------------------------------------
        needs_review = False
        llm_adjudicated = False
        rationale: str | None = None
        if self.review_threshold <= score < self.pii_threshold:
            if adjudication is not None:
                is_pii, verdict_conf, rationale = adjudication
                nudge = (
                    self.adjudicator_nudge
                    * (1 if is_pii else -1)
                    * max(0.0, min(1.0, verdict_conf))
                )
                signals.append(
                    Signal(
                        code="llm:adjudication",
                        weight=round(nudge, 4),
                        detail=(
                            f"Gemma adjudicator says {'PII' if is_pii else 'non-PII'} "
                            f"(conf {verdict_conf:.2f})"
                        ),
                    )
                )
                score = max(0.0, min(1.0, score + nudge))
                llm_adjudicated = True
            if self.review_threshold <= score < self.pii_threshold:
                needs_review = True  # still ambiguous: a human decides

        if score >= self.pii_threshold:
            category = category_hint or ColumnCategory.PII_DIRECT
        elif (
            (needs_review and category_hint is not None)
            or score >= self.pii_threshold * 0.5
            and category_hint
            in (
                ColumnCategory.PII_QUASI,
                ColumnCategory.SENSITIVE,
            )
        ):
            category = category_hint
        else:
            category = ColumnCategory.NON_PII

        return ColumnClassification(
            profile=profile,
            category=category,
            score=round(score, 4),
            signals=tuple(signals),
            entity_type=entity,
            recommended_action=_ACTIONS[category],
            needs_review=needs_review,
            llm_adjudicated=llm_adjudicated,
            llm_rationale=rationale,
        )
