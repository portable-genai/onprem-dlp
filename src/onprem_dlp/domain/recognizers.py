"""Pure-stdlib PII recognizers: regex candidates hardened by checksum validators.

Design copied from the Presidio model but with zero dependencies: each recognizer is a
compiled regex plus an optional validator (Luhn, NRIC/HKID/MyNumber/TFN/ABN/Medicare
checksums, IBAN mod-97, IPv4 octets) and context words that boost confidence when they
appear near the match. A validator PASS lifts confidence to near-certainty; a validator
FAIL kills the candidate outright — that is what keeps false positives low without ML.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime

from .models import EntityType, Finding

# ------------------------------------------------------------------------- validators


def luhn_valid(digits: str) -> bool:
    if not digits.isdigit() or len(digits) < 13:
        return False
    if len(set(digits)) == 1:
        return False  # degenerate all-identical run (e.g. 0000...) is never a real PAN
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


_NRIC_ST = "JZIHGFEDCBA"
_NRIC_FG = "XWUTRQPNMLK"
_NRIC_M = "KLJNPQRTUWX"
_NRIC_WEIGHTS = (2, 7, 6, 5, 4, 3, 2)


def sg_nric_valid(value: str) -> bool:
    value = value.upper()
    if len(value) != 9 or value[0] not in "STFGM" or not value[1:8].isdigit():
        return False
    s = sum(int(d) * w for d, w in zip(value[1:8], _NRIC_WEIGHTS, strict=True))
    prefix = value[0]
    if prefix in "TG":
        s += 4
    elif prefix == "M":
        s += 3
    table = _NRIC_ST if prefix in "ST" else _NRIC_FG if prefix in "FG" else _NRIC_M
    return table[s % 11] == value[8]


def hk_hkid_valid(value: str) -> bool:
    m = re.fullmatch(r"([A-Z]{1,2})(\d{6})\(?([0-9A])\)?", value.upper())
    if not m:
        return False
    prefix, digits, check = m.groups()
    vals = [36, ord(prefix) - 55] if len(prefix) == 1 else [ord(c) - 55 for c in prefix]
    vals.extend(int(c) for c in digits)
    s = sum(v * w for v, w in zip(vals, range(9, 1, -1), strict=True))
    r = (11 - s % 11) % 11
    return check == ("A" if r == 10 else str(r))


def jp_my_number_valid(value: str) -> bool:
    digits = re.sub(r"[ -]", "", value)
    if not digits.isdigit() or len(digits) != 12:
        return False
    if len(set(digits)) == 1:
        return False  # all-identical run is not a real My Number
    s = 0
    for n in range(1, 12):
        p = int(digits[11 - n])  # P_n = nth digit from the right of the first 11
        q = n + 1 if n <= 6 else n - 5
        s += p * q
    r = s % 11
    return int(digits[11]) == (0 if r <= 1 else 11 - r)


def au_tfn_valid(value: str) -> bool:
    digits = re.sub(r"[ -]", "", value)
    weights = (1, 4, 3, 7, 5, 8, 6, 9, 10)
    if not digits.isdigit() or len(digits) != 9:
        return False
    return sum(int(d) * w for d, w in zip(digits, weights, strict=True)) % 11 == 0


def au_abn_valid(value: str) -> bool:
    digits = re.sub(r"[ ]", "", value)
    if not digits.isdigit() or len(digits) != 11 or digits[0] == "0":
        return False
    weights = (10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19)
    ds = [int(c) for c in digits]
    ds[0] -= 1
    return sum(d * w for d, w in zip(ds, weights, strict=True)) % 89 == 0


def au_medicare_valid(value: str) -> bool:
    digits = re.sub(r"[ /]", "", value)
    if not digits.isdigit() or len(digits) not in (10, 11) or digits[0] not in "23456":
        return False
    weights = (1, 3, 7, 9, 1, 3, 7, 9)
    return sum(int(d) * w for d, w in zip(digits[:8], weights, strict=True)) % 10 == int(digits[8])


def iban_valid(value: str) -> bool:
    v = re.sub(r"[ ]", "", value.upper())
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", v):
        return False
    rearranged = v[4:] + v[:4]
    digits = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    return int(digits) % 97 == 1


def ipv4_valid(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def us_ssn_valid(value: str) -> bool:
    digits = re.sub(r"[- ]", "", value)
    if len(digits) != 9 or not digits.isdigit():
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    return area not in ("000", "666") and area < "900" and group != "00" and serial != "0000"


def phone_plausible(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    return 8 <= len(digits) <= 15


def date_of_birth_valid(value: str) -> bool:
    """Accept only real calendar dates in the recognizer's supported formats."""
    formats = (
        "%d/%m/%Y",
        "%d-%m-%Y",
        "%d/%m/%y",
        "%d-%m-%y",
        "%Y-%m-%d",
        "%d %b %Y",
        "%d %B %Y",
    )
    return any(_date_parses(value, date_format) for date_format in formats)


def _date_parses(value: str, date_format: str) -> bool:
    try:
        datetime.strptime(value, date_format)
    except ValueError:
        return False
    return True


# ------------------------------------------------------------------------ recognizers


@dataclass(frozen=True, slots=True)
class Recognizer:
    """One deterministic pattern detector.

    ``require_context`` demotes format-only patterns (passport numbers, dates of
    birth) to fire only when a context word confirms the meaning — the standard
    trick to keep generic alphanumerics from flooding the results.
    """

    name: str
    entity_type: EntityType
    pattern: re.Pattern[str]
    base_confidence: float
    validator: Callable[[str], bool] | None = None
    context_words: tuple[str, ...] = ()
    require_context: bool = False
    validated_confidence: float = 0.98
    context_boost: float = 0.2
    jurisdiction: str = "GLOBAL"


_CONTEXT_WINDOW = 48


def _has_context(text: str, start: int, end: int, words: tuple[str, ...]) -> bool:
    lo = max(0, start - _CONTEXT_WINDOW)
    window = text[lo : min(len(text), end + _CONTEXT_WINDOW)].lower()
    return any(w in window for w in words)


def run_recognizer(rec: Recognizer, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for m in rec.pattern.finditer(text):
        raw = m.group(0)
        confidence = rec.base_confidence
        validated = False
        if rec.validator is not None:
            if not rec.validator(raw):
                continue  # checksum fail: drop the candidate entirely
            confidence = rec.validated_confidence
            validated = True
        boosted = False
        if rec.context_words and _has_context(text, m.start(), m.end(), rec.context_words):
            confidence = min(0.99, confidence + rec.context_boost)
            boosted = True
        elif rec.require_context:
            continue  # format-only pattern with no confirming context: too risky
        findings.append(
            Finding(
                entity_type=rec.entity_type,
                start=m.start(),
                end=m.end(),
                text=raw,
                confidence=round(confidence, 4),
                recognizer=f"regex:{rec.name}",
                validated=validated,
                context_boosted=boosted,
            )
        )
    return findings


def match_ratio(rec: Recognizer, values: Iterable[str]) -> float:
    """Fraction of values that FULLY match this recognizer (validator included).

    This is the bridge to the structured pipeline: the same recognizers that scan
    prose also profile database columns, so both solutions share one PII definition.
    """
    total = 0
    hits = 0
    for v in values:
        if v is None or v == "":
            continue
        total += 1
        m = rec.pattern.fullmatch(v.strip())
        if m and (rec.validator is None or rec.validator(v.strip())):
            hits += 1
    return hits / total if total else 0.0


def default_recognizers() -> tuple[Recognizer, ...]:
    return (
        Recognizer(
            name="email",
            entity_type=EntityType.EMAIL_ADDRESS,
            pattern=re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
            base_confidence=0.9,
            context_words=("email", "e-mail", "mail", "メール"),
        ),
        Recognizer(
            name="credit_card",
            entity_type=EntityType.CREDIT_CARD,
            pattern=re.compile(r"(?<![\dA-Za-z])(?:\d[ -]?){12,18}\d(?![\dA-Za-z])"),
            base_confidence=0.4,
            validator=lambda v: luhn_valid(re.sub(r"[ -]", "", v)),
            context_words=(
                "card",
                "visa",
                "mastercard",
                "amex",
                "credit",
                "debit",
                "カード",
                "クレジット",
            ),
        ),
        Recognizer(
            name="iban",
            entity_type=EntityType.IBAN,
            pattern=re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b"),
            base_confidence=0.4,
            validator=iban_valid,
            context_words=("iban", "account", "transfer", "bank", "口座", "銀行", "振込"),
        ),
        Recognizer(
            name="sg_nric",
            entity_type=EntityType.SG_NRIC,
            pattern=re.compile(r"\b[STFGMstfgm]\d{7}[A-Za-z]\b"),
            base_confidence=0.3,
            validator=sg_nric_valid,
            context_words=("nric", "fin", "identity", "ic number", "uin"),
            jurisdiction="SG",
        ),
        Recognizer(
            name="hk_hkid",
            entity_type=EntityType.HK_HKID,
            pattern=re.compile(r"\b[A-Z]{1,2}\d{6}\(?[0-9A]\)?"),
            base_confidence=0.3,
            validator=hk_hkid_valid,
            context_words=("hkid", "identity card", "identity"),
            jurisdiction="HK",
        ),
        Recognizer(
            name="jp_my_number",
            entity_type=EntityType.JP_MY_NUMBER,
            # boundary lookarounds also reject 12-digit prefixes/suffixes of longer
            # grouped runs (e.g. the first 12 digits of a 16-digit card PAN, which
            # can coincidentally pass the MyNumber checksum)
            pattern=re.compile(r"(?<!\d)(?<!\d[- ])\d{4}[- ]?\d{4}[- ]?\d{4}(?![- ]?\d)"),
            base_confidence=0.2,
            validator=jp_my_number_valid,
            context_words=("my number", "mynumber", "マイナンバー", "個人番号"),
            jurisdiction="JP",
        ),
        Recognizer(
            name="au_tfn",
            entity_type=EntityType.AU_TFN,
            pattern=re.compile(r"(?<!\d)\d{3}[ -]?\d{3}[ -]?\d{3}(?!\d)"),
            base_confidence=0.2,
            validator=au_tfn_valid,
            context_words=("tfn", "tax file"),
            require_context=True,  # 9 digits + valid checksum is still too common alone
            validated_confidence=0.65,
            jurisdiction="AU",
        ),
        Recognizer(
            name="au_abn",
            entity_type=EntityType.AU_ABN,
            pattern=re.compile(r"(?<!\d)\d{2} ?\d{3} ?\d{3} ?\d{3}(?!\d)"),
            base_confidence=0.2,
            validator=au_abn_valid,
            context_words=("abn", "business number"),
            jurisdiction="AU",
        ),
        Recognizer(
            name="au_medicare",
            entity_type=EntityType.AU_MEDICARE,
            pattern=re.compile(r"(?<!\d)[2-6]\d{3} ?\d{5} ?\d(?: ?/? ?\d)?(?!\d)"),
            base_confidence=0.2,
            validator=au_medicare_valid,
            context_words=("medicare",),
            jurisdiction="AU",
        ),
        Recognizer(
            name="us_ssn",
            entity_type=EntityType.US_SSN,
            pattern=re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"),
            base_confidence=0.5,
            validator=us_ssn_valid,
            context_words=("ssn", "social security"),
            validated_confidence=0.8,
            jurisdiction="US",
        ),
        Recognizer(
            name="ip_address",
            entity_type=EntityType.IP_ADDRESS,
            pattern=re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
            base_confidence=0.3,
            validator=ipv4_valid,
            context_words=("ip", "address", "host", "server", "ipアドレス", "サーバー"),
            validated_confidence=0.75,
        ),
        Recognizer(
            name="phone_intl",
            entity_type=EntityType.PHONE_NUMBER,
            # a leading +country-code is strong evidence on its own
            pattern=re.compile(
                r"(?<![\d.\w])\+\d{1,3}(?:[ -]\d{1,4}){1,4}(?![\d.])"
                r"|(?<![\d.\w])\+\d{8,15}(?![\d.])"
            ),
            base_confidence=0.4,
            validator=phone_plausible,
            context_words=(
                "phone",
                "mobile",
                "tel",
                "call",
                "contact",
                "whatsapp",
                "hp",
                "電話",
                "携帯",
                "連絡先",
            ),
            validated_confidence=0.6,
        ),
        Recognizer(
            name="phone_local",
            entity_type=EntityType.PHONE_NUMBER,
            # separator-grouped local numbers look like invoice/PO numbers, so a
            # confirming context word is mandatory
            pattern=re.compile(
                r"(?<![\d.\w])(?:\(\d{2,4}\)[ -]?)?\d{2,4}[ -]\d{3,4}(?:[ -]\d{3,4})?(?![\d.])"
            ),
            base_confidence=0.3,
            validator=phone_plausible,
            context_words=(
                "phone",
                "mobile",
                "tel",
                "call",
                "contact",
                "whatsapp",
                "hp",
                "電話",
                "携帯",
                "連絡先",
            ),
            require_context=True,
            validated_confidence=0.5,
        ),
        Recognizer(
            name="passport",
            entity_type=EntityType.PASSPORT,
            pattern=re.compile(r"\b[A-Z]{1,2}\d{6,8}\b"),
            base_confidence=0.4,
            context_words=("passport", "パスポート", "旅券"),
            require_context=True,
        ),
        Recognizer(
            name="date_of_birth",
            entity_type=EntityType.DATE_OF_BIRTH,
            pattern=re.compile(
                r"\b(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}-\d{2}-\d{2}"
                r"|\d{1,2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]* \d{4})\b",
                re.IGNORECASE,
            ),
            base_confidence=0.45,
            validator=date_of_birth_valid,
            context_words=(
                "born",
                "birth",
                "dob",
                "d.o.b",
                "birthday",
                "生年月日",
                "誕生日",
                "出生",
            ),
            require_context=True,
            validated_confidence=0.75,
        ),
    )


SUPPORTED_JURISDICTIONS: frozenset[str] = frozenset({"SG", "HK", "JP", "AU", "US"})


def recognizers_for_jurisdictions(jurisdictions: Iterable[str]) -> tuple[Recognizer, ...]:
    """Select global patterns plus the explicitly configured jurisdiction packs."""
    selected = frozenset(str(value).strip().upper() for value in jurisdictions)
    unknown = selected - SUPPORTED_JURISDICTIONS
    if unknown:
        raise ValueError(f"unsupported PII jurisdictions: {sorted(unknown)}")
    if not selected:
        raise ValueError("at least one PII jurisdiction must be selected")
    return tuple(
        recognizer
        for recognizer in default_recognizers()
        if recognizer.jurisdiction == "GLOBAL" or recognizer.jurisdiction in selected
    )
