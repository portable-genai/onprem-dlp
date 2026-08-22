"""Prompts and strict-JSON parsing shared by both Gemma transports.

Small models drift; these prompts pin the output to one JSON object, and the parsers
refuse anything they cannot map back onto the source text — a hallucinated entity that
does not literally appear in the input is dropped, never guessed at.
"""

from __future__ import annotations

import json

from ...domain.models import AdjudicationVerdict, EntityType, Finding

#: Entity types Gemma may report for free text (things regexes can't see).
NER_TYPES = ("PERSON_NAME", "ADDRESS", "ORGANIZATION", "DATE_OF_BIRTH")

NER_PROMPT = """You are a data-loss-prevention annotator. Find personal data in the text.
Return ONLY a JSON object of the form:
{{"entities": [{{"type": "<one of {types}>", "text": "<exact substring copied from the text>"}}]}}
Rules:
- "text" MUST be copied verbatim from the input, character for character.
- Only report the listed types. Report nothing else. If none, return {{"entities": []}}.

Text:
{text}
"""

COLUMN_PROMPT = """You are a data-governance reviewer. A deterministic profiler analysed one
database column and could not decide whether it contains personal data (PII).
Column profile: {summary}
Example values are NOT provided on purpose; judge from the name and statistics only.
Return ONLY a JSON object: {{"is_pii": true|false, "confidence": <0.0-1.0>, \
"rationale": "<one sentence>"}}
"""


def build_ner_prompt(text: str) -> str:
    return NER_PROMPT.format(types=", ".join(NER_TYPES), text=text)


def build_column_prompt(summary: str) -> str:
    return COLUMN_PROMPT.format(summary=summary)


def extract_json_object(raw: str) -> dict | None:
    """Pull the first balanced ``{...}`` out of a model response and parse it.

    Brace counting is string-aware: braces inside a JSON string literal (e.g. a
    ``"text": "a}b"`` span) do not change depth, and ``\\"`` escapes are respected —
    otherwise a legitimate object with a brace in its content would be discarded.
    """
    start = raw.find("{")
    if start < 0:
        return None
    depth = 0
    in_string = False
    escaped = False
    for i in range(start, len(raw)):
        ch = raw[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    parsed = json.loads(raw[start : i + 1])
                except json.JSONDecodeError:
                    return None
                return parsed if isinstance(parsed, dict) else None
    return None


def _coerce_bool(value: object) -> bool | None:
    """Strict truthiness for model output. Returns None on anything unrecognized so
    the caller drops the verdict rather than inverting it — ``bool("false")`` is
    ``True`` in Python, so a naive cast would flip a 'not PII' verdict to 'PII'."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        token = value.strip().lower()
        if token in ("true", "yes", "y", "1"):
            return True
        if token in ("false", "no", "n", "0"):
            return False
    return None


def parse_ner_response(raw: str, source_text: str, engine: str) -> list[Finding]:
    """Map reported substrings back to real offsets; drop anything unverifiable."""
    obj = extract_json_object(raw)
    if not obj:
        return []
    findings: list[Finding] = []
    seen_spans: set[tuple[int, int]] = set()
    for item in obj.get("entities", []):
        if not isinstance(item, dict):
            continue
        etype_raw = str(item.get("type", ""))
        snippet = str(item.get("text", ""))
        if etype_raw not in NER_TYPES or not snippet.strip():
            continue
        etype = EntityType(etype_raw)
        pos = 0
        while True:
            start = source_text.find(snippet, pos)
            if start < 0:
                break
            span = (start, start + len(snippet))
            if span not in seen_spans:
                seen_spans.add(span)
                findings.append(
                    Finding(
                        entity_type=etype,
                        start=span[0],
                        end=span[1],
                        text=snippet,
                        confidence=0.7,  # advisory; detection service caps anyway
                        recognizer=engine,
                    )
                )
            pos = start + max(1, len(snippet))
    return findings


def parse_column_response(raw: str) -> AdjudicationVerdict | None:
    obj = extract_json_object(raw)
    if not obj or "is_pii" not in obj:
        return None
    is_pii = _coerce_bool(obj["is_pii"])
    if is_pii is None:
        return None  # unparseable verdict: drop it, never guess a direction
    try:
        confidence = float(obj.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5
    return AdjudicationVerdict(
        is_pii=is_pii,
        confidence=max(0.0, min(1.0, confidence)),
        rationale=str(obj.get("rationale", ""))[:500],
    )
