"""Gemma output hardening: hallucinations and malformed JSON must be harmless."""

from onprem_dlp.adapters.gemma.prompts import (
    extract_json_object,
    parse_column_response,
    parse_ner_response,
)

TEXT = "Please ask Alice Tan about the Osaka shipment."


def test_verbatim_entity_is_located():
    raw = '{"entities": [{"type": "PERSON_NAME", "text": "Alice Tan"}]}'
    findings = parse_ner_response(raw, TEXT, "llm:test")
    assert len(findings) == 1
    assert findings[0].start == TEXT.index("Alice Tan")


def test_hallucinated_entity_is_dropped():
    raw = '{"entities": [{"type": "PERSON_NAME", "text": "Bob Widodo"}]}'
    assert parse_ner_response(raw, TEXT, "llm:test") == []


def test_unknown_type_and_junk_are_dropped():
    raw = (
        '{"entities": [{"type": "CREDIT_CARD", "text": "Alice Tan"}, '
        '"junk", {"type": "PERSON_NAME"}]}'
    )
    assert parse_ner_response(raw, TEXT, "llm:test") == []


def test_prose_wrapped_json_still_parses():
    raw = (
        "Sure! Here is the result:\n"
        '{"entities": [{"type": "PERSON_NAME", "text": "Alice Tan"}]} hope that helps'
    )
    assert len(parse_ner_response(raw, TEXT, "llm:test")) == 1


def test_garbage_returns_empty():
    assert parse_ner_response("no json here", TEXT, "llm:test") == []
    assert parse_column_response("not json") is None


def test_column_verdict_parses_and_clamps():
    v = parse_column_response(
        '{"is_pii": true, "confidence": 7, "rationale": "id joins to person"}'
    )
    assert v.is_pii and v.confidence == 1.0
    v2 = parse_column_response('{"is_pii": false, "confidence": "bad"}')
    assert v2 is not None and not v2.is_pii and v2.confidence == 0.5


def test_stringified_boolean_is_not_inverted():
    # small models emit "is_pii":"false"; bool("false") is True, which would FLIP
    # a not-PII verdict into PII. The string must be read as its literal truth value.
    assert parse_column_response('{"is_pii": "false", "confidence": 0.9}').is_pii is False
    assert parse_column_response('{"is_pii": "true", "confidence": 0.9}').is_pii is True
    assert parse_column_response('{"is_pii": "yes"}').is_pii is True
    # an unrecognised verdict is dropped, never guessed
    assert parse_column_response('{"is_pii": "maybe"}') is None


def test_brace_inside_string_value_still_parses():
    # a PERSON_NAME/ADDRESS span containing a brace must not discard the whole object
    obj = extract_json_object('{"type": "PERSON_NAME", "text": "a}b"}')
    assert obj == {"type": "PERSON_NAME", "text": "a}b"}
    # and an escaped quote inside the string does not end it early
    assert extract_json_object(r'{"text": "he said \"hi\" {x}"}') == {"text": 'he said "hi" {x}'}


def test_ner_span_with_brace_is_recovered():
    text = "Unit A} on file for the account."
    raw = '{"entities": [{"type": "ADDRESS", "text": "Unit A}"}]}'
    findings = parse_ner_response(raw, text, "llm:test")
    assert len(findings) == 1 and findings[0].text == "Unit A}"
