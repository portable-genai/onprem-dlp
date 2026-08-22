from onprem_dlp.domain.detection_service import TextDetectionService
from onprem_dlp.domain.models import EntityType, RedactionStrategy
from onprem_dlp.domain.redaction_service import RedactionService

TEXT = "Mail jane@example.com, NRIC S1234567D, card 4111 1111 1111 1111."


def _scan(text=TEXT):
    return TextDetectionService().scan(text)


def test_tag_strategy_replaces_all_findings():
    redacted = RedactionService().redact(TEXT, _scan())
    assert "jane@example.com" not in redacted.text
    assert "S1234567D" not in redacted.text
    assert "<EMAIL_ADDRESS>" in redacted.text
    assert "<SG_NRIC>" in redacted.text
    assert len(redacted.applied) == len(_scan().findings)


def test_mask_keeps_last_four():
    svc = RedactionService(strategies={EntityType.CREDIT_CARD: RedactionStrategy.MASK})
    redacted = svc.redact(TEXT, _scan())
    assert "1111." in redacted.text  # tail survives
    assert "4111 1111" not in redacted.text  # head is starred


def test_hash_is_salted_and_stable():
    a = RedactionService(default_strategy=RedactionStrategy.HASH, hash_salt="s1")
    b = RedactionService(default_strategy=RedactionStrategy.HASH, hash_salt="s2")
    assert a.redact(TEXT, _scan()).text == a.redact(TEXT, _scan()).text
    assert a.redact(TEXT, _scan()).text != b.redact(TEXT, _scan()).text


def test_remove_strategy_and_offset_integrity():
    svc = RedactionService(default_strategy=RedactionStrategy.REMOVE)
    redacted = svc.redact(TEXT, _scan())
    assert "jane@example.com" not in redacted.text
    assert redacted.text.startswith("Mail ")
    # replacements applied right-to-left: surrounding punctuation intact
    assert redacted.text.endswith(".")


def test_rescan_of_tagged_output_is_clean():
    redacted = RedactionService().redact(TEXT, _scan())
    assert TextDetectionService().scan(redacted.text).findings == ()
