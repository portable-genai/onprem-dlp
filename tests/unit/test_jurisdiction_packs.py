"""Runtime uses explicit, validated jurisdiction recognizer packs."""

import pytest

from onprem_dlp.config import Container


def test_non_selected_pack_does_not_run_but_global_patterns_do() -> None:
    settings = {
        "profile": "local",
        "audit_log": None,
        "detection": {"min_confidence": 0.35, "jurisdictions": ["SG"]},
        "redaction": {"default_strategy": "tag", "hash_salt": "fictional", "strategies": {}},
        "policy": {
            "min_confidence": 0.5,
            "block_at_or_above": 1,
            "block_entities": ["SG_NRIC"],
            "redact_entities": ["EMAIL_ADDRESS"],
        },
        "classifier": {"pii_threshold": 0.6, "review_threshold": 0.3, "sample_limit": 10},
        "profiles": {
            "local": {
                "ner": {"class": "onprem_dlp.adapters.local:NullNer"},
                "adjudicator": {"class": "onprem_dlp.adapters.local:NullAdjudicator"},
            }
        },
    }
    result = (
        Container(settings, profile="local")
        .orchestrator()
        .scan_text("NRIC S1234567D and HKID A123456(3), email a@example.test")
    )
    types = {finding.entity_type.value for finding in result.findings}
    assert "SG_NRIC" in types
    assert "HK_HKID" not in types
    assert "EMAIL_ADDRESS" in types


def test_unknown_or_empty_pack_refuses() -> None:
    from onprem_dlp.domain.recognizers import recognizers_for_jurisdictions

    with pytest.raises(ValueError):
        recognizers_for_jurisdictions([])
    with pytest.raises(ValueError):
        recognizers_for_jurisdictions(["XX"])
