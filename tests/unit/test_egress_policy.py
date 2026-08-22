from dataclasses import replace

from onprem_dlp.domain.detection_service import TextDetectionService
from onprem_dlp.domain.egress_policy_service import EgressPolicyService
from onprem_dlp.domain.models import EgressAction, EgressPolicy, Severity

svc = EgressPolicyService()
detect = TextDetectionService()


def _decide(text):
    return svc.decide(detect.scan(text, source_id="t"))


def test_clean_text_allows():
    d = _decide("The quarterly revenue grew nicely across all regions.")
    assert d.action is EgressAction.ALLOW
    assert not d.escalates


def test_redactable_entity_forces_redact():
    d = _decide("Contact jane@example.com for the draft.")
    assert d.action is EgressAction.REDACT
    assert any(r.severity is Severity.MEDIUM for r in d.reasons)


def test_block_entity_forces_block_and_escalates():
    d = _decide("Her NRIC is S1234567D.")
    assert d.action is EgressAction.BLOCK
    assert d.escalates
    assert any(r.severity is Severity.HIGH for r in d.reasons)


def test_low_confidence_findings_do_not_trigger_gate():
    # bare phone-shaped number scores below the 0.5 policy floor
    d = _decide("Ref +65 9123 4567")
    assert d.action in (EgressAction.ALLOW, EgressAction.REDACT)


def test_block_entity_survives_a_raised_confidence_floor():
    # PASSPORT is a block entity whose confidence ceiling is ~0.6 (format + context,
    # no checksum). Raising the policy floor above it must NOT let it slip to ALLOW.
    text = "Please courier my passport E1234567 with the visa pack."
    scan = detect.scan(text, source_id="t")
    assert any(f.entity_type.value == "PASSPORT" for f in scan.findings)
    strict = EgressPolicyService(policy=replace(EgressPolicy.default(), min_confidence=0.7))
    decision = strict.decide(scan)
    assert decision.action is EgressAction.BLOCK
    assert decision.escalates


def test_raised_floor_still_suppresses_weak_redact_findings():
    # the floor knob keeps tuning redaction noise: a below-floor redact-tier finding
    # is dropped, while nothing block-listed is present
    text = "meeting notes for 12/03/2026, nothing sensitive"
    strict = EgressPolicyService(policy=replace(EgressPolicy.default(), min_confidence=0.7))
    assert strict.decide(detect.scan(text, source_id="t")).action is EgressAction.ALLOW
