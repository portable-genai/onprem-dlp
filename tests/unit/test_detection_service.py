from onprem_dlp.domain.detection_service import MODEL_CONFIDENCE_CAP, TextDetectionService
from onprem_dlp.domain.models import EntityType, Finding


def test_deterministic_same_input_same_output():
    svc = TextDetectionService()
    text = "NRIC S1234567D, card 4111 1111 1111 1111, mail a@b.co"
    assert svc.scan(text) == svc.scan(text)


def test_overlap_prefers_validated_then_longer():
    # the 16-digit card contains a 12-digit run that happens to pass the
    # MyNumber checksum; the longer validated credit card must win
    svc = TextDetectionService()
    scan = svc.scan("card: 4111 1111 1111 1111")
    types = [f.entity_type for f in scan.findings]
    assert types == [EntityType.CREDIT_CARD]


def test_model_findings_are_capped_and_bounds_checked():
    svc = TextDetectionService()
    text = "Alice Tan lives here."
    good = Finding(EntityType.PERSON_NAME, 0, 9, "Alice Tan", 0.99, "llm:test")
    out_of_bounds = Finding(EntityType.PERSON_NAME, 15, 99, "x", 0.99, "llm:test")
    scan = svc.scan(text, extra_findings=[good, out_of_bounds], extra_engines=["llm:test"])
    assert len(scan.findings) == 1
    assert scan.findings[0].confidence <= MODEL_CONFIDENCE_CAP
    assert scan.engines == ("regex", "llm:test")


def test_min_confidence_floor_drops_weak_findings():
    text = "a@b.co and S1234567D"  # bare email scores 0.9; validated NRIC 0.98
    relaxed = TextDetectionService(min_confidence=0.35)
    strict = TextDetectionService(min_confidence=0.95)
    assert {f.entity_type for f in relaxed.scan(text).findings} == {
        EntityType.EMAIL_ADDRESS,
        EntityType.SG_NRIC,
    }
    assert [f.entity_type for f in strict.scan(text).findings] == [EntityType.SG_NRIC]
