"""Image pipeline logic with a fake OCR engine — no Tesseract needed."""

from onprem_dlp.domain.models import OcrResult, OcrWord
from onprem_dlp.domain.orchestrator_service import DlpOrchestrator


class FakeOcr:
    def __init__(self, words):
        self._words = words

    def extract(self, image_path):  # noqa: ARG002
        return OcrResult(words=tuple(self._words))


def _word(text, i):
    return OcrWord(text=text, left=i * 100, top=50, width=90, height=20, confidence=95.0)


def test_findings_map_back_to_pixel_boxes():
    words = [_word(w, i) for i, w in enumerate(["NRIC", "S1234567D", "on", "file"])]
    orch = DlpOrchestrator()
    result = orch.scan_image("fake.png", FakeOcr(words))
    assert [f.entity_type.value for f in result.scan.findings] == ["SG_NRIC"]
    assert result.boxes == ((100, 50, 90, 20),) or [
        (b.left, b.top, b.width, b.height) for b in result.boxes
    ] == [(100, 50, 90, 20)]


def test_multi_word_finding_covers_all_words():
    # credit card split across four OCR tokens -> four boxes
    tokens = ["Card:", "4111", "1111", "1111", "1111", "thanks"]
    words = [_word(w, i) for i, w in enumerate(tokens)]
    orch = DlpOrchestrator()
    result = orch.scan_image("fake.png", FakeOcr(words))
    assert [f.entity_type.value for f in result.scan.findings] == ["CREDIT_CARD"]
    assert len(result.boxes) == 4
    assert all(b.left in (100, 200, 300, 400) for b in result.boxes)


def test_clean_image_yields_no_boxes():
    words = [_word(w, i) for i, w in enumerate(["hello", "world"])]
    result = DlpOrchestrator().scan_image("fake.png", FakeOcr(words))
    assert result.scan.findings == ()
    assert result.boxes == ()
