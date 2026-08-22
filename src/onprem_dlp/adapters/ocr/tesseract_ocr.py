"""Tesseract OCR adapter: word-level text + boxes, all local CPU.

Host packages: ``apt-get install tesseract-ocr`` (add ``tesseract-ocr-jpn`` etc. for
CJK) plus ``pip install 'onprem-dlp[ocr]'``.
"""

from __future__ import annotations

from ...adapter_settings import AdapterSettings
from ...domain.models import OcrResult, OcrWord


class TesseractOcr:
    def __init__(self, settings: AdapterSettings) -> None:
        self.lang = str(settings.get("lang", "eng"))
        self.min_word_confidence = float(settings.get("min_word_confidence", 30.0))

    def extract(self, image_path: str) -> OcrResult:
        import pytesseract  # lazy: optional dependency
        from PIL import Image

        with Image.open(image_path) as img:
            data = pytesseract.image_to_data(
                img, lang=self.lang, output_type=pytesseract.Output.DICT
            )
        words: list[OcrWord] = []
        for text, left, top, width, height, conf in zip(
            data["text"],
            data["left"],
            data["top"],
            data["width"],
            data["height"],
            data["conf"],
            strict=True,
        ):
            token = (text or "").strip()
            confidence = float(conf)
            if not token or confidence < self.min_word_confidence:
                continue
            words.append(
                OcrWord(
                    text=token,
                    left=int(left),
                    top=int(top),
                    width=int(width),
                    height=int(height),
                    confidence=confidence,
                )
            )
        return OcrResult(words=tuple(words))
