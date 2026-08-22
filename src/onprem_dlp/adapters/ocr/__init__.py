"""OCR + image redaction adapters (optional extra ``[ocr]``)."""

from .pillow_redactor import PillowImageRedactor
from .tesseract_ocr import TesseractOcr

__all__ = ["PillowImageRedactor", "TesseractOcr"]
