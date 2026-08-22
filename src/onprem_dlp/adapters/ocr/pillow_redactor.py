"""Pillow image redactor: paints opaque boxes over PII pixel regions.

Also strips all image metadata (EXIF GPS, camera serials, XMP) by re-encoding pixels
into a fresh image — metadata is its own leak channel, not just the visible text.
"""

from __future__ import annotations

from collections.abc import Sequence

from ...adapter_settings import AdapterSettings
from ...domain.models import PixelBox


class PillowImageRedactor:
    def __init__(self, settings: AdapterSettings) -> None:
        self.fill = str(settings.get("fill", "black"))
        self.padding = int(settings.get("padding", 2))

    def redact(self, image_path: str, boxes: Sequence[PixelBox], output_path: str) -> str:
        from PIL import Image, ImageDraw  # lazy: optional dependency

        with Image.open(image_path) as img:
            clean = Image.new(img.mode, img.size)
            clean.putdata(list(img.getdata()))  # pixels only: EXIF/XMP left behind
            draw = ImageDraw.Draw(clean)
            pad = self.padding
            for b in boxes:
                draw.rectangle(
                    (b.left - pad, b.top - pad, b.left + b.width + pad, b.top + b.height + pad),
                    fill=self.fill,
                )
            clean.save(output_path)
        return output_path
