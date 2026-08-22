"""Adapters, grouped by dependency footprint.

* ``local``    — stdlib only; the default profile and the CI stack.
* ``gemma``    — small Google Gemma model on CPU via Ollama (stdlib HTTP) or llama.cpp.
* ``ner``      — Microsoft Presidio / spaCy NER (optional extra ``[ner]``).
* ``ocr``      — Tesseract OCR + Pillow (optional extra ``[ocr]``).
* ``db``       — network database samplers (optional extra ``[postgres]``).

Heavy imports are lazy (inside methods) so importing the package never drags an SDK.
"""
