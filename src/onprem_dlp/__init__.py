"""On-prem data-leak-prevention gate: scrub PII before any byte leaves for the cloud.

Two capabilities behind one deterministic core:

* unstructured — detect and redact PII in free text and images (OCR + box blackout);
* structured — classify database/CSV columns as PII / quasi-identifier / sensitive /
  non-PII from profiling signals (name, value patterns, cardinality).

The domain core is pure stdlib and fully offline. NER (Presidio), OCR (Tesseract) and
a small CPU-friendly Google Gemma model (via Ollama or llama.cpp) are optional adapters
that raise recall; they never make the egress decision.
"""

__version__ = "0.0.1"
