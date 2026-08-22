# ARCHITECTURE: ports-and-adapters, domain-pure core

Documentation authority is declared in [`docs/doc-authority.md`](docs/doc-authority.md).

```
src/onprem_dlp/
  domain/                     # PURE stdlib. No SDKs, no I/O, no clock, no randomness.
    models.py                 #   frozen dataclasses: Finding, ScanResult, ColumnProfile,
                              #   ColumnClassification, EgressPolicy/Decision, ...
    recognizers.py            #   regex + checksum validators (NRIC/HKID/MyNumber/TFN/ABN/
                              #   Medicare/Luhn/IBAN/mod-97) + context boosting
    detection_service.py      #   scan text; cap+sanitise model candidates; resolve overlaps
    redaction_service.py      #   tag/mask/hash/remove, right-to-left, salted stable hashes
    column_profile_service.py #   cardinality/null/type/pattern statistics from samples
    column_classifier_service.py  # weighted explainable signals -> category + action
    egress_policy_service.py  #   ALLOW / REDACT / BLOCK; BLOCK escalates to a human
    orchestrator_service.py   #   composes services + ports; the only port consumer
    services.py               #   aggregator re-exports
  ports/__init__.py           # @runtime_checkable typing.Protocols (the hexagon edge)
  adapters/
    local/                    # stdlib-only working stack: CSV/SQLite/inline samplers,
                              # JSONL audit sink, Null NER/adjudicator. Default + CI.
    gemma/                    # Gemma on CPU: Ollama transport (stdlib urllib) and
                              # llama.cpp transport (lazy import); shared prompts+parsers
    ner/                      # Presidio NER (lazy import)
    ocr/                      # Tesseract OCR + Pillow box-blackout redactor (lazy)
    db/                       # PostgreSQL/MySQL/BigQuery read-only samplers (lazy SDKs)
  config.py                   # Settings loader (YAML/JSON) + Container (DI): profile ->
                              # dotted-path class bindings with kwargs
  cli/main.py                 # argparse; exit codes 0/3/4 as a pipeline gate
  api/app.py                  # optional FastAPI egress endpoint (lazy import)
```

## Ports

| Port | Purpose | Shipped adapters |
|---|---|---|
| `NerAnalyzer` | model-based findings regexes cannot see | `NullNer`, `PresidioNer`, `OllamaGemmaClient`, `LlamaCppGemmaClient` |
| `LlmAdjudicator` | advisory verdict on ambiguous columns | `NullAdjudicator`, `OllamaGemmaClient`, `LlamaCppGemmaClient` |
| `OcrEngine` | word-level text + pixel boxes from images | `TesseractOcr` |
| `ImageRedactor` | opaque boxes + metadata strip on a copy | `PillowImageRedactor` |
| `ColumnSampler` | bounded read-only column samples | `CsvSampler`, `SqliteSampler`, `InlineSampler`, `PostgresSampler`, `MySqlSampler`, `BigQuerySampler` |
| `AuditSink` | append-only decision trail | `JsonlAuditSink` |

The contract test (`tests/contract/test_ports.py`) asserts every shipped adapter
satisfies its Protocol; `ports/__init__.py.__all__` is the source of truth for the
port list; docs enumerate by name, never by count.

## Invariants that keep the system trustworthy

1. **The domain never imports an SDK.** Model/OCR/DB code lives behind ports; heavy
   imports are lazy inside adapter methods, so `import onprem_dlp` works on a bare
   Python install.
2. **Determinism.** Same inputs → same findings, same redactions, same categories,
   same egress action. No clock reads or randomness in the domain; the hash strategy
   takes its salt as configuration.
3. **Models advise, the engine decides.** Model findings are confidence-capped (0.85)
   below checksum certainty (0.98); Gemma column verdicts move the score at most
   ±0.15 and only inside the ambiguity band; unresolved ambiguity escalates to a
   human (`needs_review`), and BLOCK decisions always escalate.
4. **Fail-soft models, fail-closed policy.** Ollama down / bad JSON / hallucinated
   span → the deterministic result stands. A block-listed validated finding → BLOCK,
   regardless of what any model says.
5. **Audit without leakage.** Audit events carry entity *counts*, spans and actions;
   never the raw matched values.
6. **Remote samplers stay optional and read-only.** MySQL starts a read-only
   transaction; BigQuery uses metadata plus bounded `SELECT` queries. Both validate
   server-returned identifiers, sort/order results for replay, and import their SDK
   only on first I/O, so the local gate never installs or imports a cloud dependency.
   MySQL verifies TLS certificates and host identity by default, accepts only three
   typed TLS DSN options, orders full values by SHA-256/byte-length/hex (not a
   `max_sort_length` prefix), and rolls back/closes its owned connection deterministically.

## Data flow (egress gate deployment)

```
app payload ──► POST /v1/egress/decide ──► scan (regex ▸ +NER ▸ +Gemma) ──► policy
                                                                        ├─ ALLOW  ─► caller sends original
                                                                        ├─ REDACT ─► caller sends /v1/redact/text output
                                                                        └─ BLOCK  ─► human release queue (nothing sent)
```

The gate is stateless; scale it horizontally behind any LB. State (audit trail) is an
append-only file per instance, shippable to the SIEM.
