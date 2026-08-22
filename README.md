# onprem-dlp: on-prem DLP gate before cloud egress

Documentation authority is declared in [`docs/doc-authority.md`](docs/doc-authority.md).

**Rsk6** in the GRC GenAI catalog. An open-source (Apache-2.0) data-leak-prevention
tool that runs **entirely on-prem, CPU-only**, and scrubs data **before** it is sent to
any cloud LLM or API. No byte reaches the cloud unless this gate says so.

Two solutions behind one deterministic core:

| Solution | What it does |
|---|---|
| **Unstructured** (text + images) | Detects PII in free text and images (OCR), then redacts (tag/mask/hash/remove) or black-boxes pixel regions; issues an ALLOW / REDACT / BLOCK egress decision. |
| **Structured** (database columns) | Profiles CSV / SQLite / PostgreSQL / MySQL / BigQuery columns (name, value patterns, **cardinality**, type, null ratio) and classifies each as `PII_DIRECT` / `PII_QUASI` / `SENSITIVE` / `NON_PII` with explainable, weighted signals. |

The detection heart is **pure stdlib**: regex candidates hardened by real checksum
validators (SG NRIC/FIN, HK HKID, JP MyNumber, AU TFN/ABN/Medicare, credit-card Luhn,
IBAN mod-97) with context-word confidence boosting. A small **Google Gemma** model
(via [Ollama](https://ollama.com) or llama.cpp, ~815 MB quantised, CPU-friendly) and
**Microsoft Presidio** NER are *optional adapters* that raise recall for names and
addresses. They contribute candidates and advisory verdicts, but the deterministic
policy engine always makes the decision.

## Install

```bash
pip install .                 # zero third-party deps: core + CLI + CSV/SQLite + Ollama-Gemma
pip install '.[yaml]'         # YAML settings file (JSON config works without)
pip install '.[api]'          # FastAPI egress endpoint
pip install '.[ner]'          # Presidio NER (then: python -m spacy download en_core_web_lg)
pip install '.[ocr]'          # Tesseract OCR + Pillow (host: apt-get install tesseract-ocr)
pip install '.[llamacpp]'     # in-process Gemma GGUF (fully air-gapped)
pip install '.[postgres]'     # PostgreSQL column sampler
pip install '.[mysql]'        # MySQL column sampler
pip install '.[bigquery]'     # BigQuery column sampler (uses ADC/workload identity)
```

Optional Gemma second pass (CPU): `ollama pull gemma3:1b`, then run with
`--profile gemma-ollama`.

## Quick start

```bash
# 1. unstructured text: scan, redact, decide
onprem-dlp scan-text   --file demo/sample_support_email.txt
onprem-dlp redact-text --file demo/sample_support_email.txt
onprem-dlp decide      --file demo/sample_support_email.txt   # exit 0=ALLOW 3=REDACT 4=BLOCK

# 2. images: OCR + pixel blackout (needs [ocr])
onprem-dlp scan-image   statement.png
onprem-dlp redact-image statement.png --out statement.clean.png

# 3. structured columns: PII vs non-PII from name+pattern+cardinality signals
onprem-dlp classify-columns demo/customers.csv
onprem-dlp classify-columns demo/customers.db
onprem-dlp classify-columns \
  "postgresql://ro_user@dbhost/corebank?sslmode=verify-full&sslrootcert=/etc/ssl/certs/bank-ca.pem" \
  --fail-on-pii  # CI gate
ONPREM_DLP_MYSQL_PASSWORD=... onprem-dlp classify-columns \
  "mysql://ro_user@dbhost/corebank"
onprem-dlp classify-columns "bigquery://REPLACE_WITH_GCP_PROJECT_ID/customer_data"

# REST gate in front of your cloud egress (needs [api]).
# Binds 127.0.0.1 by default: the surface authenticates nobody, so exposing it off
# loopback needs ONPREM_DLP_ALLOW_UNAUTHENTICATED_EXPOSURE=1 and a network control.
python -m onprem_dlp.api.serve
curl -s localhost:8484/v1/egress/decide -H 'content-type: application/json' \
     -d '{"text": "customer NRIC S1234567D asked for a refund"}'
```

Typical `decide` output for the demo email:

```
egress decision for demo/sample_support_email.txt: BLOCK
  [HIGH  ] SG_NRIC detected (confidence 0.98): span [259:268] via regex:sg_nric; checksum-validated
  [HIGH  ] CREDIT_CARD detected (confidence 0.98): ...
  ...
  → BLOCK escalates to human review; nothing was sent.
```

## How decisions are made (and why it is auditable)

1. **Recognizers** propose spans; checksum validators kill invalid candidates
   (a Luhn-failing "card number" never becomes a finding).
2. Optional **model engines** (Presidio, Gemma) add candidates for entities regex
   cannot see; their confidence is capped below checksum certainty and hallucinated
   spans that don't exist verbatim in the text are dropped.
3. The **egress policy** (config, not code) maps entities to BLOCK / REDACT lists with
   a confidence floor. BLOCK escalates to a human; the tool never auto-releases.
4. For columns, three **explainable signal families** (name synonyms, shared value
   patterns, cardinality/shape) sum to a score; ambiguous scores go to the Gemma
   adjudicator whose verdict nudges the score by a *bounded* amount, or the column is
   flagged `needs_review`. Every classification carries its signal breakdown.

Same inputs → same outputs, every time. An auditor can re-run any decision.

## Profiles

| Profile | Engines | Needs |
|---|---|---|
| `local` (default) | regex + checksums only | Python. Nothing else. |
| `gemma-ollama` | + Gemma NER & column adjudication | local Ollama, `gemma3:1b` |
| `gemma-llamacpp` | same, in-process GGUF | `[llamacpp]` + model file |
| `full` | Presidio NER + Gemma adjudication | `[ner]` + Ollama |

Select with `profile:` in [config/settings.yaml](config/settings.yaml), the
`ONPREM_DLP_PROFILE` env var, or `--profile`.

## Repository map

- [SPEC.md](SPEC.md): behaviour spec for both solutions
- [ARCHITECTURE.md](ARCHITECTURE.md): ports-and-adapters layout, port table
- [DEMO.md](DEMO.md): scripted walkthrough
- [COMPLIANCE.md](COMPLIANCE.md): control mapping (PDPA/GDPR/APPs lens)
- [docs/runbook.md](docs/runbook.md): operate, tune, respond
- [docs/onprem-migration.md](docs/onprem-migration.md): deployment postures; this system is on-prem-native
- [deploy/helm/onprem-dlp](deploy/helm/onprem-dlp): secure local-profile Kubernetes package
- [eval/run_eval.py](eval/run_eval.py): offline English/Japanese quality gate plus column accuracy

## Development

```bash
make setup   # venv + dev deps
make test    # pytest: unit + contract + integration (offline, no models)
make eval    # English + Japanese golden-set gate
make demo    # end-to-end demo on synthetic data
make gate    # exact Ruff + tests + eval; same command CI runs
make dependency-audit  # strict networked check over the pinned runtime and dev locks
```

All demo/test identifiers are synthetic but checksum-valid; no real personal data
exists anywhere in this repository.
