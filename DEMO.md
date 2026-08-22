# DEMO: five minutes, fully offline

Everything below runs on the `local` profile: no models, no network, synthetic data
only (all identifiers are fake but checksum-valid).

```bash
make setup          # or: uv venv .venv && uv pip install -p .venv -e '.[dev]'
```

## 1. Unstructured: the support email that must never reach a cloud LLM

```bash
.venv/bin/onprem-dlp scan-text --file demo/sample_support_email.txt
```

13 entity types fire: NRIC, credit card, IBAN, MyNumber, HKID, TFN, ABN, Medicare,
passport, date of birth, emails, phones, an IP; each with span, confidence,
recognizer provenance and a ✓ when a checksum validated it.

```bash
.venv/bin/onprem-dlp decide --file demo/sample_support_email.txt ; echo "exit=$?"
```

`BLOCK` (exit 4): block-listed identifiers present; the reasons list every one.

```bash
.venv/bin/onprem-dlp redact-text --file demo/sample_support_email.txt
```

Same email with `<SG_NRIC>`, masked card (`*** 1111`), tags for the rest. The
version that IS safe to send. Re-scan it: zero findings.

## 2. Images (optional `[ocr]` extra + tesseract on the host)

```bash
.venv/bin/onprem-dlp scan-image   card-scan.png
.venv/bin/onprem-dlp redact-image card-scan.png --out card-scan.clean.png
```

OCR words → same detection pipeline → pixel boxes → blacked-out copy with EXIF/GPS
metadata stripped.

## 3. Structured: which columns are PII?

```bash
.venv/bin/onprem-dlp classify-columns demo/customers.csv
```

Expected classification of the 14-column synthetic bank table:

| column | category | why (top signals) |
|---|---|---|
| email, phone, nric, full_name | PII_DIRECT | name synonym + 100% pattern match (+ near-unique) |
| date_of_birth | PII_QUASI | birth-name + date pattern |
| gender, nationality, postal_code | PII_QUASI | demographic name (+ low/high cardinality shape) |
| customer_id | PII_QUASI ⚠ needs review | id-name + unique values, no known pattern |
| salary_sgd, health_condition | SENSITIVE | special-category names; blocked pending DPO |
| account_balance, product_code, branch_code | NON_PII | plain measure / category codes |

The ⚠ rows are the ambiguity band: wire up Gemma (`--profile gemma-ollama` after
`ollama pull gemma3:1b`) and the adjudicator confirms or rejects them with a one-line
rationale recorded on the classification.

```bash
.venv/bin/onprem-dlp classify-columns demo/customers.db          # same verdicts via SQLite
.venv/bin/onprem-dlp classify-columns demo/customers.csv --fail-on-pii ; echo "exit=$?"   # CI gate: exit 4
```

Optional read-only adapters use the same output:

```bash
# Values are placeholders; these commands are not part of the offline demo gate.
ONPREM_DLP_MYSQL_PASSWORD=REPLACE_WITH_SECRET \
  .venv/bin/onprem-dlp classify-columns \
  "mysql://REPLACE_WITH_USER@REPLACE_WITH_HOST/REPLACE_WITH_DATABASE"
.venv/bin/onprem-dlp classify-columns \
  "bigquery://REPLACE_WITH_GCP_PROJECT_ID/REPLACE_WITH_BIGQUERY_DATASET"
```

## 4. Japanese-language regression evidence

```bash
.venv/bin/onprem-dlp scan-text --text '個人番号：123456789018'
.venv/bin/python eval/run_eval.py
```

The second command reports English and Japanese precision/recall separately, so an
English pass cannot mask a Japanese context regression.

## 5. The egress API (optional `[api]` extra)

```bash
# Binds 127.0.0.1: the surface authenticates nobody, so it is unreachable off the host
# until an operator sets ONPREM_DLP_ALLOW_UNAUTHENTICATED_EXPOSURE=1.
.venv/bin/python -m onprem_dlp.api.serve &
curl -s localhost:8484/v1/egress/decide -H 'content-type: application/json' \
     -d '{"text": "customer NRIC S1234567D asked for a refund"}' | python3 -m json.tool
```

Returns `{"action": "BLOCK", "escalates": true, ...}`; the caller sends nothing.

## 6. Prove the gate

```bash
make gate     # exact Ruff + pytest + English/Japanese golden eval, all offline
```
