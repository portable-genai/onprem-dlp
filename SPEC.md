# SPEC: on-prem DLP gate (`onprem-dlp`)

Documentation authority is declared in [`docs/doc-authority.md`](docs/doc-authority.md).

The reusable kernel is the deterministic stdlib detection, checksum, redaction, egress-decision,
column-profiling and evidence model. Jurisdiction recognizer packs and bank policy/configuration
are the adopter-owned vertical. A fork preserves the kernel contracts and replaces or extends the
packs and policy without adding a mandatory dependency.

That boundary is physical, not a naming convention.
[`src/onprem_dlp/domain/kernel.py`](src/onprem_dlp/domain/kernel.py) holds the vertical-neutral
machinery and imports nothing from this package.
[`src/onprem_dlp/domain/models.py`](src/onprem_dlp/domain/models.py) holds only what a fork
rewrites (the `EntityType` jurisdiction label pack, `DIRECT_IDENTIFIERS` and `EgressPolicy`),
imports the kernel and re-exports every kernel name, so existing import sites are unaffected.
The dependency arrow runs one way, models to kernel, and never back. `tests/unit/test_kernel_boundary.py`
proves it by execution: a fresh interpreter imports the kernel and asserts the vertical module
never enters `sys.modules`. Jurisdiction recognizer packs are the other half of the vertical and
live in [`src/onprem_dlp/domain/recognizers.py`](src/onprem_dlp/domain/recognizers.py).

## Problem

Regulated firms want cloud GenAI, but every prompt, document, image and dataset that
leaves the estate is a potential personal-data disclosure (PDPA s.24, GDPR art. 32/44,
APP 8, MAS TRM). Cloud-side DLP (e.g. Google Cloud Sensitive Data Protection) inspects
data **after** it has already left. This system is the complementary control: an
**on-prem, open-source, CPU-only gate** that detects, redacts or blocks personal data
**before egress**.

## Solution 1: unstructured text and images

**Inputs**: UTF-8 text (prompt, email, document extract) or an image (PNG/JPEG/TIFF).

**Pipeline**:
1. *Detection.* Deterministic recognizers (regex + checksum validators + context
   boosting) for: `EMAIL_ADDRESS`, `PHONE_NUMBER` (intl / context-gated local),
   `CREDIT_CARD` (Luhn), `IBAN` (mod-97), `IP_ADDRESS`, `SG_NRIC`, `HK_HKID`,
   `JP_MY_NUMBER`, `AU_TFN`, `AU_ABN`, `AU_MEDICARE`, `US_SSN`, `PASSPORT`
   (context-gated), `DATE_OF_BIRTH` (context-gated). Checksum failure kills a
   candidate; checksum pass lifts confidence to 0.98 (TFN 0.65 + context, SSN 0.8;
   format-only checks are weaker evidence).
2. *Optional model pass.* A NER port (Presidio) and/or Gemma add `PERSON_NAME`,
   `ADDRESS`, `ORGANIZATION`, `DATE_OF_BIRTH` candidates. Model findings are: bounds-checked,
   confidence-capped at 0.85 (below checksum certainty), and for Gemma, dropped unless
   the reported span exists verbatim in the source text.
3. *Overlap resolution.* Prefer validated, then higher confidence, then longer span.
4. *Redaction.* Per-entity strategy: `tag` (`<SG_NRIC>`), `mask` (keep last 4),
   `hash` (salted SHA-256 token, stable per salt; preserves joinability), `remove`.
   Applied right-to-left; re-scanning tagged output yields zero findings.
5. *Egress decision.* Policy maps entities to a BLOCK list and a REDACT list with a
   confidence floor. `ALLOW` / `REDACT` / `BLOCK`; BLOCK escalates to a human queue.
   Exit codes 0/3/4 make the CLI a CI/pipeline gate.

**Images**: OCR port extracts word-level text + pixel boxes (Tesseract). The SAME text
pipeline runs over the OCR extract; findings map back to word boxes; the image
redactor writes a copy with opaque rectangles and **all metadata (EXIF/GPS) stripped**.

## Solution 2: structured column classification

**Inputs**: CSV file, SQLite database, PostgreSQL/MySQL DSN, or
`bigquery://project/dataset` source (read-only sampling, default
500 values per column). Raw values never leave the host; only profiles and
classifications are emitted.

**Deterministic profile per column**: total/null/distinct counts, **cardinality ratio**
(distinct ÷ non-null), avg length, digit/alpha ratios, inferred type
(numeric/text/date/boolean), and per-entity **full-match ratios using the same
recognizers as Solution 1**: one shared PII definition.

**Classification signals** (each carries code, weight, human-readable detail):
- *Name*: multilingual synonym dictionary (email, nric, dob, seinengappi, jusho,
  salary, diagnosis, ...) → entity + category hint.
- *Pattern*: best full-match ratio; ≥ 0.6 ratio is strong evidence. Date-shaped values
  WITHOUT a birth-ish name are deliberately weak (order dates are not PII).
- *Shape*: cardinality ≥ 0.95 (identifier-shaped; unknown unique columns get a small
  positive weight; surrogate keys that join to persons), cardinality ≤ 0.05 with a
  demographic hint (quasi), very low cardinality otherwise (negative; category
  codes), plain numeric measures (negative).

**Categories**: `PII_DIRECT` (score ≥ 0.6 with direct evidence), `PII_QUASI`
(dob/gender/postcode/nationality/ids), `SENSITIVE` (health, salary, religion,
ethnicity, biometrics; blocked by default), `NON_PII`. Each carries a
`recommended_action` (tokenize/mask, generalise/bucket, block pending DPO, allow).

**Ambiguity band** (score 0.3–0.6): if a Gemma adjudicator is configured, its verdict
(is_pii, confidence, rationale) shifts the score by at most ±0.15; if the score stays
in the band, or no adjudicator exists, the column is flagged `needs_review = true`;
a human decides, never the model.

## The role of Gemma (explicitly bounded)

Gemma (3:1b default; 4b optional) runs fully on-prem on CPU. It may: propose NER
candidates, and adjudicate ambiguous columns. It may NOT: redact, classify a column
by itself, change policy, or release an egress. All Gemma output is schema-validated
JSON; garbage, hallucinations and timeouts degrade to the deterministic result
(fail-soft, fail-closed on the policy side).

## Quality gates (offline, deterministic)

- `pytest`: 70+ unit/contract/integration tests.
- `eval/run_eval.py`: golden-set gate; unstructured precision ≥ 0.90 and recall
  ≥ 0.85; structured column accuracy ≥ 0.85. Local profile currently scores 1.0 on
  all three (the golden set includes checksum-failure and context-trap negatives).

## Non-goals

- Not a network proxy/TLS interceptor: it gates payloads handed to it (CLI, REST,
  library call), it does not sniff traffic.
- Not exfiltration/insider-threat monitoring (endpoint DLP agents, CASB).
- Not k-anonymisation tooling: it *recommends* generalisation for quasi-identifiers
  but does not transform datasets.
- PERSON_NAME/ADDRESS recall in the `local` profile is limited by design (no models);
  enable the `full` or Gemma profiles for that recall.
