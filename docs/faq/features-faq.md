# Features FAQ

For product, compliance, and delivery teams: what this gate does, what is deterministic vs
advisory, and where its responsibilities **stop** and a sibling catalog system takes over.
Cross-references: [`README.md`](../../README.md), [`DEMO.md`](../../DEMO.md),
[`SPEC.md`](../../SPEC.md).

### What does Rsk6 actually do?

It is a preventive **DLP egress gate**: it detects, redacts, and decides on PII **before** any
byte leaves the estate for a cloud LLM or API. It ships **two solutions behind one
deterministic core**:

- **Unstructured** (text and images): detect PII in free text and in images (OCR), then
  redact it (tag / mask / salted-hash / remove) or black out the pixel regions, and issue an
  **ALLOW / REDACT / BLOCK** egress decision.
- **Structured** (database columns): profile CSV / SQLite / PostgreSQL / MySQL /
  BigQuery columns (name, value
  patterns, cardinality, type, null ratio) and classify each as `PII_DIRECT` / `PII_QUASI` /
  `SENSITIVE` / `NON_PII` from explainable, weighted signals, flagging ambiguous columns as
  `needs_review`.

### What is deterministic vs done by a model?

The consequential logic is **deterministic and replayable** (pure stdlib, no clock, no
randomness, unit-tested): the regex-plus-checksum recognizers (SG NRIC/FIN, HK HKID, JP My
Number, AU TFN/ABN/Medicare, credit-card Luhn, IBAN mod-97, US SSN, plus email, phone, IP,
passport, date of birth), the ALLOW / REDACT / BLOCK egress policy, and the column profiling
and classification. The offline eval scores precision, recall, and column accuracy at 1.0.
The optional Google Gemma and Microsoft Presidio models only **advise**: they add candidate
spans (mainly names and addresses) and bounded verdicts. An auditor can recompute every
decision without any model.

### Is anything auto-released?

No. BLOCK never auto-releases: `EgressDecision.escalates` routes it to a human queue and
nothing is sent. Ambiguous columns flip `needs_review=True` rather than guessing. Model
verdicts are advisory and bounded (about +/-0.15) and can never redact, block, or release on
their own; a checksum-validated block-listed identifier forces BLOCK regardless of the
confidence floor. Escalation signals raise the bar, they never lower it.

### How do the exit codes work as a CI gate?

The CLI returns egress-shaped exit codes so it drops straight into a pipeline: `0` = ALLOW,
`3` = REDACT, `4` = BLOCK. The structured pipeline adds `classify-columns --fail-on-pii`,
which exits `4` if any `PII_DIRECT` or `SENSITIVE` column is found, so a schema that would
leak PII fails the build. The optional REST gate (the `[api]` extra) exposes the same
decision to machine-to-machine callers on the egress path.

### Which capabilities does this repo own vs leave to the catalog?

This is one system in a catalog of composable GRC systems, and it is a deliberately narrow
**leaf control**. Being air-gapped with zero runtime egress, it **consumes nothing** at
runtime; the table below is about where it sits, not what it calls:

| Concern | Owned by (catalog id / repo) | Rsk6's relationship |
|---|---|---|
| In-cloud runtime guardrail: prompt-injection / jailbreak defence, cloud DLP | **Hrz1** `agent-guardrail-gateway` | Rsk6 is the on-prem gate that runs *before* egress; Hrz1 is the in-cloud control layered behind it |
| Enterprise immutable WORM prompt/response audit | **Hrz5** `agent-observability` | Rsk6's local JSONL sink ships to it (or your SIEM) for durability and tamper-evidence |
| Cloud document-diligence agents (CDD / SoW, and similar) | the document-vertical repositories | consume Rsk6 as the sovereign-DLP option behind their redaction port |
| Residency validation / exit planning | **Rsk4** / **Rsk5** | Rsk6 is one of the systems those tools reason about; its residency is physical (on-prem) |

So the in-cloud guardrail, the enterprise audit system, and the eval platform are *adjacent*,
not features of this repo, and this repo does not rebuild any of them.

### How do I see it working?

`make demo` drives the real CLI (`scan-text`, `decide`, `redact-text`, `classify-columns`)
over synthetic fixtures, fully offline, with no models and no API key. `DEMO.md` is the
presenter script. `tests/integration/test_cli.py` exercises the exact demo commands and
asserts live state (entity types, a BLOCK decision, exit codes, audit contents), so the demo
cannot rot silently. Every fixture uses obviously-fictional but checksum-valid identifiers.

### Can I use it for a non-BFSI domain?

Yes. The recognizers and the classifier are domain-neutral; a hospital, insurer, or public
body forks it the same way. What you change is the jurisdiction pattern packs and the egress
policy lists, not the engine. See [`docs/ADOPTING.md`](../ADOPTING.md) and
[adoption-faq.md](adoption-faq.md).
