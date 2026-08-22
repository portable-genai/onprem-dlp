# Compliance FAQ

For compliance, DPO, and model-risk teams assessing the repo's regulatory posture.
Cross-references: [`COMPLIANCE.md`](../../COMPLIANCE.md) (the full control map and residual
risks), [`SPEC.md`](../../SPEC.md).

### What kind of control is this?

A **preventive, on-prem data-egress DLP gate**: it identifies personal data and stops or
minimises its disclosure **before** anything leaves for a cloud LLM or API. It is itself a
control, not a decision-support agent. `COMPLIANCE.md` maps each function to concrete
implementation and evidence, with multi-regulator references (PDPA, GDPR, APP, HIPAA
de-identification analogue, MAS FEAT, EU AI Act article 14 posture).

### How is customer PII handled?

Detect, then redact or block, before egress. National-identifier detection is checksum-hardened
(SG NRIC/FIN, HK HKID, JP My Number, AU TFN/ABN/Medicare, US SSN, plus credit-card Luhn and
IBAN mod-97), so a Luhn-failing "card number" never becomes a finding. Redaction offers tag,
mask, salted-hash, and remove strategies; images have their PII regions blacked out and
metadata stripped. One honest caveat the docs state plainly: salted-hash tokens are
**pseudonymisation, not anonymisation** (GDPR recital 26) because the salt holder can re-link,
so the salt must be managed like a key.

### Is anything decided autonomously?

No consequential release is automatic. A checksum-valid block-listed identifier forces
**BLOCK**, and BLOCK **escalates to a human** rather than auto-releasing. Ambiguous columns
are flagged `needs_review`. The optional Gemma / Presidio models are advisory and bounded
(about +/-0.15); they can raise a finding but can never release, redact, or block on their
own. This is the human-in-the-loop posture regulators expect for consequential outcomes.

### How is the work auditable and reproducible?

The deterministic core has no clock and no randomness, so the same input always yields the
same decision and an auditor can replay any outcome. Every `Finding` carries its recognizer,
span, and validation flags, and every egress reason cites its span and recognizer, so no
decision is emitted without a traceable source. The optional append-only JSONL audit sink
records entity **counts**, spans, and actions and **never the raw matched values** (a test
asserts a known identifier is absent from the trail). For tamper-evidence and durability, ship
that sink to your SIEM; the in-repo sink is append-only but not hash-chained.

### What is the model-risk story?

An offline eval gate (`eval/run_eval.py`) scores unstructured precision and recall and
structured column accuracy against a synthetic golden set, with labelled thresholds
(precision >= 0.90, recall >= 0.85, column accuracy >= 0.85), and fails below them. Crucially
the eval and the runtime share exactly one detection source (`recognizers.py`), so the gate
cannot trivially go falsely green. A fork must rebuild the golden set for its own jurisdictions
or the gate measures the wrong identifiers. Because the system is air-gapped, there is no
external promotion authority; the offline gate is the model-risk evidence by design.

### Is data residency satisfied?

Yes for the default local/detection profiles, by construction rather than by
configuration. Regex, checksums, Gemma, Presidio, and Tesseract run **on-prem on CPU**;
the Helm local profile denies egress. PostgreSQL/MySQL/BigQuery column samplers are
explicit opt-in connections to an adopter-authorized data source, so their location,
TLS, and identity policy are adopter-owned. This repo is one of the systems that a
residency validator (Rsk4) or an exit planner (Rsk5) reasons about.

### Which regulators does it map to, and can I add mine?

`COMPLIANCE.md` carries a control-to-implementation-to-evidence table with PDPA / GDPR / APP /
HIPAA / MAS references inline and an honest residual-risk section. To add FCA / RBI / OJK /
HKMA / APRA, extend the mapping and re-review with local counsel; the internal control column
is stable across regulators. Honest gap: the regulator references are inline rather than a
dedicated adopter-owned crosswalk appendix, so state ownership explicitly when you adopt.

### Can we run it against real customer data today?

Not without your own legal, security, and model-risk sign-off. Every fixture and golden case
uses obviously-fictional but checksum-valid identifiers, and the docs state throughout that
this is a reference build. And remember the gate only sees traffic it is given: enforce at the
network layer that cloud egress actually flows through it, and treat it as risk reduction, not
a guarantee (recall is not 100%). The adoption checklist in
[`docs/ADOPTING.md`](../ADOPTING.md) lists the steps (jurisdiction packs, egress policy, salt,
golden set, deploy posture) that must precede any live-data use.
