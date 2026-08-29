# Common-base practices audit

- **Repo:** `onprem-dlp`
- **Catalog id:** Rsk6 (package `onprem_dlp`, env prefix `ONPREM_DLP`)
- **Catalogue reference:** [`common-base-practices.md`](https://github.com/portable-genai/.github/blob/main/common-base-practices.md) (checks A1..G7)
- **Authoritative source:** reconciled to the maintainer's cross-repository audit matrix,
  authoritative on portfolio status. This file owns current repository evidence and verdicts.
  Commons remain deliberately unadopted for the offline core.
- **Note:** Rsk6 is a **stdlib, air-gapped, on-prem DLP egress gate** (detect / redact / block PII in
  text, images and database columns *before* any byte leaves for the cloud), **not** a GCP hexagonal
  cloud agent. It is hexagonal (ports-and-adapters, one-config profile swap) but its "profiles" vary a
  local model stack (regex-only -> +Gemma -> +Presidio), not a cloud backend. Cloud-specific checks are
  therefore **N-A by design** (marked with a one-line reason after reading the code), never FAILed. Its
  determinism (B1) and fail-closed egress policy (C5) are audited as first-class strengths.

Applicability: Rsk6 ships **no web UI** and **no Terraform / cloud deploy**, so `[ui]` and the cloud
`[infra]` checks are N-A. It has an optional machine-to-machine REST gate (`[api]` extra) and an
optional local-CPU Gemma/Presidio pass, so `[agentic]` checks are audited on their merits.
**Load-bearing** checks (a FAIL breaks a shared catalog guarantee) are A1-A6, C1-C5, D1-D3, E1; here
those resolve to 13 PASS, 0 PARTIAL, 0 FAIL, 2 N-A-by-design (C1, C2); D2 was the single PARTIAL and its
three operator preconditions were met on 2026-08-23. The gate itself
(`make gate` = exact Ruff + 228 tests + English/Japanese/block-safety eval + portability) is wired to SHA-pinned CI
and remains fully green offline with zero secrets.

**Shared commons: deliberately not adopted.** The catalog's
shared packages (`hex-service-kit`, `agent-eval-kit`) are not consumed here, by design
rather than by omission, and this is the same seam already recorded for `pii-kit`:

- `hex-service-kit` would be a runtime dependency of the domain core, and this repo's
  load-bearing portability claim is `dependencies = []` (a pure-stdlib egress gate that
  runs air-gapped on CPU). One dependency breaks that claim. The kit's primitives
  (StrEnum, hash-chained audit, fail-closed bind) remain available as reference
  implementations to mirror manually if a gap is ever closed here.
  The manual-mirror approach carries a real risk: without a guard, the REST app's four POST
  routes would have no exposure control while the image `CMD` serves them on `0.0.0.0`.
  Rather than pin the kit and falsify
  `dependencies = []`, `src/onprem_dlp/netguard.py` mirrors the kit's fail-closed bind,
  request-time exposure guard, three-state environment read and never-wildcard CORS
  allowlist in pure stdlib, matching its semantics so the fleet behaves uniformly even
  though the code is local. The cost of the mirror is honest: a kit fix does not reach this
  repo automatically, so `netguard.py` names the kit as its reference and
  `tests/unit/test_netguard.py` pins the behaviour that must not drift.
- `agent-eval-kit` is n/a: an air-gapped egress gate has no reachable Hrz4 promotion
  authority, so a `--mode gate` would be a fake authority; `eval/run_eval.py` IS the
  offline gate by design; the repository CI runs it directly without claiming remote
  promotion authority.

The copy relationship between this repo's recognizers and the public `pii-kit` remains
pinned only by the package's validator tests and review (see the catalog's
plan-commons-extraction "Rsk6 seam" section).

| Check | Verdict | Evidence / gap |
|---|---|---|
| **A1** Hexagonal core, stdlib-only domain `[all]` **(load-bearing)** | PASS | `grep -rE "google\|fastapi\|httpx\|pydantic\|boto3\|azure\|presidio\|PIL\|psycopg\|ollama\|llama_cpp" src/onprem_dlp/domain/` returns only a docstring mention; `domain/` is pure stdlib (frozen dataclasses, regex, checksums). |
| **A2** Ports are `@runtime_checkable` Protocols, re-exported once `[all]` **(load-bearing)** | PASS | `ports/__init__.py` defines 6 `@runtime_checkable` Protocols (`NerAnalyzer`, `OcrEngine`, `ImageRedactor`, `LlmAdjudicator`, `ColumnSampler`, `AuditSink`) with `__all__` as the source of truth; `tests/contract/test_ports.py` asserts each shipped adapter satisfies its Protocol. |
| **A3** Swappable profiles by one config value `[all]` **(load-bearing)** | PASS | `ONPREM_DLP_PROFILE` (or `profile:` / `--profile`) = `local\|gemma-ollama\|gemma-llamacpp\|full`; per-port dotted `module:Class`+kwargs bindings under `profiles:` in `config/settings.yaml`; offline suite runs on `pip install -e ".[dev]"` with no models. The managed-cloud / platform-HTTP / onprem-placeholder profile *taxonomy* is N-A (this system is itself the on-prem endpoint); the load-bearing property, one-config profile swap with zero domain edits, holds. |
| **A4** One adapter constructor `Adapter(settings)` `[all]` **(load-bearing)** | PASS | Every configuration-bound NER, adjudicator, OCR and image-redactor adapter accepts one positional `AdapterSettings`. `_instantiate` is the only translation from YAML kwargs to that immutable boundary. Contract tests construct every binding from every profile through this convention. Database samplers take the source URI because it is request input, not DI configuration. |
| **A5** Lazy cloud imports in cloud adapters `[all]` **(load-bearing)** | PASS | `BigQuerySampler` imports `google.cloud.bigquery` only in `_connection`; MySQL/PostgreSQL and all model/OCR SDK imports are likewise method-local. Contract tests construct every adapter without any optional SDK installed, and the complete offline gate imports the package with no cloud dependency. |
| **A6** Contract tests enforce the hexagon; port map cannot drift `[all]` **(load-bearing)** | PASS | `test_ports.py` asserts Protocol conformance, exact profile/binding key sets, construction through the one-settings convention, lazy optional imports, and deterministic equality across independent local containers. `scripts/portability_demo.py` runs the contract plus real CLI replay as an exit-code gate. |
| **A7** Kernel vs vertical split in the domain `[all]` | PASS | The split is physical, not a label. `src/onprem_dlp/domain/kernel.py` holds the vertical-neutral machinery SPEC.md names (the `Finding`/`TextScanResult` evidence model, `RedactionStrategy`/`AppliedRedaction`/`RedactedText`, the OCR and pixel geometry, `ColumnProfile`/`ColumnClassification`/`DatasetClassification`, `EgressAction`/`EgressReason`/`EgressDecision`, `AdjudicationVerdict`, `AuditEvent`, `Severity`, the member-less open-taxonomy base `OpenLabel` and `utcnow`) and imports nothing from this package. `src/onprem_dlp/domain/models.py` keeps only the adopter-owned vertical (the `EntityType` jurisdiction label pack, `DIRECT_IDENTIFIERS`, `EgressPolicy`), imports `.kernel` and re-exports every kernel name as `X as X`, so no import site changed. Proved by execution, not by reading: `tests/unit/test_kernel_boundary.py` runs a fresh `subprocess` interpreter that imports `onprem_dlp.domain.kernel` and asserts `onprem_dlp.domain.models` never enters `sys.modules`, plus the reverse arrow, an AST scan for intra-package imports in `kernel.py`, `is`-identity of all 22 kernel names across both modules, and the absence of all 3 vertical names from the kernel. Verified RED first: against a re-export shim `kernel.py` over the pre-split `models.py` the same file failed 5 of 28 (the direction probe, the reverse arrow, the AST scan, `OpenLabel`, `utcnow`); after the split, 28 passed. Full gate green: 228 passed, 1 skipped, eval PASS, portability PASS, exit 0. |
| **A8** Consume platform horizontals via thin delegates `[all]` | N-A | By design: an air-gapped on-prem leaf control with no platform to consume. It *is* a DLP/guardrail primitive (Rsk6); COMPLIANCE explicitly positions it to layer *behind* a cloud gateway (e.g. Hrz1), not to re-implement one. No cloud/platform delegate adapters. |
| **B1** Consequential math is deterministic, pure, replayable `[agentic]` | PASS | Standout strength. `recognizers.py` (regex + Luhn/NRIC/HKID/MyNumber/TFN/ABN/Medicare/IBAN/SSN checksums), `egress_policy_service.py`, `column_classifier_service.py`, `column_profile_service.py`: pure stdlib, no clock/randomness, unit-tested; `eval` scores precision/recall/accuracy = 1.0 offline. Models only advise. |
| **B2** Every claim carries a citation; empty retrieval is a hard error `[agentic]` | PASS | Provenance analog fully met: every `Finding` carries `recognizer` (e.g. `regex:sg_nric`), span, `validated`, `context_boosted`; every `EgressReason` cites span + recognizer. No claim is emitted without a traceable source. The retrieval-grounding sub-clause is N-A (no RAG). |
| **B3** Maker-checker on every consequential output `[agentic]` | PASS | BLOCK never auto-releases (`EgressDecision.escalates` -> human queue); ambiguous columns flip `needs_review=True`; Gemma verdicts are advisory and bounded (+/-0.15) and can never redact/block/release; asserted in `test_egress_policy.py`, `test_column_services.py`, `test_cli.py`. |
| **B4** Bank-owned policy numbers in config, defaults = reference `[all]` | PASS | `settings.yaml policy:`/`detection:`/`redaction:`/`classifier:` carry block/redact entity lists, confidence floors, `block_at_or_above`, thresholds, strategies; defaults = `EgressPolicy.default()`. `test_config.py` proves defaults reproduce reference behaviour AND overrides (min_confidence 0.9, hash strategy) change it; `test_egress_policy.py` proves a raised floor still BLOCKs a block-listed ID. |
| **B5** Open taxonomy: `StrEnum` vocabularies, engines typed on `str` `[all]` | PASS | Known entities remain discoverable `StrEnum` members and `EntityType._missing_` creates stable string-valued pseudo-members for safe config-only extensions. `test_entity_taxonomy_accepts_safe_config_only_extensions` proves an adopter can add a policy entity without editing the enum; malformed values still fail. |
| **C1** Identity resolved server-side; client actor/ACL discarded `[all]` **(load-bearing)** | N-A | By design: an internal, unauthenticated payload-scrubbing gate with **no actor/identity concept** (request schema is `text` + a `source_id` label). `grep -niE "actor\|principal\|identity" src/onprem_dlp/api/` finds none. There is no client-asserted actor or ACL to trust or discard. |
| **C2** Object-level authz derived server-side; tenant isolation by data tags `[all]` **(load-bearing)** | N-A | By design: stateless scrubber. Nothing is persisted or retrieved per-tenant; each call scrubs a payload and returns (structured mode samples read-only and emits only profiles). No multi-tenant store, no per-resource ACL to enforce. |
| **C3** Redact before everything `[agentic]` **(load-bearing)** | PASS | The audit sink records entity **counts**, spans and actions, never raw matched values (`orchestrator_service.py` `_audit(...)`; ARCHITECTURE invariant 5); `tests/integration/test_cli.py::test_audit_trail_is_written` asserts `"S1234567D" not in audit`. (The "redact before model" clause is inverted here: the model *is* the detector, so it must see raw text.) |
| **C4** Jurisdiction-driven PII packs keep the gate honest `[agentic]` **(load-bearing)** | PASS | `detection.jurisdictions` explicitly selects SG/HK/JP/AU/US packs; global patterns remain active. One selector supplies both text detection and column profiling and refuses empty/unknown packs. Cross-jurisdiction tests prove SG-only detects SG/global identifiers but not HKID. The eval drives the same runtime service. |
| **C5** Fail-closed defaults everywhere `[all]` **(load-bearing)** | PASS | Policy fail-closed is strong: a checksum-validated block-listed finding forces BLOCK regardless of the confidence floor (`egress_policy_service.py` comment + `test_block_entity_survives_a_raised_confidence_floor`); unknown profile and un-inferable sampler both raise `ValueError` (`test_config.py`); models fail-soft to the deterministic result. A plain `docker run -p 8484:8484` would put four unauthenticated routes accepting raw personal data on every interface unless bind and CORS are constrained; SPEC's non-goals say nothing that exempts the bind, and "designed to sit behind a load balancer" describes an intended topology, not a requirement enforced in code. The loopback/CORS sub-clauses are therefore in scope and PASS on evidence: `netguard.resolve_bind_host` binds loopback unless the exposure is explicitly accepted, `netguard.LoopbackExposureGuard` enforces the same rule per request on the app object, `cors_allowlist` is never a wildcard in any state, and the chart refuses to render an accepted exposure without its default-deny NetworkPolicy (`test_netguard.py`, `test_api_exposure.py`, `test_deployment_assets.py`). The absence of an *auth* surface remains N-A by design: reachability, not identity, is the control here. Every environment read resolves three states, guarded by `test_env_single_source.py`. |
| **C6** Security-header baseline on every surface `[ui]` | N-A | No web UI. The optional `[api]` REST gate is a machine-to-machine endpoint, not a browser surface; it sets no CSP/HSTS (a minor hardening note, not a `[ui]` finding). |
| **C7** Service-to-service calls authenticated, https-only outside loopback `[all]` | PASS | BigQuery uses authenticated ADC/HTTPS; MySQL verifies certificate and host identity with a strict option allowlist. PostgreSQL refuses construction unless the DSN sets exactly `sslmode=verify-full` and a non-empty `sslrootcert`. Database tests pin the refusal and successful contract; Helm local denies egress. |
| **C8** Web login flow hardening `[ui]` | N-A | No login flow, no UI, no OIDC. |
| **C9** Tamper-evident audit with honest limits `[all]` | PASS | `JsonlAuditSink` chains canonical records with SHA-256, fsyncs append, atomically writes a sidecar head anchor, verifies before append/export, and restores only a valid complete JSONL chain. Tests catch record modification and tail truncation and prove export/restore. Its docstring states that an administrator able to rewrite log and anchor still requires independently protected storage/SIEM. The "tail truncation" claim holds only for a log sitting beside its own anchor: an export that carried only the record lines, without the head, would let `restore_jsonl` derive the head from a walk of the payload it was handed and write that out as the restored log's anchor, so a truncated export would arrive self-consistent and verify clean, undetectably. The export leads with an anchor header line, a restore checks the arriving records against the head that travelled with them and refuses a mismatch, and a pre-anchor payload restores with no anchor and is reported unanchored rather than verified (`test_audit_chain.py`). |
| **C10** No secret values in the repo `[all]` | PASS | `.env` and `.env.secrets` are ignored; tracked examples separate non-secrets from secrets. `ONPREM_DLP_REDACTION_HASH_SALT` and `ONPREM_DLP_MYSQL_PASSWORD` are consumed from the environment, and the Helm chart references an existing Kubernetes Secret without rendering values. Tests assert the separation. |
| **D1** Locked, reproducible installs everywhere `[all]` **(load-bearing)** | PASS | Committed lockfiles pin every gate/runtime install, the Dockerfile installs locked, and Ruff is exactly `0.15.18` in both `pyproject.toml` and `requirements-dev.lock`. The domain core still has zero runtime dependencies. |
| **D2** Digest-pinned images, SHA-pinned Actions, dependabot, CI audit `[all]` **(load-bearing)** | PARTIAL | The base image is digest-pinned, every GitHub Action is pinned by a full commit SHA, and Dependabot tracks pip/docker. The locked networked recipe installs the toolchain and runs exactly pinned `pip-audit==2.10.1` strictly over both fully pinned runtime and development locks with resolver use disabled. Both audits pass locally, and now hosted as well. This row was PARTIAL on three operator preconditions, all of which were met on 2026-08-23: (1) the two-job hosted-CI contract is applied, as this repo's `offline-gate` and `dependency-audit` Cloud Build jobs; (2) `main` required the hosted pull-request check on its `main-safety-rails` ruleset; and (3) a hosted run of the exact pinned `pip-audit==2.10.1` recipe over BOTH lockfiles reported `No known vulnerabilities found` twice and is retained with its `GRC_CI_EVIDENCE` line. GitHub Actions remain disabled fleet-wide by portfolio decision, which is why the workflow files here are a reviewed contract that Cloud Build is digest-bound to rather than something that runs; the hosted signal is Cloud Build. Retired as of 2026-08-29: the project that ran that hosted check and held its retained evidence was deleted, so preconditions (2) and (3) are proved against infrastructure that no longer exists. The foundation has been rebuilt and this repository's pull-request check is required again. How far that is proved is `org-metadata/docs/deployment-status.md`'s to say, and it is the only place that should say it: a per-repository copy of a status that changes is a copy that goes stale, which this row did within the hour. |
| **D3** Whole gate runs offline, zero org secrets `[all]` **(load-bearing)** | PASS | `make gate` runs exact Ruff, the full pytest suite, English/Japanese golden evaluation, and column evaluation fully offline with zero secrets. `.github/workflows/ci.yaml` runs that same command from the locked dev requirements on every push and pull request. |
| **D4** Non-root, minimal, healthchecked container `[infra]` | PASS | `Dockerfile`: `USER dlp` (non-root), `HEALTHCHECK` against `/healthz`, `EXPOSE 8484`, `python:3.12-slim` base with only tesseract added; no build toolchain left in the image. (Single-stage rather than multi-stage, but nothing to strip.) Digest-pinning is tracked under D2. |
| **D5** Deploy-time residency/sovereignty, parameterised `[infra]` | N-A | By design: on-prem / air-gapped tool with no cloud deploy. Residency is physical (runs inside the customer estate, zero runtime egress - COMPLIANCE "Data residency" row); there is no cloud region, Org Policy, CMEK, VPC-SC or Terraform to parameterise. |
| **E1** Offline eval smoke guards merge; Hrz4 owns promotion `[agentic]` **(load-bearing)** | PASS | `eval/run_eval.py` deterministically gates English and Japanese precision/recall plus column accuracy with labelled thresholds and exit-code semantics; `make gate` wires it into CI. Hrz4 promotion is N-A by design for this standalone air-gapped tool, and the repo does not claim a fake remote promotion authority. |
| **E2** Safety metric with strictest threshold, no false green `[agentic]` | PASS | The eval reports release-critical block-entity recall separately at the strictest threshold (`>=0.99`) across English and Japanese golden labels. It invokes the runtime `TextDetectionService`; the independent golden labels are the oracle. A planted empty detector drives the score to zero in `test_eval_gate.py`. |
| **E3** Fixtures and golden data obviously fictional `[all]` | PASS | Demo/golden data is synthetic and checksum-valid: `@example.com`, `support@examplebank.sg`, obviously-synthetic names, generated by `scripts/generate_demo_data.py`; README/DEMO/CONTRIBUTING all state "no real personal data ... fake but checksum-valid". |
| **F1** Demo is code, offline, one command, presenter-paced `[all]` | PASS | `make demo` drives the real CLI (scan / decide / redact / classify-columns) over synthetic fixtures, offline, no models or API key; `DEMO.md` is the presenter script. (Straight-line CLI rather than back/jump-paced - a reasonable simplification for a CLI tool with no UI.) |
| **F2** Demo cannot rot silently `[all]` | PASS | `tests/integration/test_cli.py` exercises the exact demo commands over the real fixtures and asserts entity types, BLOCK, exit codes, and audit contents; the SHA-pinned CI workflow runs the complete suite through `make gate`. |
| **F3** Portability claim is executable `[all]` | PASS | `scripts/portability_demo.py`, invoked by `make gate`, runs adapter contracts, byte-identical real CLI replay and a cloud-import scan, and states the optional-model/OCR/database/Kubernetes limits it cannot establish. Audit export/restore is separately gated by `test_audit_chain.py`; identity swap is N-A for this stateless gate. |
| **G1** Declared doc authority order, kept true `[all]` | PASS | `docs/doc-authority.md` declares SPEC > ARCHITECTURE > COMPLIANCE > README > supporting guides, with changelog/audit roles. Root documents link it and a static test pins the order and kernel statement. |
| **G2** Compliance mapping table + adopter-owned crosswalk `[all]` | PASS | `COMPLIANCE.md` retains its control/evidence mapping and adds an explicitly adopter-owned PDPA/MAS, HKPD/HKMA, APPI/FSA and Privacy Act/APRA crosswalk with responsibility for applicability, instrument versions, pack validation, approvals and retained evidence. |
| **G3** Documented, mechanised fork path `[all]` | PASS | `docs/ADOPTING.md` (keep-vs-rewrite table, core-vs-adopter-owned file boundary, mechanical-rebrand + human-decisions split, adoption checklist) and `scripts/rename_fork.py` (stdlib-only, preview-first). The dry-run exits 0, prints a de-duplicated plan for `onprem_dlp` / `onprem-dlp` / `ONPREM_DLP_` (CLI, dist and resource stem coincide here), and writes nothing. |
| **G4** Retired `[all]` | N-A (retired) | Retired practice. Releases are tracked by git tag and the `pyproject.toml` version. |
| **G5** Role-specific FAQs referencing sibling systems `[all]` | PASS | `docs/faq/` ships a role index (`README.md`) plus five audience FAQs (security, portability, features, adoption, compliance) tailored to Rsk6's real posture (air-gapped, CPU-only, zero mandatory deps, ALLOW/REDACT/BLOCK policy, optional advisory adapters). Each names the owning catalog ids at the boundary (Hrz1 in-cloud guardrail, Hrz5 audit, the document verticals, Rsk4/Rsk5) and states that, being air-gapped, this gate consumes no sibling service at runtime. |
| **G6** Contribution docs cover full extension touch list, enforced by test `[all]` | PASS | `CONTRIBUTING.md` enumerates adapter, port/sub-service and jurisdiction-pack touch lists across bindings, composition, surfaces, contracts, docs, eval and demo/portability evidence. `test_practices_closures.py` pins the key sections. |
| **G7** Markdown discipline: minimise em-dashes, validate mermaid `[all]` | PASS | Tracked Markdown contains zero em-dash glyphs. Rsk6 intentionally uses text/tables and has no Mermaid block; the static practice test asserts both properties so unvalidated Mermaid cannot enter silently. |

**Verdict counts:** 33 PASS, 1 PARTIAL, 0 FAIL, 7 N-A (of 41 checks). Of the load-bearing set
(A1-A6, C1-C5, D1-D3, E1): 12 PASS, 1 PARTIAL, 0 FAIL, 2 N-A-by-design (C1, C2).
No load-bearing FAIL remains. **D2 is the only open row, and it is not code-addressable:** every
mechanised part is done and green locally; what is missing is an operator applying the hosted-CI
contract, requiring its check on `main`, and retaining one hosted run of the pinned `pip-audit`
recipe, which cannot happen while Actions are disabled fleet-wide. A7 rests on the kernel/vertical
dependency direction being physical and proven in a fresh interpreter, RED-first.
Exact Ruff, the offline CI gate, and locale-specific eval
ground D3/E1. G3 and G5 rest on `docs/ADOPTING.md` +
`scripts/rename_fork.py` (G3) and the `docs/faq/` role set (G5), which are
additive docs with no source change. G4 is a retired practice. No FAIL remains anywhere. The determinism (B1) and fail-closed
egress policy (C5) are strong PASSes, as expected for this system.

## Gaps carried to systems/

The material gaps to record on the Rsk6 row of
the maintainer's per-system register
`Capability gaps`:

- **Hosted CI dependency-vulnerability evidence (load-bearing residual: D2).** Lockfiles,
  digest/SHA pins, Dependabot, exact Ruff, the complete offline gate and the pinned `pip-audit`
  recipe are mechanised. The catalog's exact two-job GCP hosted-CI contract is implemented and
  tested offline; an operator must apply it, set branch protection on `main` requiring its PR check,
  and retain one successful hosted execution of the exact pinned `pip-audit` recipe to close the
  evidence gap. GitHub Actions remain disabled fleet-wide by portfolio decision, so this residual is
  externally blocked and no repository change can clear it.
- **Adopter / documentation gaps (G3, G5).**
  `docs/ADOPTING.md` + `scripts/rename_fork.py` (G3) and the `docs/faq/`
  role set (G5) are additive docs, with no source
  change. Quality-of-adoption, not load-bearing; recorded here for provenance. G4 is a retired
  practice.
- **A7 module boundary.** `domain/kernel.py` physically holds the
  vertical-neutral machinery and imports nothing from the package; `domain/models.py` keeps the
  jurisdiction pack and bank policy and re-exports every kernel name, so no import site moved.
  `tests/unit/test_kernel_boundary.py` proves the direction in a fresh interpreter, verified
  against a re-export shim run RED first.
- **Other code-addressable practice gaps.** The constructor/parity, open
  taxonomy, jurisdiction-pack, PostgreSQL TLS, tamper-evidence, strict safety, portability and
  documentation findings are gated offline. D2 remains evidence-only, as stated above.

By-design **N-A** (audited and confirmed against the code, not FAILed): A8 (air-gapped
leaf control, no platform to consume), C1/C2 (unauthenticated stateless scrubber, no
actor/tenant surface), C6/C8 (no web UI), D5 (on-prem, residency is physical - no cloud
Terraform). The managed-cloud/platform/onprem-placeholder *profile taxonomy* under A3 is likewise
N-A, but A3's load-bearing property (one-config profile swap) is a PASS.
