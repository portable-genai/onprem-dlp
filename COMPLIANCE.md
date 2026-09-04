# COMPLIANCE: control mapping

Documentation authority is declared in [`docs/doc-authority.md`](docs/doc-authority.md).

## Adopter-owned regulatory crosswalk

This table is an implementation starting point, not legal advice. Each adopting organization owns
applicability, exact instrument/version references, validation of the selected jurisdiction packs,
approval by privacy/legal/control owners, and retained evidence.

| Regime / regulator | Control family to validate | `onprem-dlp` evidence seam |
| --- | --- | --- |
| Singapore PDPA / MAS | Data minimization, protection, outsourcing and technology risk | `SG` pack, deterministic BLOCK/REDACT policy, verified audit chain |
| HK PDPO / HKMA | Personal-data protection and technology/outsourcing risk | `HK` pack plus adopter-owned policy and runbook evidence |
| Japan APPI / FSA | Personal-information safeguards and applicable outsourcing controls | `JP` pack plus adopter-owned approval evidence |
| Australia Privacy Act / APRA | APP privacy obligations and CPS 230/234 controls | `AU` pack, egress policy and operating evidence |
| Other regimes | Applicable privacy, secrecy and sector obligations | Add/test a pack and policy extension before enabling that jurisdiction |

This system is itself a control: a preventive, on-prem data-egress DLP gate. The map
below states what it enforces and where the residual risk sits.

| Control | Implementation | Evidence |
|---|---|---|
| Personal data identified before egress | deterministic recognizers + optional NER/Gemma; per-entity taxonomy incl. SG NRIC, HK HKID, JP MyNumber, AU TFN/Medicare | `SPEC.md`, eval golden set |
| Disclosure minimised (PDPA s.13/24, GDPR art. 5(1)(c)/32, APP 6/8, HIPAA de-id analogue) | redaction strategies per entity (tag/mask/salted-hash/remove); image box blackout + metadata strip | redaction tests; rescan-clean test |
| High-risk identifiers never leave (cross-border rules: GDPR ch. V, PDPA s.26, APP 8.1) | BLOCK list with confidence floor; exit-code/API contract; nothing is auto-released | egress-policy tests; CLI exit codes |
| Human-in-the-loop for consequential outcomes (MAS FEAT, EU AI Act art. 14 posture) | BLOCK escalates; ambiguous columns `needs_review`; Gemma verdicts bounded ±0.15 and advisory | classifier tests; `escalates` property |
| Special-category data flagged (GDPR art. 9, PDPA sensitive treatment) | `SENSITIVE` category (health/salary/religion/ethnicity/biometric) → "block pending DPO approval" | column classifier rules + tests |
| Structured PII inventory (RoPA support, BCBS 239 lineage input) | column classification with explainable weighted signals incl. cardinality; JSON export | `classify-columns --json` |
| Auditability & replayability | pure deterministic domain (same input → same decision); append-only JSONL audit with counts, never raw values | audit test asserts no raw PII in trail |
| Data residency | the default local profile and all detection engines run on-prem on CPU with zero runtime egress; remote database samplers are explicit opt-in adapters and BigQuery loads the Google SDK only when selected | Dockerfile, lazy adapter imports, default-deny Helm NetworkPolicy |
| Supply-chain honesty | core has ZERO third-party runtime deps; optional extras are opt-in and lazily imported | `pyproject.toml` |
| The unauthenticated REST surface cannot be exposed by default (ISO 27001 A.8.20/A.8.9, MAS TRM network segmentation) | fail-closed bind guard plus a request-time ASGI exposure guard on the app object; loopback unless an operator sets `ONPREM_DLP_ALLOW_UNAUTHENTICATED_EXPOSURE=1`; chart render fails if that acceptance is not compensated by the default-deny NetworkPolicy | `src/onprem_dlp/netguard.py`, `tests/unit/test_netguard.py`, `deploy/helm/.../deployment.yaml` |
| Security-relevant configuration cannot be relaxed by absence (fail-closed defaults) | every environment read resolves three states (unset / set-and-empty / set-and-valid); a variable set to nothing refuses rather than inheriting the permissive default | `read_env_setting`, `tests/unit/test_env_single_source.py` |

## Residual risks / honest limitations

- **Recall is not 100%.** Regex+checksum misses unformatted or novel identifiers;
  PERSON/ADDRESS recall requires the `full` or Gemma profiles; OCR misses low-quality
  scans. Treat the gate as risk reduction, not a guarantee; keep contractual and
  cloud-side controls (e.g. `agent-guardrail-gateway` with Cloud DLP) layered behind it.
- **Gemma/Presidio models can be wrong.** That is why they are advisory and bounded;
  their failure mode is a missed *extra* finding, never a silent release of a
  checksum-validated identifier.
- **Salted hash tokens are pseudonymisation, not anonymisation** (GDPR recital 26):
  the salt holder can re-link. Manage the salt like a key (per deployment, rotated).
- **Free-text columns** (notes, complaints) classify on shape/name only; route their
  *content* through the unstructured pipeline before egress.
- The gate does not intercept traffic it is not given (see SPEC non-goals); enforce
  at the network layer that cloud egress flows through it.
- **The REST surface authenticates nobody, in every profile.** It is an in-estate sidecar,
  and its four POST routes take, by construction, the raw personal data a caller was about
  to send out. The guards below make that surface unreachable by default rather than
  authenticated; identity is still the network's job, not the service's.

## Exposure posture: why the guard is local, not the shared commons

The catalog commons (`hex-service-kit`) carries the same fail-closed bind and exposure
primitives, and most repos in the fleet consume it. This one does not, and the reason is
recorded rather than implied.

`dependencies = []` is a load-bearing claim here, not a preference: this gate installs and
runs on an air-gapped host with nothing but Python, and "Supply-chain honesty" above is a
control that a single mandatory runtime dependency would falsify. The non-adoption
assessment in [`docs/practices-audit.md`](docs/practices-audit.md) reserves the kit's
primitives as reference implementations to mirror manually if a gap is ever closed here.
So `src/onprem_dlp/netguard.py` mirrors the kit's **semantics** verbatim, in pure stdlib,
and only the code is local.

Being air-gapped by design changes the threat model; it does not license an unauthenticated
write surface to bind every interface. Both halves of the guard exist because either alone
is bypassable:

| Half | What it bounds | Bypass it would leave |
|---|---|---|
| `resolve_bind_host` in `onprem_dlp.api.serve` (the image `CMD`) | the bind the container actually performs | a hand-typed `uvicorn ... --host 0.0.0.0` never calls it |
| `LoopbackExposureGuard` on the app object | every request, whatever served the app | a bind guard alone is a property of one entry point |

Kubernetes is the case where the exposure is legitimate: a pod must bind its pod IP or
neither the Service nor the kubelet probes can reach it. The chart therefore accepts it
**explicitly** (`api.acceptUnauthenticatedExposure`), and the render fails outright unless
`networkPolicy.enabled` is the compensating boundary. An accepted exposure with no network
control is the combination that is refused, so the acceptance is auditable in the values
file rather than buried in a container argument.
