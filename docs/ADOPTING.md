# Adopting this repo as your base

This repository is a **common base** that a bank, insurer, hospital, or any regulated
organisation forks to build its own on-prem DLP egress gate: a control that detects,
redacts, and decides on PII in free text, images, and database columns **before** any byte
leaves the estate for a cloud LLM or API. It ships a reusable hexagonal core (a pure-stdlib
deterministic domain, typed ports, swappable adapter profiles, a green offline gate) plus a
fully worked set of jurisdiction recognizers and two solutions (unstructured text/image DLP
and structured column classification) you can keep, retune, or extend.

This guide is the step-by-step for making it yours. It has two halves: a **mechanical
rebrand** (one script) and the **human decisions** the script cannot make for you.

> Related reading: [`ARCHITECTURE.md`](../ARCHITECTURE.md) (ports, adapters, invariants),
> [`CONTRIBUTING.md`](../CONTRIBUTING.md) (adding a recognizer / adapter), the
> [`faq/`](faq/) directory.

---

## 1. What you keep vs what you rewrite

This is a focused single-purpose DLP gate, not a multi-vertical framework, so the boundary
is drawn by responsibility rather than by a named kernel module:

| Layer | Where | For your deployment |
|---|---|---|
| **Deterministic core** (recognizer engine, egress policy, column profiling and classification, redaction) | `domain/services.py`, `domain/recognizers.py` mechanics, `domain/egress_policy_service.py`, `domain/column_profile_service.py`, `domain/column_classifier_service.py` | keep the machinery untouched |
| **Ports and wiring** | `ports/`, `config.py` (`Container`, `_instantiate`), `tests/contract/` | keep; take upstream fixes |
| **Policy** (your numbers and lists) | the `detection:` / `redaction:` / `policy:` / `classifier:` sections of `config/settings.yaml` | change by config, not code |
| **Pattern packs** (your jurisdictions) | the recognizer definitions in `domain/recognizers.py` | add or remove national-identifier packs |
| **Data** (fixtures, golden set) | `demo/`, `scripts/generate_demo_data.py`, `eval/golden/` | replace with your own synthetic data |

The deterministic core, the ports, and the eval harness mechanics transfer directly. What
you own is the pattern packs for your jurisdictions, the egress policy numbers, and the
golden set that keeps the gate honest.

## 2. Core-vs-adopter-owned files (so upstream merges stay mechanical)

Upstream keeps evolving these; avoid diverging from them so you can pull fixes cleanly:

- **Upstream-owned** (take our changes): the domain service mechanics
  (`domain/services.py`, the profiling/classification/egress engines), `ports/`,
  `tests/contract/`, the eval harness (`eval/run_eval.py` mechanics), the hexagon wiring
  (`config.py` `Container`), the `Dockerfile` structure.
- **Adopter-owned** (yours; expect to edit): the `config/settings.yaml` *values* (block /
  redact entity lists, confidence floors, redaction strategies, classifier thresholds), the
  recognizer pattern packs for your jurisdictions in `domain/recognizers.py`, the demo
  fixtures and the eval golden set, and the `COMPLIANCE.md` jurisdiction / regulator rows.

Track upstream via git tags; rebase your
adopter-owned changes onto each release rather than merging `main` continuously.

## 3. The mechanical rebrand (one script)

`scripts/rename_fork.py` rewrites the package name, the CLI entry point, the `ONPREM_DLP_`
env prefix, and the resource ids across the tree in one pass. Preview first, then apply:

```bash
# Preview (writes nothing):
python scripts/rename_fork.py --package acme_dlp --cli acme-dlp \
    --env-prefix ACME --resource acme-dlp --dry-run

# Apply:
python scripts/rename_fork.py --package acme_dlp --cli acme-dlp \
    --env-prefix ACME --resource acme-dlp --yes

# Then recreate the environment (the distribution name changed) and prove it is green:
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
make gate
```

In this repo the CLI name, the distribution name, and the resource stem are the same string
(`onprem-dlp`), so a single kebab id normally covers all three and `--dist` defaults to
`--resource`. Add `--include-docs` to sweep Markdown prose too. The script deliberately does
NOT touch the human decisions below.

## 4. The human decisions (the script can't make these)

1. **Jurisdiction / PII pattern packs.** The built recognizers (SG NRIC/FIN, HK HKID, JP My
   Number, AU TFN/ABN/Medicare, US SSN, plus email, phone, credit card, IBAN, IP, passport,
   date of birth) are code-defined in `domain/recognizers.py` and are **all active at once**.
   Add a pack for your jurisdiction (for example PAN, Aadhaar, NINO, NIK) with a real
   checksum validator where one exists, or trim packs you do not need. A candidate should
   only become a finding once its checksum validates.
2. **Egress policy.** Own the `policy:` section of `config/settings.yaml`: the
   `block_entities` and `redact_entities` lists, the `min_confidence` floor, and
   `block_at_or_above`. The defaults reproduce `EgressPolicy.default()` exactly; they are a
   reference, not your policy. Remember a checksum-valid block-listed identifier forces BLOCK
   regardless of the floor, and BLOCK escalates to a human rather than auto-releasing.
3. **Redaction salt.** The HASH strategy uses `redaction.hash_salt`, overridden at runtime
   by `ONPREM_DLP_REDACTION_HASH_SALT` from `.env.secrets` or the secret manager.
   Salted-hash tokens are pseudonymisation, not anonymisation (the salt holder can
   re-link), so rotate it per deployment. Treat it like a key, as `COMPLIANCE.md` states.
4. **Model profile.** Choose the adapter profile for your recall / footprint trade-off:
   `local` (regex plus checksums only, the default, fully stdlib), `gemma-ollama` or
   `gemma-llamacpp` (a small local Gemma second pass on CPU), or `full` (Presidio NER plus
   Gemma). For a strict air-gap prefer `local` or `gemma-llamacpp` (in-process GGUF, no
   daemon). Models only add advisory candidates; they never make the decision.
5. **Classifier thresholds.** Tune `classifier.pii_threshold`, `classifier.review_threshold`,
   and `classifier.sample_limit` for the structured pipeline against your own data. Ambiguous
   columns flip to `needs_review` rather than guessing.
6. **Reference data is fictional.** Every fixture (`demo/`) and the eval golden set
   (`eval/golden/`) use obviously-fake but checksum-valid identifiers, generated by
   `scripts/generate_demo_data.py`. Rebuild the golden set so it exercises YOUR identifiers,
   or the gate stays green while measuring the wrong thing. **Do not run against live data
   without your own legal, security, and model-risk sign-off.**
7. **Deployment posture.** Review the `Dockerfile` (digest-pinned base, non-root `USER dlp`,
   healthcheck) and how you enforce, at the network layer, that cloud egress actually flows
   through this gate. The gate does not intercept traffic it is not given (see the SPEC
   non-goals); place it inline on the egress path.

## 5. Where this sits in the catalog (and why it consumes nothing)

This repo is one system in a catalog of composable GRC systems, but it is deliberately a
**leaf control**: an air-gapped, CPU-only gate with `dependencies = []` and **zero runtime
egress**. It therefore does NOT consume the sibling platform services, by design rather than
by omission:

- It is the on-prem, sovereign-DLP option that a cloud agent layers **behind** its runtime
  guardrail. The cloud guardrail gateway (**Hrz1** `agent-guardrail-gateway`) is the
  in-cloud control; this gate runs inside the customer estate before anything reaches it.
- Cloud document-diligence agents in the catalog (for example the CDD / Source-of-Wealth
  agent) reference this system as the sovereign-DLP option behind their redaction port. They
  consume it; it consumes nothing from them.
- The catalog commons packages (`hex-service-kit`, `agent-eval-kit`) are **not** adopted
  here: `hex-service-kit` would add a runtime dependency and break the load-bearing
  `dependencies = []` air-gap claim, and an air-gapped gate has no reachable promotion
  authority for `agent-eval-kit` to talk to. `eval/run_eval.py` is the offline gate by
  design. See [`faq/portability-faq.md`](faq/portability-faq.md) for the boundary.

## 6. Adoption checklist

- [ ] Ran `scripts/rename_fork.py`, recreated the venv, `make gate` green.
- [ ] Added or trimmed jurisdiction pattern packs in `domain/recognizers.py`, each with a real checksum where one exists.
- [ ] Owned the `policy:` block / redact lists and confidence floor with your compliance function.
- [ ] Sourced `ONPREM_DLP_REDACTION_HASH_SALT` from `.env.secrets` / your secret manager and set a rotation schedule.
- [ ] Chose the model profile for your air-gap and recall needs.
- [ ] Tuned the classifier thresholds against your own data.
- [ ] Rebuilt the eval golden set and every synthetic fixture for your identifiers.
- [ ] Reviewed the deploy posture (Dockerfile/Helm, NetworkPolicy, audit PVC lifecycle, inline egress enforcement).
- [ ] Recorded your baseline upstream tag so you can take future fixes.
