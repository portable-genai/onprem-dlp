# Portability FAQ

For architecture, air-gap, and exit-planning teams. The claim this repo makes is "runs
anywhere Python runs, with nothing but Python", and it is designed to be *shown*, not
asserted. Cross-references: [`ARCHITECTURE.md`](../../ARCHITECTURE.md) (ports and adapters),
[`docs/onprem-migration.md`](../onprem-migration.md), [`README.md`](../../README.md) (install
matrix).

### What does "portable" actually mean here?

The load-bearing claim is `dependencies = []`: the deterministic domain core, the local
profile, the CLI, CSV / SQLite sampling, and the Ollama-Gemma adapter install and run on an
**air-gapped, CPU-only** host with nothing but a Python interpreter. There is no mandatory
cloud SDK or managed service, and the local profile has **zero runtime egress**. Everything
heavier (Presidio NER, Tesseract OCR, Pillow, the REST API, PostgreSQL/MySQL/BigQuery
sampling) is an opt-in, lazily imported extra; the BigQuery SDK is never installed or
imported by the offline gate.

### How does the profile switch work?

The pure-domain core speaks only to `typing.Protocol` **ports**; adapters implement them, and
`config/settings.yaml` binds one adapter per port per profile as a dotted `module:Class` plus
kwargs. Setting `ONPREM_DLP_PROFILE` (or `profile:` in the settings, or `--profile`) rebinds
the model stack with **no domain edits**:

- `local`: regex plus checksums only, stdlib, always works. The default for dev / test / CI.
- `gemma-ollama`: adds a small Google Gemma second pass via a loopback Ollama daemon.
- `gemma-llamacpp`: the same Gemma pass in-process from a GGUF file (no daemon, strict
  air-gap).
- `full`: Microsoft Presidio NER plus Gemma for the best PERSON / ADDRESS recall.

The contract test (`tests/contract/test_ports.py`) proves each shipped adapter satisfies its
Protocol, and the offline suite imports every module on a bare interpreter with no models
installed.

### Is this the same "four profiles" as the cloud agents in the catalog?

No, and that distinction matters for portability. The cloud hexagonal agents vary a *backend*
(managed cloud / offline / platform / on-prem placeholder). Here the profiles vary a *local
model stack* (regex-only up to regex-plus-Presidio-plus-Gemma). This system **is itself the
on-prem endpoint**, so a managed-cloud or platform-HTTP profile would contradict its reason
to exist. The load-bearing portability property, a one-config profile swap with zero domain
edits, holds; the cloud profile *taxonomy* simply does not apply.

### Why are the shared "commons" packages not adopted?

Deliberately, not by omission. The catalog's shared commons (`hex-service-kit`,
`agent-eval-kit`) are not consumed here:

- `hex-service-kit` would be a **runtime dependency** of the domain core, which breaks the
  load-bearing `dependencies = []` claim. One dependency ends the "runs air-gapped with
  nothing but Python" guarantee. The kit's primitives (StrEnum vocabularies, hash-chained
  audit, fail-closed bind) remain available as reference implementations to mirror by hand if
  a gap is ever closed here.
- `agent-eval-kit` is not applicable: an air-gapped gate has no reachable promotion authority
  to talk to, so `eval/run_eval.py` is the offline gate by design.

### How do we get data out? Is there lock-in?

There is nothing to lock in. Findings, egress decisions, redacted text, and column
classifications all serialise to plain JSON via the CLI `--json` flag, so any downstream
system reads them without this package. The audit sink is line-delimited JSON you can copy or
ship to a SIEM. The exit story is "copy the files"; there is no proprietary store to migrate.

### How is on-prem / air-gapped operation proven rather than claimed?

The whole gate (`make gate` = exact Ruff, pytest, and `eval/run_eval.py`) runs fully
offline with zero secrets and passes: English/Japanese precision / recall and
structured column accuracy score
against a synthetic golden set that shares exactly one pattern source (`recognizers.py`) with
the runtime, so it cannot go falsely green. The `local` profile needs no models at all, and
the `gemma-llamacpp` profile runs a quantised model in-process from a local GGUF with no
network. See [`docs/onprem-migration.md`](../onprem-migration.md) for the deployment notes.

### What is NOT portable / a residual?

Remote database adapters are intentionally not exercised by the offline gate; an
adopter must integration-test its MySQL/PostgreSQL TLS policy or BigQuery identity
against an authorized non-production source. The SHA-pinned CI workflow proves the
SDK-free local profile and deterministic gate, not external connectivity.
