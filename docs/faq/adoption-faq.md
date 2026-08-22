# Adoption FAQ

For an engineering lead forking this repo as their institution's DLP gate. The step-by-step
is [`docs/ADOPTING.md`](../ADOPTING.md); this answers the "will it hurt later?" questions.

### How do I rebrand it for my institution?

`scripts/rename_fork.py` rewrites the package name, the CLI entry point, the `ONPREM_DLP_`
env prefix, and the resource ids in one pass (preview with `--dry-run`, apply with `--yes`).
Then recreate the venv, `pip install -e ".[dev]"`, and run `make gate`. In this repo the CLI
name, distribution name, and resource stem are the same string (`onprem-dlp`), so one kebab
id normally covers all three and `--dist` defaults to `--resource`. The script does the
mechanical rename; the human decisions (jurisdiction packs, egress policy, hash salt, model
profile, fixtures, golden set) are the checklist in `ADOPTING.md`.

### If several banks fork this, how does each take upstream fixes?

Track upstream via **git tags** (semver). The repo declares a **core-vs-adopter-owned boundary** (ADOPTING section 2): upstream
owns the domain service mechanics, `ports/`, `tests/contract/`, the eval harness mechanics,
and the `config.py` container wiring; you own the `config/settings.yaml` values, the
recognizer pattern packs for your jurisdictions, the fixtures, the eval golden set, and the
`COMPLIANCE.md` regulator rows. Rebase your adopter-owned changes onto each release rather
than merging `main` continuously, so conflicts stay in files you were told to expect. Note
this repo has **no remote**, so "upstream" is whatever base you cloned from.

### How do I add a recognizer for my jurisdiction?

The touch list is in [`CONTRIBUTING.md`](../../CONTRIBUTING.md) ("Adding a recognizer"): add
the regex plus a real checksum validator to `domain/recognizers.py`, add the entity to the
`EntityType` taxonomy, add a golden positive **and** a trap negative to the eval set (a
checksum-failing candidate must not become a finding), and decide whether the entity goes on
the block or redact list in `config/settings.yaml`. Because the eval imports the same
`recognizers.py` the runtime uses, a recognizer that is wrong shows up as a red gate rather
than a false green. The bundled packs (SG / HK / JP / AU / US) are always active; trim the
ones you do not need.

### How do I add a new adapter (a new model or sampler)?

Adapters bind to `@runtime_checkable` Protocols in `ports/` and are constructed from config,
not code. Implement your adapter (for example a different NER engine or a new column
sampler), add its dotted `module:Class` plus kwargs under the relevant `profiles:` entry (or
the top-level `ner` / `ocr` / `sampler` bindings) in `config/settings.yaml`, and keep heavy
imports inside methods so the bare `local` profile still imports on an air-gapped host. The
contract test (`tests/contract/test_ports.py`) fails if a shipped adapter does not satisfy
its Protocol. Heads-up: the contract test enforces *structural* parity but does not yet assert
the port list equals the settings bindings, so double-check you bound every port.

### How do I retune the policy without touching code?

Everything a compliance function owns lives in `config/settings.yaml`: the `policy:` block /
redact entity lists, `min_confidence`, and `block_at_or_above`; the `detection:` floor; the
`redaction:` strategies and `hash_salt`; and the `classifier:` thresholds. The defaults
reproduce `EgressPolicy.default()` exactly, and `tests/unit/test_config.py` proves both that
the defaults reproduce reference behaviour and that overrides change it. Source the
`ONPREM_DLP_REDACTION_HASH_SALT` from your secret manager via `.env.secrets` or the
configured Kubernetes Secret.

### Can I extend the entity taxonomy purely by config?

Not today, and this is an honest limitation. `EntityType`, `ColumnCategory`, and
`RedactionStrategy` are string-valued enums, but the vocabulary is **closed**: the engines are
typed on `EntityType` and `config.py` calls `EntityType(e)`, which rejects unknown values. A
new entity therefore needs an enum edit plus a recognizer, not a config line alone. Plan a
small code change when you add a jurisdiction.

### Does the gate run for my fork out of the box?

`make gate` (pytest plus the offline eval) runs on the `local` profile with **no models, no
network, and no secrets**, so a fresh clone is green immediately. The SHA-pinned CI workflow
runs the same `make gate` on every push and pull request. Note the
eval measures the *reference* identifiers until you rebuild the golden set for your own
jurisdictions; that is an explicit adoption step, not a silent pass.
