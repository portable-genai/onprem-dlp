# Security FAQ

For an application-security team reviewing this repo before adopting it as a base. Answers
reflect the current code. Cross-references: [`ARCHITECTURE.md`](../../ARCHITECTURE.md)
(ports, adapters, invariants), [`COMPLIANCE.md`](../../COMPLIANCE.md), [`SPEC.md`](../../SPEC.md)
(non-goals).

### What is the attack surface? Is there an authenticated API?

The primary surface is the `onprem-dlp` **CLI** over local files, plus an **optional**
machine-to-machine REST gate (the `[api]` extra) intended to sit inline on an internal
egress path. There is no web UI, no login flow, and no user accounts. The REST gate is a
stateless scrubber: a request carries `text` and an optional `source_id` label, and there is
**no actor or identity field** to spoof. Any client-asserted actor or ACL is a non-concept
here, so there is nothing to trust or discard.

It authenticates nobody, though, and its four POST routes take the raw personal data a
caller was about to send out. So reachability is the control, and the code enforces it: see
the next answer.

### Does anything bind 0.0.0.0? Is that safe?

Not by default, and not without an explicit acceptance. An internal LB-fronted deployment
is not by itself an enforced topology: nothing in the code requires the load balancer to
exist, so a container bound to `0.0.0.0` with no other guard would put an unauthenticated
write surface on every interface the moment it is run with `-p 8484:8484`. Being air-gapped
by design changes the threat model; it does not license that.

The image entry point resolves its bind through a fail-closed guard
(`src/onprem_dlp/netguard.py`) and binds `127.0.0.1` unless `ONPREM_DLP_API_HOST` names
another host **and** `ONPREM_DLP_ALLOW_UNAUTHENTICATED_EXPOSURE=1` accepts the exposure;
otherwise it exits 2. A bind guard alone would only bind the one entry point that calls it,
so the same rule also rides the app object as ASGI middleware: any non-loopback peer, and
any request carrying a `Forwarded` or `X-Forwarded-For` header, gets HTTP 503 however the
app was served. The Helm chart is the case where the exposure is legitimate (a pod must bind
its pod IP for the Service and kubelet probes), so it accepts it explicitly in values, and
the chart refuses to render if that acceptance is not compensated by the default-deny
NetworkPolicy.

There is no CORS wildcard in any state. `ONPREM_DLP_API_CORS_ORIGINS` grants nothing when
unset or set to empty, and a `*` entry raises rather than being silently dropped.

Model egress is only to a **loopback** Ollama daemon
(`http://127.0.0.1:11434`) under `gemma-ollama`; llama.cpp is in-process. Optional
database samplers make explicit cross-host connections: BigQuery uses ADC over HTTPS,
and MySQL verifies TLS certificates and host identity by default before entering a
read-only transaction. The Helm chart supports only the local profile and denies all
egress unless an adopter supplies a separately reviewed policy.

### What happens if a secret or config variable arrives empty?

It refuses, loudly, at startup. Every environment read resolves three states rather than two:
unset, set-and-empty, set-and-valid. `os.environ.get(name, default)` cannot tell the first
two apart and answers both with the default, which is how a fail-closed default fails open.
Concretely: an emptied `ONPREM_DLP_REDACTION_HASH_SALT` (a Secret key that rendered blank)
would revert to the built-in salt, which is in the public source tree, making every
"pseudonymous" hash token re-linkable by anyone with the repo; an emptied `ONPREM_DLP_AUDIT_LOG`
would disable the evidence trail; an emptied `ONPREM_DLP_PROFILE` would drop back to the weakest
detection profile; an emptied `ONPREM_DLP_MYSQL_PASSWORD` would attempt a passwordless
connection. Each of those raises `ConfiguredEmptyError` naming the variable instead.
`ONPREM_DLP_CONFIG` pointing at a missing file raises too, because a policy file that
silently fails to load means the enforced policy is not the configured one.

The one deliberate exception is `ONPREM_DLP_ALLOW_UNAUTHENTICATED_EXPOSURE`. It is a
*relaxation*, so it fails closed in the opposite direction: it is compared against exactly
`"1"`, and unset and set-to-empty both mean no opt-in. `tests/unit/test_env_single_source.py`
fails the build if a second module reads the environment directly or a two-state read
reappears anywhere.

### What is the core security property of the gate?

**Fail-closed egress.** The egress policy maps entities to a block list and a redact list
with a confidence floor, and a checksum-validated block-listed identifier forces **BLOCK
regardless of the floor** (`egress_policy_service.py`,
`test_block_entity_survives_a_raised_confidence_floor`). BLOCK never auto-releases: it sets
`EgressDecision.escalates` and routes to a human queue. Unknown profiles and un-inferable
samplers raise `ValueError` rather than degrading silently, and the optional models
fail-soft to the deterministic result, never the other way round.

### How do the optional models affect trust?

They cannot lower the bar. Gemma and Presidio only add candidate spans and advisory
verdicts; their confidence is capped below checksum certainty (bounded to about +/-0.15),
hallucinated spans that do not align to real text are dropped, and no model verdict can
release, redact, or block on its own. The deterministic policy engine always makes the final
decision, so a compromised or wrong model degrades recall at worst, never causes a silent
release of a checksum-validated identifier.

### What does the audit trail record? Can it leak PII?

The optional append-only JSONL sink records entity **counts**, spans, and actions, and
**never the raw matched values** (`orchestrator_service.py` `_audit(...)`;
`tests/integration/test_cli.py::test_audit_trail_is_written` asserts a known NRIC string is
absent from the trail). It is a redacted-by-construction record. Honest limit: it is
append-only but **not** hash-chained and has no `verify` / `export` / `restore`; for
tamper-evidence and durability the documented pattern is to ship it to your SIEM, which owns
non-rewritability. This repo does not replace an enterprise WORM audit system.

### Supply chain: are dependencies pinned?

The domain core has **zero** third-party runtime dependencies (`dependencies = []`), so the
smallest install has almost no supply-chain surface. Committed lockfiles pin every optional
install (`requirements-runtime.lock`, `requirements-dev.lock`, both `uv pip compile`
outputs), the Docker base image is digest-pinned (`python:3.12-slim@sha256:...`), the
Dockerfile installs from the lockfile rather than resolving at build time, and
`.github/dependabot.yml` tracks the pip and docker ecosystems. The CI workflow pins
every Action by full commit SHA and runs the exact offline `make gate`; Ruff is pinned
at `0.15.18` in both the manifest and dev lock. A separate networked job runs exactly pinned
`pip-audit==2.10.1` strictly over both fully pinned runtime and development locks with dependency
resolution disabled.
GitHub account billing/spending controls currently block hosted execution before job steps start,
so retained hosted evidence still requires that manual account action.

### Where are secrets? Are any committed?

No real secret material is committed. Real `.env` and `.env.secrets` files are
ignored; tracked examples separate non-secrets from secrets. The redaction salt is
injected with `ONPREM_DLP_REDACTION_HASH_SALT` from `.env.secrets` or a Kubernetes
Secret. Salted-hash tokens are pseudonymisation, not anonymisation, so rotate it per
deployment and materialize it from the approved secret manager.

### What is explicitly out of scope / a residual risk?

- **Recall is not 100%.** Regex plus checksum misses unformatted or novel identifiers;
  PERSON / ADDRESS recall needs the Gemma or `full` profile; OCR misses low-quality scans.
  Treat the gate as risk reduction, not a guarantee, and keep cloud-side controls layered
  behind it.
- **The gate only sees what it is given.** It does not intercept traffic on its own; you must
  enforce at the network layer that cloud egress flows through it.
- **The audit sink needs your SIEM** for tamper-evidence and durability.
- This is a reference build: run your own pen-test, threat model, and model-risk review
  before any live-data deployment.
