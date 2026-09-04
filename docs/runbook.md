# Runbook: operating the on-prem DLP gate

## Deploy

**Container (recommended):**
```bash
docker build -t onprem-dlp .
docker run -d --name dlp -p 127.0.0.1:8484:8484 \
  -v /etc/onprem-dlp/settings.yaml:/app/config/settings.yaml:ro \
  -v /var/log/onprem-dlp:/var/log/onprem-dlp \
  onprem-dlp
curl -s localhost:8484/healthz    # {"status":"ok","profile":"local"}
```

### Exposing the REST gate beyond loopback

The gate authenticates nobody, so it binds `127.0.0.1` and refuses non-loopback callers
until an operator says otherwise. That is deliberate: the four POST routes accept the raw
personal data a caller was about to send to the cloud, so reachability is the whole control.

To put it inline on an internal path, set both, and only where a network control (an
internal load balancer with its own authentication, a NetworkPolicy, a host firewall) is the
compensating boundary:

```bash
docker run -d --name dlp -p 8484:8484 \
  -e ONPREM_DLP_API_HOST=0.0.0.0 \
  -e ONPREM_DLP_ALLOW_UNAUTHENTICATED_EXPOSURE=1 \
  onprem-dlp
```

Without the acceptance the container exits 2 with a message naming the variable, rather
than starting in a state you did not choose. The guard also runs per request, so serving
the app some other way (`uvicorn ... --host 0.0.0.0` by hand) refuses non-loopback peers
with HTTP 503 instead of quietly serving them. A request arriving with an
`X-Forwarded-For` or `Forwarded` header is refused on the same rule: a proxy in front means
the loopback peer is the proxy, not the client.

Browser callers, if you ever have any, need `ONPREM_DLP_API_CORS_ORIGINS` set to the exact
origins. It is never a wildcard: `*` is refused, not silently dropped. Unset and
set-to-empty both mean no origin is trusted.

**Configuration reads fail closed.** `ONPREM_DLP_REDACTION_HASH_SALT`,
`ONPREM_DLP_AUDIT_LOG`, `ONPREM_DLP_AUDIT_RETENTION_DAYS`, `ONPREM_DLP_CONFIG`,
`ONPREM_DLP_PROFILE`, `ONPREM_DLP_API_HOST`, `ONPREM_DLP_API_PORT` and
`ONPREM_DLP_MYSQL_PASSWORD` distinguish "unset" from "set to nothing". A variable present
but empty is a configuration error and refuses at startup: an empty salt injected by a
misprovisioned secret used to revert to the built-in public default and make every
pseudonymous token re-linkable. If a Secret or ConfigMap renders empty you now get an
immediate, named failure instead of a silently weakened gate. `ONPREM_DLP_CONFIG` pointing
at a file that does not exist refuses for the same reason: the policy you configured would
not be the policy enforced.

**With Gemma (CPU):** run Ollama on the same host (`ollama pull gemma3:1b`,
`OLLAMA_HOST=127.0.0.1`), set `profile: gemma-ollama`. Budget ~2 GB RAM for the 1b
model; `gemma3:4b` (~3.3 GB) raises NER recall on beefier hosts. Air-gapped hosts:
use the `gemma-llamacpp` profile with a GGUF copied from your artefact mirror.

**Enforce the path:** firewall/proxy rules must force LLM-bound traffic through the
gate (the gate inspects what it is given; it is not a packet sniffer).

### Kubernetes / Helm (future deployment)

The chart is code-complete under `deploy/helm/onprem-dlp`; this repository does not
apply it. Prepare local inputs without committing them:

```bash
cp .env.example .env
cp .env.secrets.example .env.secrets
# Replace every REPLACE_WITH_* value, then source only in an approved shell.
set -a; . ./.env; . ./.env.secrets; set +a

kubectl -n "$ONPREM_DLP_K8S_NAMESPACE" create secret generic onprem-dlp-secrets \
  --from-env-file=.env.secrets --dry-run=client -o yaml
helm lint deploy/helm/onprem-dlp
helm template onprem-dlp deploy/helm/onprem-dlp \
  --namespace "$ONPREM_DLP_K8S_NAMESPACE" \
  --set image.repository="$ONPREM_DLP_IMAGE_REPOSITORY" \
  --set image.tag="$ONPREM_DLP_IMAGE_TAG"
```

The `kubectl` command intentionally omits `| kubectl apply -f -`; add it only in an
approved future deployment workflow. In production, materialize the same keys from
the approved secret manager instead of retaining a workstation file.

Secure defaults: local profile, no egress, same-namespace ingress only, non-root,
read-only root filesystem, all capabilities dropped, service-account token disabled,
health probes, resource limits, PDB, and a persistent audit volume. The default
single replica avoids concurrent writers on a `ReadWriteOnce` audit PVC. To scale,
send audit events to the SIEM or use an approved RWX layout and validate append
semantics first.

The chart intentionally accepts only `profile: local`. The current image does not
package Gemma/Presidio model assets, mount a GGUF, define an Ollama dependency, open
model egress, or probe engine readiness. Advertising those profiles would produce a
healthy API with missing inference capability. Deploy model profiles only through a
separately reviewed chart/image overlay that implements all of those contracts.

## Configure

Everything lives in `config/settings.yaml` (or a JSON equivalent;
`ONPREM_DLP_CONFIG` points elsewhere). The three knobs that matter operationally:

| Knob | Effect of raising it |
|---|---|
| `detection.min_confidence` | fewer, surer findings (less noise, more leak risk) |
| `policy.min_confidence` | gate ignores weaker findings (same trade-off at decision time) |
| `classifier.review_threshold` / `pii_threshold` | widens/narrows the human-review band |

**Change `redaction.hash_salt` per deployment** and treat it as a secret (it is what
keeps hash tokens unlinkable across sites).

Policy lists (`block_entities`, `redact_entities`) are the DPO's dial: start strict
(national IDs, PANs, TFNs in `block`), loosen per approved use case.

Secrets belong in `.env.secrets` locally and in the cluster secret manager at
runtime. Non-secrets belong in `.env`. The tracked `*.example` files define the
required names; real `.env` and `.env.secrets` files are ignored. The redaction salt
is consumed through `ONPREM_DLP_REDACTION_HASH_SALT`, and a MySQL password may be
supplied through `ONPREM_DLP_MYSQL_PASSWORD` so it never appears in the DSN.

Remote structured sources:

| Source | URI | Read-only/determinism control |
|---|---|---|
| PostgreSQL | `postgresql://user@host/database?sslmode=verify-full&sslrootcert=/etc/ssl/certs/bank-ca.pem` | verified server identity and adopter CA; read-only transaction; bounded sample |
| MySQL | `mysql://user@host/database?ssl_ca=/path/ca.pem&ssl_verify_cert=true&ssl_verify_identity=true` | TLS certificate/identity verification defaults true; strict TLS option allowlist; read-only transaction; binary metadata ordering and full-value SHA-256/byte-length/hex sample ordering; explicit rollback/close |
| BigQuery | `bigquery://project/dataset` (domain-scoped legacy IDs: `bigquery://example.com:legacy-project/dataset`) | strict URI: one decoded dataset component, no userinfo/numeric port/query/fragment; ADC/workload identity; metadata-validated identifiers; JSON-ordered sample |

## Monitor

- Audit trail: set `audit_log: /var/log/onprem-dlp/audit.jsonl`; ship to the SIEM.
  Events carry entity counts and actions, never raw values.
- Audit retention defaults to **180 days (six months)**. The application writer is
  append-only and does not destroy or rewrite evidence, so enforce the 180-day
  archive/delete lifecycle on the PVC backend and SIEM. The chart records the target
  as configuration and resource annotations for policy checks.
- Watch the **BLOCK rate** (spikes = a new upstream data source is leaking into
  prompts) and the **needs_review queue length** (columns awaiting a human verdict).
- `healthz` returns the active profile; alert if a prod gate reports `local` when
  `full` is mandated.

## Routine tasks

| Task | How |
|---|---|
| Add an entity to the block list | edit `policy.block_entities`, restart, re-run `make eval` |
| Re-scan a schema after migration | `onprem-dlp classify-columns <dsn> --json > snapshot.json`; diff against the previous snapshot in review |
| Regenerate demo data | `python scripts/generate_demo_data.py` |
| Upgrade Gemma | `ollama pull gemma3:1b` (new tag), canary one gate, watch precision on `make eval` |
| Verify Japanese recall | `python eval/run_eval.py`; inspect the separate `unstructured/ja` line |
| Render the Kubernetes package | `helm lint deploy/helm/onprem-dlp && helm template onprem-dlp deploy/helm/onprem-dlp` |

The eval rejects empty, positive-only, and negative-only golden files. It compares
findings as multisets, so duplicated PII cannot disappear behind set deduplication.
Date-of-birth recognition also validates the actual calendar date (including leap
years), not only its shape.
| Release a BLOCKed payload | human reviews the reasons in the audit trail; if approved, send the `redact-text` output, never the original |

## Incidents

**Suspected leak (finding missed):** capture the payload hash from the caller's logs,
reproduce with `onprem-dlp scan-text --json`, add the miss to
`eval/golden/text_golden.jsonl` as a failing case, fix (recognizer/context/threshold),
re-run `make gate`, then follow `breach-reportability-assessor` breach-assessment for the disclosure itself.

**False-positive storm (business blocked):** identify the recognizer via the
`recognizer` provenance on the findings; raise its floor via `policy.min_confidence`
or narrow its context words; add the FP text as a golden negative so it cannot
regress.

**Ollama down:** gate keeps running deterministically (fail-soft); NER recall drops
and ambiguous columns queue for humans. Restore the daemon; no restart of the gate
needed.

## Hosted CI

Cloud Build runs this repository's `dependency-audit` and `offline-gate` jobs on every pull
request and every push to `main`, from the reviewed job contract in the catalog's
`ci/gcp/repository-policy.json`. The build only builds and tests: it holds no deploy authority
and cannot reach this system's runtime.
