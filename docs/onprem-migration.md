# On-prem posture & portability

Most systems in this catalog document how to *migrate off* managed cloud services.
This system is different: **it is on-prem-native by design**. Its entire purpose is
to run inside the estate, before any cloud boundary. There is nothing to migrate off:

- zero mandatory third-party dependencies; the core is Python stdlib;
- all engines are local CPU processes: regex/checksums (in-process), Gemma via
  Ollama/llama.cpp (localhost), Presidio/spaCy (in-process), Tesseract (host binary);
- no telemetry, no phone-home, no model download at runtime (models are pulled once
  from your artefact mirror).

## Portability directions that DO apply

**Air-gapped hardening:** use the `gemma-llamacpp` profile (no daemon), pip-install
from an internal index, copy the GGUF from the mirror. The `local` profile needs only
the Python runtime.

**Scaling out:** the gate is stateless; run N containers behind a LB; ship each
audit JSONL to the SIEM. SQLite/CSV sampling happens where the data lives; for
PostgreSQL/MySQL, point at a read replica with a read-only role. BigQuery uses ADC
or workload identity and bounded, deterministically ordered `SELECT` queries.

**Moving INTO the cloud (reverse exit):** if a workload later runs inside a
sovereign/VPC-SC perimeter, the same container runs unchanged on GKE/Cloud Run; the
optional BigQuery adapter sits behind the same `ColumnSampler` port, while `agent-guardrail-gateway`'s
Cloud-DLP-based gateway becomes a second, cloud-side layer behind this one. The
Google SDK is never part of the core or offline gate.

**Kubernetes:** the Helm chart under `deploy/helm/onprem-dlp` is infrastructure
neutral. Its default local profile denies all pod egress, runs non-root with a
read-only root filesystem, drops Linux capabilities, disables service-account
token mounting, and persists the audit trail. This is packaging, not a deployment;
cluster storage, ingress identity, and SIEM lifecycle remain adopter-owned.
The chart deliberately rejects Gemma/Presidio profiles until a deployment-specific
image, model mount/endpoint, network policy, and engine-readiness probe are supplied.

**Model substitution:** the Gemma adapters implement the same ports as Presidio and
the null engines. Swapping to any other local model (a different Gemma size, a
future small model) is a `settings.yaml` binding change plus the standard eval gate;
no domain code changes, by construction.
