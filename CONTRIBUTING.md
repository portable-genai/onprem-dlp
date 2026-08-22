# CONTRIBUTING

## Non-negotiable conventions

1. **Keep the domain pure.** Nothing under `src/onprem_dlp/domain/` imports an SDK, a
   web framework, a validation lib, or does I/O. Stdlib only. If a feature needs the
   outside world, define a port (`typing.Protocol` in `ports/__init__.py`) and put the
   implementation in `adapters/`.
2. **Heavy imports are lazy.** Adapter modules must import cleanly on a bare Python
   install; `import presidio_analyzer`, `PIL`, `psycopg`, `llama_cpp` happen inside
   methods, never at module top level.
3. **Deterministic decisions.** No clock reads, randomness or network in anything
   that scores, classifies, redacts or decides. Tunables are dataclass fields with
   defaults, mirrored in `config/settings.yaml`.
4. **Models never decide.** LLM/NER output is a candidate or an advisory verdict with
   bounded influence. If your feature lets a model redact, block, release or
   classify unilaterally, it will not merge.
5. **Every adapter satisfies its Protocol:** add it to `tests/contract/test_ports.py`.
6. **No real personal data anywhere:** fixtures use synthetic, checksum-valid values
   (see `scripts/generate_demo_data.py`).

### Extension touch lists

Adding an adapter requires its `AdapterSettings` constructor, profile/global binding, Protocol
conformance assertion and behavior test. Adding a port or sub-service requires updating
`ports/__init__.py`, every applicable binding, `Container` composition, orchestration and CLI/API
surface, structural and behavioral contract tests, configuration docs, golden evaluation and the
portability/demo evidence. A jurisdiction pack additionally updates the recognizer selector,
fictional positives and negatives, the block-safety metric when consequential, and the adopter
crosswalk.

## Delivery loop (vertical slices)

One feature = one slice = model → service → orchestrator → CLI/API surface → demo →
docs → tests, shipped green. Do not hardcode counts in docs ("the N ports"); enumerate
by name.

## Gate

```bash
make gate   # exact Ruff + pytest + English/Japanese eval; must be green before any PR
make dependency-audit  # strict networked check over the pinned runtime and dev locks
```

The vulnerability audit is deliberately separate because advisory lookup needs network
access. A release needs both gates; air-gapped development can still run `make gate`
without weakening the deterministic product contract.

Adding a recognizer? Add: validator unit tests (valid + near-miss), a golden-set
positive AND a trap negative, and a `settings.yaml` policy-list decision (block or
redact) with a sentence of rationale in SPEC.md.
