PY ?= .venv/bin/python

.PHONY: setup test eval demo gate dependency-audit lint clean

setup:
	uv venv .venv
	uv pip install -p .venv -e '.[dev]'

test:
	$(PY) -m pytest

eval:
	$(PY) eval/run_eval.py

demo:
	$(PY) -m onprem_dlp.cli.main scan-text --file demo/sample_support_email.txt
	-$(PY) -m onprem_dlp.cli.main decide --file demo/sample_support_email.txt
	$(PY) -m onprem_dlp.cli.main redact-text --file demo/sample_support_email.txt
	$(PY) -m onprem_dlp.cli.main classify-columns demo/customers.csv

# The green gate: exact Ruff, tests, evaluation and portability proof. It performs
# no network calls and imports no optional database/cloud SDKs.
portability:
	$(PY) scripts/portability_demo.py

gate: lint test eval portability

# Networked supply-chain gate. Keep separate so `make gate` remains air-gap runnable.
#
# The dev lock carries a direct reference (`agent-eval-kit @ git+...`), and pip-audit refuses
# the WHOLE file when it meets one rather than skipping the line, so the commons pins are
# filtered out and audited where they live: each is pinned to an exact commit in this
# organization and gated by its own repository. Everything a pin PULLS IN is still an ordinary
# versioned line in this lock and is still audited here. The filtered copy is written outside
# the tree because CI mounts the workspace read-only.
DEV_LOCK_AUDIT := $(shell mktemp -t onprem-dlp-dev-lock.XXXXXX)

dependency-audit:
	$(PY) -m pip_audit --strict --requirement requirements-runtime.lock --no-deps --disable-pip --progress-spinner off
	grep -v '@ git+' requirements-dev.lock > $(DEV_LOCK_AUDIT)
	$(PY) -m pip_audit --strict --requirement $(DEV_LOCK_AUDIT) --no-deps --disable-pip --progress-spinner off
	rm -f $(DEV_LOCK_AUDIT)

lint:
	$(PY) -m ruff check src tests eval scripts
	$(PY) -m ruff format --check src tests eval scripts

clean:
	rm -rf .venv .pytest_cache dist build
