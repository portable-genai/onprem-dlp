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
dependency-audit:
	$(PY) -m pip_audit --strict --requirement requirements-runtime.lock --no-deps --disable-pip --progress-spinner off
	$(PY) -m pip_audit --strict --requirement requirements-dev.lock --no-deps --disable-pip --progress-spinner off

lint:
	$(PY) -m ruff check src tests eval scripts
	$(PY) -m ruff format --check src tests eval scripts

clean:
	rm -rf .venv .pytest_cache dist build
