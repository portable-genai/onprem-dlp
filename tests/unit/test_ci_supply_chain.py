"""Supply-chain CI wiring cannot silently lose the pinned vulnerability gate."""

from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]


def test_ci_runs_separate_locked_dependency_audit() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "ci.yaml").read_text()
    makefile = (_ROOT / "Makefile").read_text()
    development_lock = (_ROOT / "requirements-dev.lock").read_text()
    runtime_lock = (_ROOT / "requirements-runtime.lock").read_text()
    action_references = re.findall(r"^\s*uses:\s*(\S+)", workflow, flags=re.MULTILINE)

    assert "dependency-audit:" in workflow
    assert "make dependency-audit PY=python" in workflow
    assert "python -m pip install --disable-pip-version-check -r requirements-dev.lock" in workflow
    assert action_references
    assert all(re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", reference) for reference in action_references)
    assert "pip-audit==2.10.1" in development_lock
    assert "fastapi==" in runtime_lock
    for lock_name in ("requirements-runtime.lock", "requirements-dev.lock"):
        assert (
            f"$(PY) -m pip_audit --strict --requirement {lock_name} "
            "--no-deps --disable-pip --progress-spinner off"
        ) in makefile
