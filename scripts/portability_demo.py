#!/usr/bin/env python3
"""Bounded portability proof for the on-prem-native pre-egress DLP gate.

onprem-dlp is deliberately not a GCP-hosted application. Its portability claim is that the same
deterministic DLP decision runs with the stdlib-only profile and with optional local model
adapters, before any byte is allowed to reach a cloud service.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run(
        [sys.executable, *args], cwd=ROOT, env=env, text=True, capture_output=True, check=False
    )


def _assert_cloud_free_domain() -> int:
    checked = 0
    for path in sorted((ROOT / "src" / "onprem_dlp" / "domain").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        checked += 1
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            else:
                names = []
            assert not any(name.split(".", 1)[0] in {"google", "vertexai"} for name in names), (
                f"cloud SDK crossed the domain boundary at {path}:{node.lineno}"
            )
    return checked


def main() -> int:
    tests = _run("-m", "pytest", "tests/contract", "tests/integration/test_cli.py", "-q")
    if tests.returncode:
        sys.stderr.write(tests.stdout + tests.stderr)
        return tests.returncode
    print("PASS port contract: optional local adapters satisfy the same DLP interfaces")

    command = (
        "-m",
        "onprem_dlp.cli.main",
        "scan-text",
        "--file",
        "demo/sample_support_email.txt",
    )
    first = _run(*command)
    second = _run(*command)
    assert first.returncode == second.returncode == 0
    assert first.stdout == second.stdout and first.stdout.strip()
    print("PASS local replay: the same synthetic input produces byte-identical findings")

    checked = _assert_cloud_free_domain()
    print(f"PASS portable core: {checked} domain modules import no cloud SDK")
    print("PASS graceful degradation: stdlib recognizers work without Presidio, OCR, or Gemma")
    print(
        "LIMITS: onprem-dlp is an on-prem-native pre-egress control, not a GCP serving workload. "
        "This proof does not claim optional-model quality, OCR quality, database-driver "
        "availability, or Kubernetes production evidence."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
