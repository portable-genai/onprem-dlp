"""A7: the kernel/vertical split is a real dependency direction, not a label.

The claim SPEC.md makes is that a fork inherits the deterministic detection, checksum,
redaction, egress-decision, column-profiling and evidence machinery untouched, and rewrites
only the jurisdiction recognizer packs and the bank policy. That claim is worth nothing if
the shared machinery and the jurisdiction/policy artifacts sit in the same module: naming a
boundary is not enforcing one.

So the primary assertion here is executed, not read. A fresh interpreter imports
``onprem_dlp.domain.kernel`` and reports which package modules ended up in ``sys.modules``.
If the kernel drags ``onprem_dlp.domain.models`` in, the fork boundary is decorative and this
test is RED. It was verified RED against a re-export shim before the physical split landed.
"""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest

from onprem_dlp.domain import kernel, models

SRC = Path(__file__).resolve().parents[2] / "src"
KERNEL_PATH = SRC / "onprem_dlp" / "domain" / "kernel.py"

# The vertical-neutral machinery A7 requires a fork to inherit untouched.
KERNEL_NAMES = (
    "AdjudicationVerdict",
    "AppliedRedaction",
    "AuditEvent",
    "ColumnCategory",
    "ColumnClassification",
    "ColumnProfile",
    "DatasetClassification",
    "EgressAction",
    "EgressDecision",
    "EgressReason",
    "Finding",
    "ImageScanResult",
    "OcrResult",
    "OcrWord",
    "OpenLabel",
    "PixelBox",
    "RedactedText",
    "RedactionStrategy",
    "Severity",
    "Signal",
    "TextScanResult",
    "utcnow",
)

# The adopter-owned jurisdiction and policy artifacts a fork rewrites. None may live
# in the kernel: the jurisdiction label pack, the identifiability judgement over it, and
# the bank egress policy are exactly what changes per adopter.
VERTICAL_NAMES = (
    "DIRECT_IDENTIFIERS",
    "EgressPolicy",
    "EntityType",
)


def _import_probe(module: str) -> list[str]:
    """Import ``module`` in a FRESH interpreter and report what it pulled in."""
    program = (
        "import json, sys\n"
        f"import {module}\n"
        "print(json.dumps(sorted(m for m in sys.modules if m.startswith('onprem_dlp'))))\n"
    )
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", program],
        capture_output=True,
        text=True,
        cwd=str(SRC),
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout.strip().splitlines()[-1])


def test_importing_the_kernel_does_not_import_the_vertical_models() -> None:
    """Executed proof of the dependency direction, in a process of its own."""
    imported = _import_probe("onprem_dlp.domain.kernel")
    assert "onprem_dlp.domain.kernel" in imported
    assert "onprem_dlp.domain.models" not in imported, (
        "importing the kernel pulled the vertical model module in; the split is a label, "
        f"not a boundary (imported: {imported})"
    )


def test_the_vertical_models_do_import_the_kernel() -> None:
    """The arrow must exist in the other direction, or nothing is actually shared."""
    imported = _import_probe("onprem_dlp.domain.models")
    assert "onprem_dlp.domain.kernel" in imported


def test_kernel_source_has_no_intra_package_imports() -> None:
    """Static backstop: the kernel depends on the standard library and nothing else here."""
    tree = ast.parse(KERNEL_PATH.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert node.level == 0, f"kernel makes a relative import of {node.module!r}"
            assert not (node.module or "").startswith("onprem_dlp"), node.module
        elif isinstance(node, ast.Import):
            for alias in node.names:
                assert not alias.name.startswith("onprem_dlp"), alias.name


@pytest.mark.parametrize("name", KERNEL_NAMES)
def test_kernel_names_are_defined_in_the_kernel_and_re_exported(name: str) -> None:
    """Backward-compatible re-exports keep every existing import site working unchanged."""
    assert hasattr(kernel, name), f"{name} is not in the kernel"
    assert getattr(models, name) is getattr(kernel, name), (
        f"models.{name} is not the same object as kernel.{name}"
    )


@pytest.mark.parametrize("name", VERTICAL_NAMES)
def test_vertical_artifacts_stay_out_of_the_kernel(name: str) -> None:
    assert hasattr(models, name)
    assert not hasattr(kernel, name), f"{name} is vertical and must not sit in the kernel"
