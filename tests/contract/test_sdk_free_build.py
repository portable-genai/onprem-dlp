"""EVERY profile, and every sampler, builds where the cloud SDKs cannot be imported.

Not "no SDK installed on this machine": ``tests/contract/_sdk_free_probe.py`` installs a
meta-path finder that refuses the ``google`` and ``vertexai`` roots, then constructs every
adapter of the profile in a fresh process. Proving the claim by absence would tie it to the
developer machine: one with the SDK installed would pass while hiding an eager import that
breaks the air-gapped install everywhere else.

This repository has no managed adapter FAMILY. It is the on-premises gate, every profile is
meant to run air-gapped, and its single point of contact with a cloud SDK is
:class:`BigQuerySampler`, which imports ``google.cloud.bigquery`` inside the method that first
connects. Elsewhere in the catalog that laziness went unenforced because the probe constructed
only the profiles nobody expected to need an SDK, so the managed modules were never imported at
all and a hoisted import passed the whole suite. The same hole here is a sampler the probe
never builds: samplers are bound by no profile, they come from ``Container.sampler`` routing on
a caller's source string, so the probe walks every branch of that router as a case of its own
and this file asserts the BigQuery sampler was among the adapters it constructed. Proved by
hoisting that import to module scope and watching the sampler case fail alone.

The parity suite next door proves the adapters satisfy their Protocols in-process; this file
proves every one of them imports and constructs under prohibition.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from tests.contract._sdk_free_probe import CONFIG_PATH, SAMPLER_SOURCES

from onprem_dlp.config import load_settings

REPO_ROOT = Path(__file__).resolve().parents[2]

#: Every profile the settings file binds, discovered rather than restated, so a profile added
#: to the binding table is proved from the moment it exists instead of when somebody remembers
#: this list. A hand-written tuple here is how a new profile would go unproved for a release.
ALL_PROFILES = tuple(sorted(load_settings(str(REPO_ROOT / CONFIG_PATH))["profiles"]))

#: Every sampler ``Container.sampler`` can return. ``InlineSampler`` is absent on purpose: it
#: is built from an in-memory mapping by the caller, never from a source string, so the router
#: cannot reach it.
ROUTED_SAMPLERS = (
    "BigQuerySampler",
    "CsvSampler",
    "MySqlSampler",
    "PostgresSampler",
    "SqliteSampler",
)


def _run_probe(argument: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "tests.contract._sdk_free_probe", argument],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env={**os.environ, "PYTHONPATH": "src"},
        check=False,
        timeout=300,
    )


@pytest.mark.parametrize("profile", ALL_PROFILES)
def test_the_profile_constructs_with_the_cloud_sdks_blocked(profile: str) -> None:
    completed = _run_probe(profile)
    assert completed.returncode == 0, (
        f"the {profile} profile could not be built with the cloud SDKs blocked:\n"
        f"{completed.stdout}\n{completed.stderr}"
    )
    assert "no cloud SDK importable" in completed.stdout


def test_every_sampler_constructs_with_the_cloud_sdks_blocked() -> None:
    """The BigQuery sampler is the only place this repo's lazy-import rule can be broken.

    Every other adapter would pass this suite with the rule deleted, so a probe that stopped
    constructing this one would keep four green profiles while proving nothing at all. The
    assertion is on the class names the probe reports having BUILT, not on the source list,
    because a source string that no longer routes to the sampler is the same silent loss.
    """
    completed = _run_probe("--samplers")
    assert completed.returncode == 0, (
        f"the samplers could not be built with the cloud SDKs blocked:\n"
        f"{completed.stdout}\n{completed.stderr}"
    )
    for sampler in ROUTED_SAMPLERS:
        assert sampler in completed.stdout, (
            f"the probe did not construct {sampler}, so nothing proves it imports without a "
            "cloud SDK present"
        )


def test_every_branch_of_the_source_router_has_a_probe_source() -> None:
    """A branch with no probe source is an adapter this suite silently stopped importing.

    The router is a hand-written chain rather than a table, so there is nothing to discover
    from; counting its returns is what makes a sixth branch fail here instead of going unbuilt.
    """
    source = (REPO_ROOT / "src/onprem_dlp/config.py").read_text(encoding="utf-8")
    body = source.split("def sampler(self, source: str):", 1)[1].split("\n    def ", 1)[0]
    branches = [line for line in body.splitlines() if line.strip().startswith("return ")]
    assert len(branches) == len(SAMPLER_SOURCES) == len(ROUTED_SAMPLERS), (
        f"the router has {len(branches)} branches and the probe carries "
        f"{len(SAMPLER_SOURCES)} sources; add a source for the new branch so its adapter is "
        "imported under the blocker"
    )


def test_the_blocker_still_blocks() -> None:
    """A probe whose blocker quietly stopped blocking would make every proof above vacuous."""
    completed = _run_probe("--self-test")
    assert completed.returncode == 0, f"{completed.stdout}\n{completed.stderr}"
    assert "blocker refused google.auth" in completed.stdout
