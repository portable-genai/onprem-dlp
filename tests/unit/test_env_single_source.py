"""The environment has ONE reader, and no read may carry a permissive literal default.

The standing gate for the absence-read-as-consent class, adapted from human-review-console's profile
guard to the shape the class takes here. Every fail-open this repo carried was spelled either
``os.environ.get(name)`` followed by ``if value:`` or ``os.environ.get(name, <literal>)``: the
two-state read that cannot tell "absent" from "set to nothing" and answers both with the default.
That default was, variously, the public built-in redaction salt, a disabled audit trail, the weakest
detection profile, and an empty database password.

``netguard.read_env_setting`` now owns that decision in three states. A second reader, or a
two-state read reappearing anywhere, brings the whole class back, so both are build failures.
``exposure_accepted`` is the one deliberate exception and is asserted on by name: it is a
RELAXATION compared raw against exactly ``"1"``, where unset and set-and-empty must land in
the same place, and that place is already the closed one.
"""

from __future__ import annotations

import re
from pathlib import Path

_SRC = Path(__file__).resolve().parents[2] / "src" / "onprem_dlp"
_READER_MODULE = "netguard.py"
_ENV_READ = re.compile(r"os\.(environ\.get|getenv|environ\[)")
#: An environment read that supplies a fallback: ``os.environ.get("X", "something")``.
_TWO_STATE_READ = re.compile(r"os\.(environ\.get|getenv)\([^)]*,")


def _source_lines() -> list[tuple[str, int, str]]:
    out: list[tuple[str, int, str]] = []
    for path in sorted(_SRC.rglob("*.py")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if line.lstrip().startswith("#") or '"""' in line or "``" in line:
                continue  # prose about the rule is not a violation of it
            out.append((str(path.relative_to(_SRC)), number, line))
    return out


def test_only_netguard_reads_the_environment() -> None:
    reads = [(f, n, line.strip()) for f, n, line in _source_lines() if _ENV_READ.search(line)]
    assert reads, "the guard is vacuous if nothing reads the environment at all"
    offenders = [f"{f}:{n}: {line}" for f, n, line in reads if f != _READER_MODULE]
    assert not offenders, (
        f"these lines read the environment outside {_READER_MODULE}, so a security-relevant "
        "value can again be resolved in two states instead of three:\n" + "\n".join(offenders)
    )


def test_no_environment_read_carries_a_literal_default() -> None:
    """``os.environ.get(name, "")`` is the exact shape that reads absence as consent."""
    offenders = [
        f"{f}:{n}: {line.strip()}" for f, n, line in _source_lines() if _TWO_STATE_READ.search(line)
    ]
    assert not offenders, (
        "these environment reads supply a fallback, which collapses 'unset' and 'set to "
        "nothing' into one answer:\n" + "\n".join(offenders)
    )


def test_the_only_raw_comparison_is_the_relaxation_opt_in() -> None:
    """The opt-in is the one read where unset and set-and-empty MUST answer the same."""
    raw_reads = [
        (f, n, line.strip())
        for f, n, line in _source_lines()
        if f == _READER_MODULE and _ENV_READ.search(line)
    ]
    assert raw_reads, "netguard must be the module that actually touches os.environ"
    unaccounted = [
        f"{f}:{n}: {line}"
        for f, n, line in raw_reads
        if "opt_in_env" not in line and "raw = os.environ.get(name)" not in line
    ]
    assert not unaccounted, (
        "every raw environment access in netguard must be either read_env_setting's own read "
        "or the exposure opt-in; these are neither:\n" + "\n".join(unaccounted)
    )
