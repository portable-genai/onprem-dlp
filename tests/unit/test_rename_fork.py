"""``--dist``, ``--cli`` and ``--resource`` have to stay independently meaningful.

``_OLD_DIST``, ``_OLD_CLI`` and ``_OLD_RESOURCE`` are all the same string in this repo, so a
bare replacement of whichever one comes first consumes every occurrence and leaves the other
two doing nothing at all: an adopter who passes three different values silently gets one.
Only the anchored forms (the pyproject ``name =`` declaration and the ``[project.scripts]``
console-script line) can tell the three apart, so this feeds a fragment carrying all three
and pins each landing on its own value.
"""

from __future__ import annotations

import importlib.util
from argparse import Namespace
from pathlib import Path

_SCRIPT = Path(__file__).parents[2] / "scripts" / "rename_fork.py"
_SPEC = importlib.util.spec_from_file_location("rename_fork", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)


def _diverging_args() -> Namespace:
    """A fork that deliberately gives the distribution, the CLI and the resource three names."""
    return Namespace(
        package="acme_dlp",
        cli="acme-dlp-cli",
        env_prefix="ACME",
        resource="acme-dlp-svc",
        dist="acme-dlp-dist",
    )


def test_dist_cli_and_resource_each_land_on_their_own_value() -> None:
    source = (
        f'name = "{_MODULE._OLD_DIST}"\n'
        f'{_MODULE._OLD_CLI} = "{_MODULE._OLD_PACKAGE}.cli.main:main"\n'
        f'resource_id = "{_MODULE._OLD_RESOURCE}"\n'
        f"{_MODULE._OLD_ENV_PREFIX}PROFILE\n"
    )

    rewritten, count = _MODULE._rewrite_text(source, _MODULE._replacements(_diverging_args()))

    assert rewritten == (
        'name = "acme-dlp-dist"\n'
        'acme-dlp-cli = "acme_dlp.cli.main:main"\n'
        'resource_id = "acme-dlp-svc"\n'
        "ACME_PROFILE\n"
    )
    assert count == 4
