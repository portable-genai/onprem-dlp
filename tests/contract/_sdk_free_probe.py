"""Construct every adapter of one profile in a FRESH interpreter with the cloud SDKs blocked.

Run as ``python -m tests.contract._sdk_free_probe <profile>`` from the repo root (with ``src``
on ``PYTHONPATH``); exits 0 when every binding of that profile imported and constructed,
non-zero naming the offence otherwise. ``--self-test`` proves the blocker itself still refuses,
because a probe whose blocker quietly stopped blocking would pass on any machine and prove
nothing.

Why a subprocess rather than a fixture that unloads modules in place: reloading rebinds the
adapter classes, so every already-imported test module would keep stale class objects and
``isinstance`` checks elsewhere in the suite would start failing for reasons that have nothing
to do with the code under test. A fresh process also proves the stronger claim: a whole
interpreter in which the SDK was never importable, which is the difference between "no SDK
installed on this machine" and "cannot be imported".

Shaped to THIS repository rather than to a ports table: the settings file is a plain mapping,
so the bindings come from ``settings["profiles"][profile]`` plus the profile-independent
``ocr`` and ``image_redactor`` entries, and they are built with ``config._instantiate``, which
is the one constructor the whole repo uses.

The samplers are not bound in settings at all (``Container.sampler`` routes on the source
string a caller passes), so ``--samplers`` builds them through that router, one source per
branch, as a case of its own. That separation is the point rather than tidiness:
:class:`BigQuerySampler` is this repository's ONLY adapter that touches a managed cloud SDK,
so it is the only place the lazy-import rule can be broken here, and it belongs to no profile.
Folding it into every profile's run would smear one broken import across four red profiles
and name none of them; on its own it fails alone and says what broke.
"""

from __future__ import annotations

import importlib
import sys
import tempfile
from pathlib import Path

#: Import roots EVERY profile must build without, the managed sampler included: its SDK
#: import is required to be lazy, so construction must not need it. ``google`` covers every
#: ``google-cloud-*`` distribution plus ``google-genai`` and ``google-adk``; ``vertexai``
#: ships as its own root.
BLOCKED_ROOTS = ("google", "vertexai")

CONFIG_PATH = "config/settings.yaml"

#: One source per branch of ``Container.sampler``, so every sampler the router can return is
#: imported and constructed. ``{tmp}`` is filled with a scratch directory; the CSV branch is
#: the only one that reads its path at construction.
SAMPLER_SOURCES = (
    "postgresql://u@h/db?sslmode=verify-full&sslrootcert=/etc/ssl/certs/ca.pem",
    "mysql://u@h/db",
    "bigquery://demo-project/demo_dataset",
    "{tmp}/probe.csv",
    "{tmp}/probe.db",
)


class _BlockedSdkFinder:
    """A meta-path finder that refuses the blocked roots, whatever is installed."""

    def find_spec(self, fullname: str, path: object = None, target: object = None) -> None:
        if any(fullname == root or fullname.startswith(root + ".") for root in BLOCKED_ROOTS):
            raise ModuleNotFoundError(
                f"{fullname} is blocked: this profile must construct with no cloud SDK"
            )
        return None


def _install_blocker() -> None:
    evicted = [
        name
        for name in sys.modules
        if any(name == root or name.startswith(root + ".") for root in BLOCKED_ROOTS)
    ]
    for name in evicted:
        del sys.modules[name]
    sys.meta_path.insert(0, _BlockedSdkFinder())  # type: ignore[arg-type]


def _self_test() -> int:
    """The blocker must refuse, and refuse for the right reason."""
    _install_blocker()
    try:
        importlib.import_module("google.auth")
    except ModuleNotFoundError as exc:
        if "blocked" in str(exc):
            print("blocker refused google.auth")
            return 0
        print(f"google.auth failed, but not because of the blocker: {exc}", file=sys.stderr)
        return 1
    print("google.auth imported despite the blocker", file=sys.stderr)
    return 1


def _report(label: str, built: list[str]) -> int:
    if not built:
        print(f"{label}: nothing was bound; a build of nothing proves nothing", file=sys.stderr)
        return 1
    print(f"{label}: constructed {len(built)} adapters with no cloud SDK importable")
    print("constructed: " + " ".join(sorted(built)))
    return 0


def _samplers() -> int:
    """Build every sampler ``Container.sampler`` can return, the managed one included."""
    _install_blocker()
    from onprem_dlp.config import Container, load_settings

    container = Container(load_settings(CONFIG_PATH))
    built: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "probe.csv").write_text("a,b\n1,2\n", encoding="utf-8")
        for template in SAMPLER_SOURCES:
            built.append(type(container.sampler(template.format(tmp=tmp))).__name__)
    return _report("samplers", built)


def main(profile: str) -> int:
    _install_blocker()

    # Imported AFTER the blocker is installed, so an eager SDK import anywhere on the
    # construction path, config.py included, is caught rather than arriving pre-loaded.
    from onprem_dlp.config import Container, _instantiate, load_settings

    settings = load_settings(CONFIG_PATH)
    if profile not in settings["profiles"]:
        print(f"unknown profile {profile!r}", file=sys.stderr)
        return 1
    container = Container(settings, profile=profile)

    built: list[str] = []
    for port_name, binding in sorted(settings["profiles"][profile].items()):
        adapter = _instantiate(binding)
        if adapter is None:
            print(f"port {port_name} has no {profile} binding", file=sys.stderr)
            return 1
        built.append(type(adapter).__name__)
    for port_name, factory in (
        ("ocr", container.ocr),
        ("image_redactor", container.image_redactor),
    ):
        adapter = factory()
        if adapter is None:
            print(f"settings bind no {port_name} adapter", file=sys.stderr)
            return 1
        built.append(type(adapter).__name__)
    return _report(profile, built)


_MODES = {"--self-test": _self_test, "--samplers": _samplers}


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(
            "usage: python -m tests.contract._sdk_free_probe <profile>|--samplers|--self-test",
            file=sys.stderr,
        )
        raise SystemExit(2)
    mode = _MODES.get(sys.argv[1])
    raise SystemExit(mode() if mode else main(sys.argv[1]))
