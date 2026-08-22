"""Port-set drift guard: the port registry, the shipped binding sets and the profile set agree.

Three registries describe this gate's hexagon and nothing at runtime compares them:

* the runtime_checkable Protocols exported by :mod:`onprem_dlp.ports` (what a port IS),
* the ``profiles:`` map plus the profile-independent ``ocr`` / ``image_redactor`` entries in
  ``config/settings.yaml`` (which class fills each port), and
* :data:`onprem_dlp.config.DEFAULT_SETTINGS`, whose ``profiles`` keys are the profile registry
  this repository has in place of a ``RUNTIME_PROFILES`` constant.

A port bound in settings but absent from the protocol map below is unenforced with a green
build. A Protocol added to ``ports/`` and never bound is a hexagon edge nobody can reach. Every
assertion is therefore set equality in BOTH directions: one direction alone lets a new port ship
with no binding in some profile, and the other lets an orphan adapter overstate coverage.

Why the missing-binding direction is the sharp one HERE. ``config._instantiate`` returns ``None``
for an absent binding, and :class:`~onprem_dlp.domain.orchestrator_service.DlpOrchestrator`
declares ``ner`` and ``adjudicator`` as ``| None``, so a profile that loses its ``ner`` entry does
not fail: it builds, runs, and silently stops contributing model-based findings. On a DLP gate
that is a fail-open, and it is exactly the shape of defect a green build hides. There is no
``KeyError`` waiting downstream to catch it, so this file is the only place it can be caught.

Two profile-independent shapes are deliberate and are asserted as exceptions rather than ignored:
``ColumnSampler`` is chosen by :meth:`onprem_dlp.config.Container.sampler` from the source string
a caller passes, and ``AuditSink`` is constructed from the ``audit_log`` path. Neither is a dotted
binding, and both are proven reachable below so the exemptions stay honest.

Scope note. This file guards the SETS. That every shipped adapter satisfies its Protocol with the
optional heavy dependencies absent is proven next door in ``tests/contract/test_ports.py``, and
that a whole profile constructs with the cloud SDKs BLOCKED is proven by
``tests/contract/test_sdk_free_build.py`` through ``_sdk_free_probe``.
"""

from __future__ import annotations

from typing import Any, Protocol, get_type_hints

import pytest

from onprem_dlp import ports
from onprem_dlp.config import DEFAULT_SETTINGS, Container, _instantiate, load_settings

CONFIG_PATH = "config/settings.yaml"

#: Ports every named profile must bind, mapped to the Protocol the bound class must satisfy.
PROFILE_PORT_PROTOCOLS: dict[str, type] = {
    "ner": ports.NerAnalyzer,
    "adjudicator": ports.LlmAdjudicator,
}

#: Ports bound ONCE at the top level, outside the profiles: the image pipeline does not vary by
#: detection profile, so these carry a single binding rather than one per profile.
SINGLETON_PORT_PROTOCOLS: dict[str, type] = {
    "ocr": ports.OcrEngine,
    "image_redactor": ports.ImageRedactor,
}

#: Protocols the ports package exports that are deliberately bound by something other than a
#: dotted settings entry, each with the reason. Written as data so a new unbound Protocol has to
#: be argued for here rather than simply not noticed.
EXEMPT_FROM_SETTINGS_BINDINGS: dict[str, str] = {
    "ColumnSampler": (
        "selected by Container.sampler from the SOURCE STRING a caller passes (.csv, .db, "
        "postgres://, mysql://, bigquery://), so it has no single binding to name"
    ),
    "AuditSink": (
        "constructed from the audit_log path when one is configured, and deliberately absent "
        "when it is not; a dotted binding would make the evidence trail look mandatory"
    ),
}


def _shipped() -> dict[str, Any]:
    """The settings the deployment actually runs: the defaults overlaid with the shipped file.

    ``load_settings`` DEEP MERGES, so a binding deleted from ``config/settings.yaml`` alone is
    backfilled from :data:`~onprem_dlp.config.DEFAULT_SETTINGS` and nothing changes. That is a
    deliberate resilience property, and it is also why the assertions below are written against
    the merged result: this is the map the gate runs, and a port can only truly go missing from
    it when BOTH sources drop it, or when a new profile is added to one of them incompletely.
    """
    return load_settings(CONFIG_PATH)


def _protocol_members(protocol: type) -> set[str]:
    """The attribute names a Protocol declares (methods + properties), no dunders."""
    members = set(getattr(protocol, "__protocol_attrs__", set()))
    if not members:  # pragma: no cover - fallback for older typing internals
        members |= set(get_type_hints(protocol).keys())
    return {m for m in members if not m.startswith("_")}


def _exported_protocols() -> dict[str, type]:
    """Every runtime_checkable Protocol :mod:`onprem_dlp.ports` exports, by name."""
    found: dict[str, type] = {}
    for name in ports.__all__:
        obj = getattr(ports, name)
        if isinstance(obj, type) and getattr(obj, "_is_runtime_protocol", False):
            found[name] = obj
    return found


def _profiles() -> list[str]:
    return sorted(_shipped()["profiles"])


# --------------------------------------------------------------------------- #
# The profile set: the code registry <-> the shipped file, both directions
# --------------------------------------------------------------------------- #
def test_the_defaults_and_the_shipped_file_declare_the_same_profiles() -> None:
    """``load_settings`` MERGES, so the two profile lists have to be reconciled by hand.

    A profile that exists only in ``DEFAULT_SETTINGS`` still resolves, and the shipped file then
    understates what an operator can select. A profile that exists only in the shipped file
    disappears the moment that file is not mounted, taking the detection posture with it. Both
    are silent today; both are named here.
    """
    in_code = set(DEFAULT_SETTINGS["profiles"])
    in_file = set(_shipped()["profiles"])

    only_in_code = in_code - in_file
    assert not only_in_code, (
        f"profiles declared in config.DEFAULT_SETTINGS but absent from {CONFIG_PATH}: "
        f"{sorted(only_in_code)}. The shipped file is what an operator reads; a selectable "
        "profile it does not mention is a profile nobody knows about."
    )
    only_in_file = in_file - in_code
    assert not only_in_file, (
        f"profiles declared in {CONFIG_PATH} but absent from config.DEFAULT_SETTINGS: "
        f"{sorted(only_in_file)}. Deploying without the file silently removes them, and "
        "Container then refuses a profile the documentation offers."
    )


def test_the_default_profile_is_one_that_is_actually_declared() -> None:
    settings = _shipped()
    assert settings["profile"] in settings["profiles"], (
        f"the default profile {settings['profile']!r} is not among the declared profiles "
        f"{sorted(settings['profiles'])}, so Container refuses to build for every caller who "
        "does not name one explicitly"
    )


# --------------------------------------------------------------------------- #
# The port set: protocol map <-> the shipped bindings, both directions
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("profile", _profiles())
def test_every_profile_binds_exactly_the_profile_scoped_ports(profile: str) -> None:
    bindings = _shipped()["profiles"][profile]

    missing = set(PROFILE_PORT_PROTOCOLS) - set(bindings)
    assert not missing, (
        f"profile '{profile}' binds no adapter for port(s) {sorted(missing)}. _instantiate "
        "returns None for an absent binding and the orchestrator accepts None, so this profile "
        "would run to completion with that port silently doing nothing."
    )
    unmapped = set(bindings) - set(PROFILE_PORT_PROTOCOLS)
    assert not unmapped, (
        f"profile '{profile}' binds port(s) {sorted(unmapped)} that PROFILE_PORT_PROTOCOLS does "
        "not know about, so they get NO conformance enforcement. Add them to the parity map "
        "with the Protocol they are supposed to satisfy."
    )


def test_the_profile_independent_ports_are_bound_exactly_once() -> None:
    settings = _shipped()
    for port_name in SINGLETON_PORT_PROTOCOLS:
        binding = settings.get(port_name) or {}
        assert binding.get("class"), (
            f"port '{port_name}' has no top-level binding; the image pipeline would build it as "
            "None and fail only when a caller reaches scan-image or redact-image"
        )


def test_every_exported_protocol_is_bound_or_a_named_exception() -> None:
    """A Protocol in ``ports/`` is either bound in settings or an argued-for exception."""
    exported = _exported_protocols()
    mapped = set(PROFILE_PORT_PROTOCOLS.values()) | set(SINGLETON_PORT_PROTOCOLS.values())

    orphans = {
        name
        for name, proto in exported.items()
        if proto not in mapped and name not in EXEMPT_FROM_SETTINGS_BINDINGS
    }
    assert not orphans, (
        f"runtime_checkable Protocols exported by onprem_dlp.ports that are neither bound in "
        f"{CONFIG_PATH} nor listed in EXEMPT_FROM_SETTINGS_BINDINGS: {sorted(orphans)}. Bind "
        "them, or record here why this one is not a settings binding."
    )
    stale = set(EXEMPT_FROM_SETTINGS_BINDINGS) - set(exported)
    assert not stale, (
        f"EXEMPT_FROM_SETTINGS_BINDINGS names Protocols onprem_dlp.ports no longer exports: "
        f"{sorted(stale)}. A stale exemption is a hole nobody is watching."
    )
    known = set(exported.values())
    foreign = {
        port
        for port, proto in {**PROFILE_PORT_PROTOCOLS, **SINGLETON_PORT_PROTOCOLS}.items()
        if proto not in known
    }
    assert not foreign, (
        f"ports mapped to a Protocol that onprem_dlp.ports does not export: {sorted(foreign)}. "
        "The ports package is the port registry; a look-alike declared elsewhere is how two "
        "copies of one interface drift apart while isinstance stays green."
    )


def test_the_exempt_protocols_really_are_reachable_another_way(tmp_path) -> None:
    """An exemption is only honest if the port is still bound, just not from a dotted entry."""
    csv_path = tmp_path / "columns.csv"
    csv_path.write_text("account_ref,notes\n1,hello\n", encoding="utf-8")

    container = Container(_shipped(), profile="local")
    sampler = container.sampler(str(csv_path))
    assert isinstance(sampler, ports.ColumnSampler), (
        "ColumnSampler is exempt from the settings bindings on the grounds that "
        "Container.sampler routes to it; if that router stops returning the Protocol, the "
        "exemption is covering a gap"
    )

    audited = dict(_shipped())
    audited["audit_log"] = str(tmp_path / "audit.jsonl")
    orchestrator = Container(audited, profile="local").orchestrator()
    assert isinstance(orchestrator.audit, ports.AuditSink), (
        "AuditSink is exempt on the grounds that a configured audit_log builds one; a "
        "configured path that yields no conforming sink means the evidence trail is not wired"
    )


# --------------------------------------------------------------------------- #
# Structural conformance of the SHIPPED bindings
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("profile", _profiles())
@pytest.mark.parametrize("port_name", sorted(PROFILE_PORT_PROTOCOLS))
def test_profile_binding_satisfies_its_protocol(profile: str, port_name: str) -> None:
    protocol = PROFILE_PORT_PROTOCOLS[port_name]
    binding = _shipped()["profiles"][profile].get(port_name)
    assert binding and binding.get("class"), (
        f"profile '{profile}' has no '{port_name}' binding, so there is no adapter to hold to "
        f"{protocol.__name__}"
    )

    # Built through config._instantiate, the one constructor the whole repo uses, so this is
    # about the mechanism the running gate uses rather than a second implementation of it.
    adapter = _instantiate(binding)

    assert isinstance(adapter, protocol), (
        f"{binding['class']} does not structurally satisfy {protocol.__name__}"
    )

    # Every declared Protocol member exists. Looked up on the CLASS via the MRO, not the
    # instance: a property getter may raise where an optional dependency is absent, so
    # ``hasattr`` would wrongly report it missing.
    declared = set().union(*(vars(klass) for klass in type(adapter).__mro__))
    for member in _protocol_members(protocol):
        assert member in declared, (
            f"{binding['class']} is missing port member '{member}' of {protocol.__name__}"
        )


@pytest.mark.parametrize("port_name", sorted(SINGLETON_PORT_PROTOCOLS))
def test_singleton_binding_satisfies_its_protocol(port_name: str) -> None:
    protocol = SINGLETON_PORT_PROTOCOLS[port_name]
    binding = _shipped().get(port_name)
    adapter = _instantiate(binding)
    assert isinstance(adapter, protocol), (
        f"{(binding or {}).get('class')} does not structurally satisfy {protocol.__name__}"
    )
    declared = set().union(*(vars(klass) for klass in type(adapter).__mro__))
    for member in _protocol_members(protocol):
        assert member in declared, (
            f"the {port_name} binding is missing port member '{member}' of {protocol.__name__}"
        )


def test_all_mapped_protocols_are_runtime_checkable() -> None:
    """``isinstance`` above is meaningless against a Protocol that is not runtime_checkable."""
    for port_name, protocol in {**PROFILE_PORT_PROTOCOLS, **SINGLETON_PORT_PROTOCOLS}.items():
        assert issubclass(protocol, Protocol)  # type: ignore[arg-type]
        assert getattr(protocol, "_is_runtime_protocol", False), (
            f"{protocol.__name__} (port '{port_name}') must be @runtime_checkable"
        )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
