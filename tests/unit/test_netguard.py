"""The fail-closed network defaults, both halves.

These run with nothing installed beyond the standard library: the guard is deliberately pure
ASGI so the offline gate exercises the real refusal path rather than skipping it for want of
the ``[api]`` extra.
"""

from __future__ import annotations

import asyncio

import pytest

from onprem_dlp.netguard import (
    DEFAULT_PORT,
    LOOPBACK_BIND,
    ConfiguredEmptyError,
    InsecureBindError,
    InsecureCorsError,
    LoopbackExposureGuard,
    cors_allowlist,
    exposure_accepted,
    is_loopback_host,
    read_env_setting,
    resolve_bind_host,
    resolve_bind_port,
)

_HOST = "ONPREM_DLP_API_HOST"
_PORT = "ONPREM_DLP_API_PORT"
_OPT_IN = "ONPREM_DLP_ALLOW_UNAUTHENTICATED_EXPOSURE"
_ORIGINS = "ONPREM_DLP_API_CORS_ORIGINS"


# --------------------------------------------------------------------------- three states
def test_env_setting_separates_unset_from_configured_empty(monkeypatch):
    monkeypatch.delenv(_HOST, raising=False)
    unset = read_env_setting(_HOST)
    assert (unset.is_unset, unset.is_configured_empty, unset.has_value) == (True, False, False)

    monkeypatch.setenv(_HOST, "   ")
    empty = read_env_setting(_HOST)
    assert (empty.is_unset, empty.is_configured_empty, empty.has_value) == (False, True, False)

    monkeypatch.setenv(_HOST, " 192.0.2.9\n")
    set_value = read_env_setting(_HOST)
    assert (set_value.is_unset, set_value.is_configured_empty, set_value.has_value) == (
        False,
        False,
        True,
    )
    assert set_value.value == "192.0.2.9", "the guard must judge the value it returns"


def test_require_not_configured_empty_names_the_variable_and_the_way_out(monkeypatch):
    monkeypatch.setenv(_HOST, "")
    with pytest.raises(ConfiguredEmptyError) as error:
        read_env_setting(_HOST).require_not_configured_empty("a host to bind")
    message = str(error.value)
    assert _HOST in message
    assert "Unset it" in message


# --------------------------------------------------------------------------- loopback
@pytest.mark.parametrize(
    "host",
    ["127.0.0.1", "localhost", "::1", "[::1]", "127.9.9.9", "::ffff:127.0.0.1", " 127.0.0.1 "],
)
def test_loopback_hosts_are_recognised(host):
    assert is_loopback_host(host) is True


@pytest.mark.parametrize(
    "host", ["0.0.0.0", "192.0.2.9", "::", "db.example", "", None, "not-an-ip"]
)
def test_non_loopback_and_unclassifiable_hosts_fail_closed(host):
    assert is_loopback_host(host) is False


# --------------------------------------------------------------------------- bind guard
def test_unset_host_binds_loopback(monkeypatch):
    monkeypatch.delenv(_HOST, raising=False)
    monkeypatch.delenv(_OPT_IN, raising=False)
    assert resolve_bind_host() == LOOPBACK_BIND


def test_wide_bind_is_refused_without_the_explicit_acceptance(monkeypatch):
    monkeypatch.setenv(_HOST, "0.0.0.0")
    monkeypatch.delenv(_OPT_IN, raising=False)
    with pytest.raises(InsecureBindError) as error:
        resolve_bind_host()
    assert _OPT_IN in str(error.value)


def test_wide_bind_is_allowed_only_on_the_exact_opt_in(monkeypatch):
    monkeypatch.setenv(_HOST, "0.0.0.0")
    for value in ("", "0", "true", "yes", " 1"):
        monkeypatch.setenv(_OPT_IN, value)
        assert exposure_accepted() is False
        with pytest.raises(InsecureBindError):
            resolve_bind_host()
    monkeypatch.setenv(_OPT_IN, "1")
    assert exposure_accepted() is True
    assert resolve_bind_host() == "0.0.0.0"


def test_empty_host_refuses_instead_of_inheriting_the_default(monkeypatch):
    monkeypatch.setenv(_HOST, "")
    with pytest.raises(ConfiguredEmptyError):
        resolve_bind_host()


def test_port_is_three_state_and_bounded(monkeypatch):
    monkeypatch.delenv(_PORT, raising=False)
    assert resolve_bind_port() == DEFAULT_PORT
    monkeypatch.setenv(_PORT, "9000")
    assert resolve_bind_port() == 9000
    monkeypatch.setenv(_PORT, "")
    with pytest.raises(ConfiguredEmptyError):
        resolve_bind_port()
    for bad in ("http", "0", "70000", "-1"):
        monkeypatch.setenv(_PORT, bad)
        with pytest.raises(ValueError):
            resolve_bind_port()


# --------------------------------------------------------------------------- CORS
def test_cors_grants_nothing_when_unset_or_configured_empty(monkeypatch):
    monkeypatch.delenv(_ORIGINS, raising=False)
    assert cors_allowlist() == []
    for empty in ("", "   ", ",", " , "):
        monkeypatch.setenv(_ORIGINS, empty)
        assert cors_allowlist() == []


def test_cors_returns_the_named_origins_stripped(monkeypatch):
    monkeypatch.setenv(_ORIGINS, " https://ops.example , https://desk.example ")
    assert cors_allowlist() == ["https://ops.example", "https://desk.example"]


def test_cors_wildcard_is_refused_not_silently_dropped(monkeypatch):
    monkeypatch.setenv(_ORIGINS, "https://ops.example,*")
    with pytest.raises(InsecureCorsError):
        cors_allowlist()


# --------------------------------------------------------------------------- exposure guard
async def _ok_app(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b'{"status":"ok"}'})


def _drive(scope, *, messages=None):
    """Run the guard over one scope and return the ASGI messages it produced."""
    sent: list[dict] = []
    inbound = list(messages or [])

    async def receive():
        return inbound.pop(0) if inbound else {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    asyncio.run(LoopbackExposureGuard(_ok_app)(scope, receive, send))
    return sent


def _http_scope(client, headers=()):
    return {
        "type": "http",
        "method": "POST",
        "path": "/v1/egress/decide",
        "client": client,
        "headers": list(headers),
    }


def test_loopback_peer_is_served(monkeypatch):
    monkeypatch.delenv(_OPT_IN, raising=False)
    sent = _drive(_http_scope(("127.0.0.1", 51234)))
    assert sent[0]["status"] == 200


@pytest.mark.parametrize("client", [("192.0.2.9", 40000), ("192.0.2.10", 40000), None])
def test_non_loopback_or_unknown_peer_is_refused(monkeypatch, client):
    monkeypatch.delenv(_OPT_IN, raising=False)
    sent = _drive(_http_scope(client))
    assert sent[0]["status"] == 503
    assert b"unauthenticated" in sent[1]["body"]


@pytest.mark.parametrize("header", [b"x-forwarded-for", b"X-Forwarded-For", b"forwarded"])
def test_a_forwarding_header_is_refused_even_from_loopback(monkeypatch, header):
    """A proxy has already rewritten scope["client"], so its presence is the honest signal."""
    monkeypatch.delenv(_OPT_IN, raising=False)
    sent = _drive(_http_scope(("127.0.0.1", 51234), [(header, b"198.51.100.7")]))
    assert sent[0]["status"] == 503


def test_the_acceptance_lets_a_remote_peer_through(monkeypatch):
    monkeypatch.setenv(_OPT_IN, "1")
    sent = _drive(_http_scope(("192.0.2.9", 40000)))
    assert sent[0]["status"] == 200


def test_websocket_is_closed_before_the_handshake(monkeypatch):
    monkeypatch.delenv(_OPT_IN, raising=False)
    scope = {"type": "websocket", "client": ("192.0.2.9", 40000), "headers": []}
    sent = _drive(scope, messages=[{"type": "websocket.connect"}])
    assert sent[0]["type"] == "websocket.close"
    assert sent[0]["code"] == 1008


def test_lifespan_scopes_are_forwarded_untouched(monkeypatch):
    monkeypatch.delenv(_OPT_IN, raising=False)
    seen = []

    async def app(scope, receive, send):
        seen.append(scope["type"])

    asyncio.run(LoopbackExposureGuard(app)({"type": "lifespan"}, None, None))
    assert seen == ["lifespan"]
