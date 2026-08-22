"""Fail-closed network defaults and the ONE environment reader (pure stdlib).

Why this module exists at all, and why it is not an import of the catalog commons:
``hex-service-kit`` carries the same primitives, but consuming it would make the catalog
commons a *runtime* dependency of an air-gapped egress gate whose load-bearing claim is
``dependencies = []`` (see ``COMPLIANCE.md``, "Supply-chain honesty"). The 2026-07-19
non-adoption assessment in ``docs/practices-audit.md`` reserved exactly this move: the kit's
primitives stay available "as reference implementations to mirror manually if a gap is ever
closed here". This is that gap, so the SEMANTICS below are the kit's, verbatim in behaviour,
and only the code is local.

Two halves, because a bind guard alone is a property of one entry point:

* start-up half: :func:`resolve_bind_host` / :func:`resolve_bind_port`, used by
  ``onprem_dlp.api.serve`` (the image's ``CMD``). It refuses to bind the unauthenticated REST
  surface anywhere but loopback unless an operator accepts the exposure explicitly.
* request-time half: :class:`LoopbackExposureGuard`, an ASGI middleware installed on the app
  object itself, so ``uvicorn onprem_dlp.api.app:create_app --factory --host 0.0.0.0`` typed by
  hand, or any other server, is bounded by the same rule.

The REST surface has NO authentication in any profile: it is an in-estate sidecar in front of
cloud egress, and it accepts writes (``/v1/scan/text``, ``/v1/redact/text``,
``/v1/egress/decide``, ``/v1/classify/columns``) whose bodies are, by construction, the raw
personal data an application was about to send out. "Air-gapped by design" is a reason the
threat model differs; it is not a reason that surface may bind every interface by default.

Every environment read in this package goes through :func:`read_env_setting`, which resolves
THREE states (unset / set-and-empty / set-and-valid) rather than the two that
``os.environ.get(name, "")`` leaves you with. Conflating them is how a fail-closed default
fails open: a hash salt an operator meant to inject, arriving empty from a misprovisioned
secret, used to inherit the built-in public default and silently make every pseudonymous
token re-linkable. Which direction "closed" points in depends on the read: a relaxation grants
nothing, a restriction refuses to run.
"""

from __future__ import annotations

import ipaddress
import json
import os
from collections.abc import Awaitable, Callable, MutableMapping
from dataclasses import dataclass
from typing import Any

#: Host to bind the REST surface to. Unset means loopback.
BIND_HOST_ENV = "ONPREM_DLP_API_HOST"
#: TCP port for the REST surface. Unset means :data:`DEFAULT_PORT`.
BIND_PORT_ENV = "ONPREM_DLP_API_PORT"
#: The explicit, auditable acceptance of serving an unauthenticated surface off loopback.
EXPOSURE_OPT_IN_ENV = "ONPREM_DLP_ALLOW_UNAUTHENTICATED_EXPOSURE"
#: Comma-separated cross-origin allowlist. Never a wildcard, in any state.
CORS_ORIGINS_ENV = "ONPREM_DLP_API_CORS_ORIGINS"

DEFAULT_PORT = 8484
LOOPBACK_BIND = "127.0.0.1"

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_FORWARDING_HEADERS = frozenset({b"x-forwarded-for", b"forwarded"})
_WS_POLICY_VIOLATION = 1008

_HOW_TO_ACCEPT = (
    f"Bind loopback, put an authenticating reverse proxy in front, or set "
    f"{EXPOSURE_OPT_IN_ENV}=1 to accept the exposure (do that only where a network control, "
    f"such as the chart's default-deny NetworkPolicy, is the compensating boundary)."
)


class InsecureBindError(RuntimeError):
    """Raised when the unauthenticated REST surface is asked to bind a non-loopback host."""


class InsecureCorsError(RuntimeError):
    """Raised when the cross-origin allowlist is configured as a wildcard."""


class ConfiguredEmptyError(RuntimeError):
    """Raised when a variable is PRESENT but empty, and an empty value cannot be honoured.

    Setting a variable to an empty string is an expressed intent, not the absence of one, so it
    must never inherit the unset default. Where an empty value is meaningful (an allowlist that
    names nobody) the empty value is honoured instead of raising; this is for the reads where it
    is not, such as the host to bind or the redaction salt.
    """


# --------------------------------------------------------------------------- #
# The three-state environment read
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class EnvSetting:
    """One environment variable resolved into THREE states, never two.

    ``os.environ.get(name, "")`` erases the difference between a variable nobody configured and
    one an operator deliberately set to empty, and the usual ``if value:`` that follows then
    gives both the unset default. ``unset`` is not a member of the valid value set, so it is
    carried separately and exactly one of the three properties below is true:

    * :attr:`is_unset`: absent. No intent was expressed, so a documented default may stand.
    * :attr:`is_configured_empty`: present and empty once stripped. An intent WAS expressed and
      it names nothing: fail closed, in whichever direction closed means for that read.
    * :attr:`has_value`: present with a usable value.
    """

    name: str
    #: Exactly what the environment held, unstripped; ``None`` when the variable is absent.
    raw: str | None
    #: ``raw`` stripped, or ``""`` when absent. Never ``None``.
    value: str

    @property
    def is_unset(self) -> bool:
        """Is the variable absent from the environment?"""
        return self.raw is None

    @property
    def is_configured_empty(self) -> bool:
        """Is the variable present but empty (or whitespace only)?"""
        return self.raw is not None and not self.value

    @property
    def has_value(self) -> bool:
        """Is the variable present with a usable value?"""
        return bool(self.value)

    def require_not_configured_empty(self, what: str) -> EnvSetting:
        """Raise :class:`ConfiguredEmptyError` when set-and-empty; otherwise return self.

        ``what`` completes the sentence "an empty value is not ...", so it reads as guidance
        rather than a stack trace.
        """
        if self.is_configured_empty:
            raise ConfiguredEmptyError(
                f"{self.name} is set to an empty value, which is not {what}. Unset it to take "
                "the documented default, or set it to the value you intend."
            )
        return self


def read_env_setting(name: str) -> EnvSetting:
    """Read ``name`` into its three states (see :class:`EnvSetting`).

    This is the single environment reader for the package; ``tests/unit/test_env_single_source``
    fails the build if another module reads the environment directly or reintroduces a
    two-state ``os.environ.get(name, <literal>)``.
    """
    raw = os.environ.get(name)
    return EnvSetting(name=name, raw=raw, value="" if raw is None else raw.strip())


def exposure_accepted(opt_in_env: str = EXPOSURE_OPT_IN_ENV) -> bool:
    """Has the operator explicitly accepted serving the unauthenticated surface off loopback?

    A RELAXATION, so it fails closed the other way from the reads above: compared raw against
    exactly ``"1"``, with unset and set-and-empty alike meaning no opt-in. Nothing here raises,
    because "not accepted" is already the safe answer.
    """
    return os.environ.get(opt_in_env) == "1"


# --------------------------------------------------------------------------- #
# Loopback classification, shared by both halves of the guard
# --------------------------------------------------------------------------- #
def is_loopback_host(host: str | None) -> bool:
    """Is ``host`` a loopback address (the whole 127/8 block, ``::1``, ``localhost``)?

    Fails CLOSED on anything it cannot classify, including ``None``: a transport that reports no
    peer address is not evidence of a loopback peer. Used at start-up and on the serving path,
    so "loopback" means the same thing in both.
    """
    if not host:
        return False
    candidate = host.strip().lower()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    if candidate in _LOOPBACK_HOSTS:
        return True
    # IPv4-mapped IPv6 (``::ffff:127.0.0.1``), which uvicorn reports on a dual-stack socket.
    if candidate.startswith("::ffff:"):
        candidate = candidate[len("::ffff:") :]
    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# Start-up half: the bind guard
# --------------------------------------------------------------------------- #
def resolve_bind_host(
    *,
    host_env: str = BIND_HOST_ENV,
    opt_in_env: str = EXPOSURE_OPT_IN_ENV,
) -> str:
    """Return the host to bind, refusing to expose the unauthenticated surface off loopback.

    ``<host_env>`` is read in three states. Unset takes :data:`LOOPBACK_BIND`, because this
    service authenticates nobody. Set and EMPTY raises :class:`ConfiguredEmptyError`: an empty
    string is not a host, and inheriting a default would mean binding on a value nobody chose.
    Set and valid is used, stripped, so the value the guard judges is exactly the value returned
    (a trailing newline out of a config map would otherwise pass the guard and then fail the
    bind). A non-loopback host raises :class:`InsecureBindError` unless ``<opt_in_env>=1``.
    """
    setting = read_env_setting(host_env).require_not_configured_empty("a host to bind")
    host = setting.value if setting.has_value else LOOPBACK_BIND
    if not is_loopback_host(host) and not exposure_accepted(opt_in_env):
        raise InsecureBindError(
            f"refusing to bind the unauthenticated DLP API on {host!r}: every route, including "
            f"the four that accept raw personal data in the request body, is reachable without "
            f"credentials. {_HOW_TO_ACCEPT}"
        )
    return host


def resolve_bind_port(*, port_env: str = BIND_PORT_ENV) -> int:
    """Return the TCP port to bind, in three states, rejecting anything that is not a port."""
    setting = read_env_setting(port_env).require_not_configured_empty("a port to bind")
    if not setting.has_value:
        return DEFAULT_PORT
    try:
        port = int(setting.value)
    except ValueError:
        raise ValueError(f"{port_env} must be an integer port, got {setting.value!r}") from None
    if not 1 <= port <= 65535:
        raise ValueError(f"{port_env} must be within 1..65535, got {port}")
    return port


# --------------------------------------------------------------------------- #
# Cross-origin allowlist
# --------------------------------------------------------------------------- #
def cors_allowlist(*, origins_env: str = CORS_ORIGINS_ENV) -> list[str]:
    """The explicit cross-origin allowlist (never ``*``, in any state).

    Granting cross-origin trust is a RELAXATION, so the fail-closed direction is to grant
    nothing:

    * **unset**: ``[]``. No browser origin is trusted, which is what this service does today;
      it has no UI of its own and its callers are server-side.
    * **set and empty**: ``[]``. An intent was expressed and it names no origin, so it denies.
      A list that parses to no origin (``","``) is the same state and lands in the same place.
    * **set and valid**: the comma-separated origins, each stripped.

    A wildcard raises :class:`InsecureCorsError` rather than being silently dropped: an
    operator who typed ``*`` in front of an unauthenticated write surface must be told, not
    quietly overruled.
    """
    setting = read_env_setting(origins_env)
    origins = [origin.strip() for origin in setting.value.split(",") if origin.strip()]
    if "*" in origins:
        raise InsecureCorsError(
            f"{origins_env} names '*': the DLP API authenticates nobody, so a wildcard origin "
            "would let any page in a browser post personal data to it and read the response. "
            "List the exact origins instead."
        )
    return origins


# --------------------------------------------------------------------------- #
# Request-time half: the exposure guard
# --------------------------------------------------------------------------- #
Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]


class LoopbackExposureGuard:
    """ASGI middleware refusing to serve the unauthenticated API to a non-loopback peer.

    :func:`resolve_bind_host` bounds the same exposure, but only in the process that CALLS it: a
    service started with ``uvicorn <module>:app --host 0.0.0.0`` never reaches that call, so the
    bind guard is a property of one entry point rather than of the application. This middleware
    puts the guard on the app object, so it holds however the app is served.

    A request is refused unless ``<opt_in_env>=1`` and either:

    * its ASGI-scope peer address is not loopback, or
    * it carries an ``x-forwarded-for`` or ``forwarded`` header at all. The value is never
      parsed and the real peer is never re-derived: a proxy has already overwritten
      ``scope["client"]`` before application middleware runs, so the header's presence is the
      only honest signal, and a genuinely loopback-only run has no proxy in front of it.

    HTTP scopes are refused with 503; WebSocket scopes are closed with 1008 before the
    handshake. Every other scope type (``lifespan``) is forwarded untouched. Pure ASGI, with no
    framework import, so the offline gate exercises it without installing the ``[api]`` extra.
    """

    def __init__(self, app: Any, *, opt_in_env: str = EXPOSURE_OPT_IN_ENV) -> None:
        self.app = app
        self.opt_in_env = opt_in_env

    def refusal_reason(self, scope: Scope) -> str | None:
        """Why this request must be refused, or ``None`` when it may proceed."""
        if exposure_accepted(self.opt_in_env):
            return None
        client = scope.get("client")
        peer = client[0] if client else None
        if not is_loopback_host(peer):
            return (
                "refusing to serve the unauthenticated DLP API to a non-loopback peer. "
                + _HOW_TO_ACCEPT
            )
        for name, _value in scope.get("headers") or ():
            if bytes(name).lower() in _FORWARDING_HEADERS:
                return (
                    "refusing to serve the unauthenticated DLP API through a proxy: the "
                    "forwarding header means the loopback peer is the proxy, not the client. "
                    + _HOW_TO_ACCEPT
                )
        return None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        scope_type = scope.get("type")
        if scope_type not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        reason = self.refusal_reason(scope)
        if reason is None:
            await self.app(scope, receive, send)
            return
        if scope_type == "websocket":
            # Refuse before the handshake: consume the connect event, then close. The reason
            # rides the close frame, truncated to what a control frame may carry.
            message = await receive()
            if message.get("type") == "websocket.connect":
                await send(
                    {
                        "type": "websocket.close",
                        "code": _WS_POLICY_VIOLATION,
                        "reason": reason[:120],
                    }
                )
            return
        body = json.dumps({"detail": reason}).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": 503,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
