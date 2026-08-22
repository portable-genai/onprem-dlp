"""Guarded entry point for the REST surface: ``python -m onprem_dlp.api.serve``.

An image ``CMD`` of ``uvicorn ... --host 0.0.0.0`` puts the bind decision in a string in a
Dockerfile where no guard can see it. Routing the entry point through
:func:`onprem_dlp.netguard.resolve_bind_host` moves that decision into code that fails closed:
loopback unless an operator has said otherwise, and a refusal (exit 2) rather than a silent
wide bind when they have not.

Configuration, all read in three states by :mod:`onprem_dlp.netguard`:

* ``ONPREM_DLP_API_HOST``  (unset: ``127.0.0.1``)
* ``ONPREM_DLP_API_PORT``  (unset: ``8484``)
* ``ONPREM_DLP_ALLOW_UNAUTHENTICATED_EXPOSURE=1`` to accept a non-loopback bind
"""

from __future__ import annotations

import sys

from ..netguard import (
    ConfiguredEmptyError,
    InsecureBindError,
    InsecureCorsError,
    resolve_bind_host,
    resolve_bind_port,
)


def main(argv: list[str] | None = None) -> int:
    """Resolve the bind through the guard, then serve. Returns a process exit code.

    Every refusal the guards can raise is turned into exit 2 with the message on stderr, so a
    misconfigured deployment stops with an explanation naming the variable rather than either
    a traceback or, worse, a listening socket nobody chose. Building the app is inside the
    same block on purpose: ``create_app`` resolves the CORS allowlist, which refuses a
    wildcard origin, and that refusal deserves the same treatment as a refused bind.
    """
    from .app import create_app  # importable without FastAPI; the extra is imported inside it

    try:
        host = resolve_bind_host()
        port = resolve_bind_port()
        app = create_app()
    except (
        ConfiguredEmptyError,
        InsecureBindError,
        InsecureCorsError,
        FileNotFoundError,
        ValueError,
    ) as exc:
        print(f"onprem-dlp: {exc}", file=sys.stderr)
        return 2

    import uvicorn  # lazy: optional dependency, part of the [api] extra, and only needed

    uvicorn.run(app, host=host, port=port)  # once a bind has actually been granted
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
