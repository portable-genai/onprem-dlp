"""The REST app object carries the exposure guard, however it is served.

The functional half needs the ``[api]`` extra, which the offline gate deliberately does not
install (the core is stdlib-only). So the wiring itself is asserted from source, which is what
actually runs in CI, and the end-to-end assertion runs wherever FastAPI is present.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_APP = Path(__file__).resolve().parents[2] / "src" / "onprem_dlp" / "api" / "app.py"


def test_create_app_installs_the_guard_and_never_a_wildcard_origin():
    source = _APP.read_text(encoding="utf-8")
    assert "app.add_middleware(LoopbackExposureGuard)" in source
    assert "allow_origins=origins" in source
    assert 'allow_origins=["*"]' not in source
    assert "allow_credentials=False" in source
    # The guard is added last so Starlette runs it outermost, ahead of any CORS handling.
    assert source.index("CORSMiddleware,") < source.index(
        "app.add_middleware(LoopbackExposureGuard)"
    )


def test_the_documented_run_command_is_the_guarded_one():
    """The module docstring used to tell operators to bind 0.0.0.0 by hand."""
    source = _APP.read_text(encoding="utf-8")
    assert "python -m onprem_dlp.api.serve" in source
    assert "--host 0.0.0.0 --port 8484" not in source


def test_the_entry_point_exits_two_on_a_refused_bind_without_needing_uvicorn(monkeypatch, capsys):
    """The refusal path is fully stdlib: no listening socket, no traceback, a named variable."""
    from onprem_dlp.api.serve import main

    monkeypatch.setenv("ONPREM_DLP_API_HOST", "0.0.0.0")
    monkeypatch.delenv("ONPREM_DLP_ALLOW_UNAUTHENTICATED_EXPOSURE", raising=False)
    assert main() == 2
    assert "ONPREM_DLP_ALLOW_UNAUTHENTICATED_EXPOSURE" in capsys.readouterr().err


def test_the_entry_point_exits_two_on_a_configured_empty_host(monkeypatch, capsys):
    from onprem_dlp.api.serve import main

    monkeypatch.setenv("ONPREM_DLP_API_HOST", "")
    assert main() == 2
    assert "ONPREM_DLP_API_HOST" in capsys.readouterr().err


def test_a_remote_peer_is_refused_end_to_end(monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from onprem_dlp.api.app import create_app

    monkeypatch.delenv("ONPREM_DLP_ALLOW_UNAUTHENTICATED_EXPOSURE", raising=False)
    client = TestClient(create_app("/nonexistent/nothing.yaml"), client=("198.51.100.7", 40000))
    assert client.post("/v1/egress/decide", json={"text": "NRIC S1234567D"}).status_code == 503
    assert client.get("/healthz").status_code == 503
