"""REST surface (optional extra ``[api]``): put this in front of your cloud egress.

    pip install 'onprem-dlp[api]'
    python -m onprem_dlp.api.serve      # guarded entry point; binds loopback by default

Applications call POST /v1/egress/decide (or /v1/redact/text) with the payload they
intend to send to a cloud LLM/API; only the redacted rendering ever leaves the estate,
and BLOCK responses carry the reasons for the human release queue.

**This surface authenticates nobody, in every profile.** Its four POST routes accept, by
construction, the raw personal data an application was about to send out. So the app object
carries :class:`~onprem_dlp.netguard.LoopbackExposureGuard`, which refuses any non-loopback
peer unless an operator sets ``ONPREM_DLP_ALLOW_UNAUTHENTICATED_EXPOSURE=1``. The guard rides
the app rather than the entry point on purpose: ``uvicorn onprem_dlp.api.app:create_app
--factory --host 0.0.0.0`` typed by hand is bounded by it too. See
:mod:`onprem_dlp.netguard` for the reasoning and for how to accept the exposure safely.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from ..config import Container, load_settings
from ..netguard import LoopbackExposureGuard, cors_allowlist


def _jsonable(obj: Any) -> Any:
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _jsonable(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    if hasattr(obj, "value") and not isinstance(obj, (int, float, str, bool)):
        return obj.value
    return obj


def create_app(config_path: str | None = None, profile: str | None = None):
    from fastapi import FastAPI  # lazy: optional dependency
    from pydantic import BaseModel, Field

    container = Container(load_settings(config_path), profile=profile)
    orch = container.orchestrator()

    class TextIn(BaseModel):
        text: str
        source_id: str = "api"

    class ColumnsIn(BaseModel):
        columns: dict[str, list[str | None]] = Field(
            description="column name -> sampled values (the caller keeps raw data on-prem)"
        )
        source_id: str = "api"

    app = FastAPI(
        title="onprem-dlp",
        version="0.1.0",
        description="On-prem DLP gate: scrub text/images/schemas before cloud egress.",
    )

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok", "profile": container.profile}

    @app.post("/v1/scan/text")
    def scan_text(body: TextIn) -> dict:
        return _jsonable(orch.scan_text(body.text, source_id=body.source_id))

    @app.post("/v1/redact/text")
    def redact_text(body: TextIn) -> dict:
        return _jsonable(orch.redact_text(body.text, source_id=body.source_id))

    @app.post("/v1/egress/decide")
    def decide(body: TextIn) -> dict:
        decision = orch.decide_egress(body.text, source_id=body.source_id)
        payload = _jsonable(decision)
        payload["escalates"] = decision.escalates
        return payload

    @app.post("/v1/classify/columns")
    def classify_columns(body: ColumnsIn) -> dict:
        from ..adapters.local.samplers import InlineSampler

        sampler = InlineSampler(body.columns, name=body.source_id)
        return _jsonable(orch.classify_columns(sampler, sample_limit=container.sample_limit()))

    # Middleware order: Starlette runs the LAST-added outermost, so the exposure guard is
    # added last and refuses before any CORS handling. A preflight from a peer the guard
    # rejects therefore gets a bare 503 with no cross-origin headers, which is the point.
    origins = cors_allowlist()
    if origins:
        from fastapi.middleware.cors import CORSMiddleware  # lazy: optional dependency

        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=False,
            allow_methods=["GET", "POST"],
            allow_headers=["content-type"],
        )
    app.add_middleware(LoopbackExposureGuard)

    return app
