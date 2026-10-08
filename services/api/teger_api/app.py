"""Teger AI v1 security API."""
# No `from __future__ import annotations`: FastAPI must resolve closure-local Depends().

import re
import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from teger_ai_analyst import AnalystSettings, ClaudeAnalyst, is_valid_byok_key
from teger_contracts import (
    AiExplanation,
    AiExplanationStatus,
    AnalysisRequest,
    AnalysisSummary,
    ThreatVerdict,
)
from teger_security_core import ThreatEngine, UrlValidationError
from teger_security_core.detectors.reputation import MockReputationProvider, UnconfiguredReputationProvider
from teger_security_core.policy import MALICIOUS_THRESHOLD, POLICY_VERSION, SUSPICIOUS_THRESHOLD

from .audit import AuditLog, configure_logging
from .capabilities import capabilities
from .keys import ApiKeyStore, Principal
from .ratelimit import SlidingWindowLimiter
from .settings import ApiSettings
from .store import AnalysisStore

API_VERSION = "1.0.0-experimental"
_REQUEST_ID = re.compile(r"[A-Za-z0-9-]{8,64}")
_DOC_PATHS = ("/docs", "/redoc", "/openapi.json")


class BodySizeLimitMiddleware:
    """Rejects bodies over ``max_bytes`` whether or not Content-Length is sent.

    The (small, bounded) body is buffered before the app runs, so chunked uploads are
    measured before any parsing happens.
    """

    def __init__(self, app: ASGIApp, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        for name, value in scope.get("headers", []):
            if name == b"content-length" and (not value.isdigit() or int(value) > self.max_bytes):
                await self._reject(send)
                return

        chunks: list[bytes] = []
        received = 0
        while True:
            message = await receive()
            if message["type"] != "http.request":
                break
            chunk = message.get("body", b"")
            received += len(chunk)
            if received > self.max_bytes:
                await self._reject(send)
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break

        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)

    @staticmethod
    async def _reject(send: Send) -> None:
        body = b'{"detail":"Request body too large."}'
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})


class Health(BaseModel):
    status: str
    version: str


def _client_ip(request: Request, trust_proxy: bool) -> str:
    if trust_proxy:
        forwarded = request.headers.get("x-forwarded-for", "")
        # The right-most entry is the one appended by our own (trusted) proxy.
        hops = [h.strip() for h in forwarded.split(",") if h.strip()]
        if hops:
            return hops[-1]
    return request.client.host if request.client else "unknown"


def create_app(
    settings: ApiSettings | None = None,
    analyst: ClaudeAnalyst | None = None,
    key_store: ApiKeyStore | None = None,
) -> FastAPI:
    settings = settings or ApiSettings.from_env()
    settings.validate()
    configure_logging()

    keys = key_store if key_store is not None else ApiKeyStore.from_config(
        settings.api_keys_json, settings.api_keys_file
    )
    provider = (
        MockReputationProvider.from_fixture() if settings.reputation_provider == "mock"
        else UnconfiguredReputationProvider()
    )
    engine = ThreatEngine(provider)
    if analyst is None:
        analyst = ClaudeAnalyst(AnalystSettings.from_env())
    store = AnalysisStore(settings.max_analyses_per_tenant)
    audit = AuditLog()
    key_limiter = SlidingWindowLimiter(settings.key_rate_limit_per_minute)
    ip_limiter = SlidingWindowLimiter(settings.ip_rate_limit_per_minute)

    app = FastAPI(
        title="Teger AI Security API",
        version=API_VERSION,
        description=(
            "Experimental v1 threat-analysis API. Verdicts are produced by Teger's deterministic policy "
            "engine; optional AI explanations never change them. Responses flag mock intelligence explicitly."
        ),
        docs_url="/docs" if settings.expose_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.expose_docs else None,
    )
    app.state.settings = settings
    app.state.store = store
    app.state.audit = audit
    app.state.analyst = analyst

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.cors_origins),
            allow_methods=["GET", "POST"],
            allow_headers=["Authorization", "Content-Type", "X-Request-ID", "X-Anthropic-Api-Key"],
            allow_credentials=False,
        )

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        incoming = request.headers.get("x-request-id", "")
        request.state.request_id = incoming if _REQUEST_ID.fullmatch(incoming) else uuid.uuid4().hex
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        if not request.url.path.startswith(_DOC_PATHS):
            response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        if settings.environment == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_body_bytes)

    # ------------------------------------------------------------------ errors

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError):
        # Never echo submitted input back (it may be sensitive or hostile).
        errors = [
            {"loc": [str(p) for p in e.get("loc", ())], "msg": str(e.get("msg", ""))[:200], "type": e.get("type")}
            for e in exc.errors()
        ][:20]
        return JSONResponse(status_code=422, content={"detail": errors})

    @app.exception_handler(StarletteHTTPException)
    async def http_handler(request: Request, exc: StarletteHTTPException):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail},
                            headers=getattr(exc, "headers", None))

    @app.exception_handler(Exception)
    async def unhandled_handler(request: Request, exc: Exception):
        request_id = getattr(request.state, "request_id", "unknown")
        audit.emit("api.error", request_id=request_id, outcome="error", error_type=type(exc).__name__)
        return JSONResponse(status_code=500, content={"detail": "Internal error.", "request_id": request_id},
                            headers={"X-Request-ID": request_id})

    # ------------------------------------------------------------------ auth

    def authenticate(request: Request) -> Principal:
        request_id = request.state.request_id
        ip = _client_ip(request, settings.trust_proxy_headers)
        allowed, retry = ip_limiter.check(f"ip:{ip}")
        if not allowed:
            audit.emit("rate_limit.exceeded", request_id=request_id, outcome="denied", scope="ip")
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Rate limit exceeded.",
                                headers={"Retry-After": str(retry)})
        header = request.headers.get("authorization", "")
        scheme, _, token = header.partition(" ")
        principal = keys.authenticate(token.strip()) if scheme.lower() == "bearer" else None
        if principal is None:
            audit.emit("auth.failure", request_id=request_id, outcome="denied",
                       reason="missing" if not header else "invalid")
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or missing API key.",
                                headers={"WWW-Authenticate": "Bearer"})
        allowed, retry = key_limiter.check(f"key:{principal.key_id}")
        if not allowed:
            audit.emit("rate_limit.exceeded", request_id=request_id, outcome="denied", scope="key",
                       tenant_id=principal.tenant_id, key_id=principal.key_id)
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Rate limit exceeded.",
                                headers={"Retry-After": str(retry)})
        return principal

    def require(scope: str):
        def dependency(request: Request, principal: Annotated[Principal, Depends(authenticate)]) -> Principal:
            if scope not in principal.scopes:
                audit.emit("authz.denied", request_id=request.state.request_id, outcome="denied",
                           tenant_id=principal.tenant_id, key_id=principal.key_id, scope=scope)
                raise HTTPException(status.HTTP_403_FORBIDDEN, "API key lacks the required scope.")
            return principal
        return dependency

    # ------------------------------------------------------------------ routes

    @app.get("/healthz", response_model=Health, tags=["ops"])
    def healthz() -> Health:
        return Health(status="ok", version=API_VERSION)

    @app.get("/readyz", tags=["ops"])
    def readyz():
        components = {
            "api_keys": "configured" if len(keys) else "missing",
            "reputation_provider": settings.reputation_provider,
            "ai_analyst": "configured" if analyst.available else "disabled",
            "ai_byok": "allowed" if analyst.byok_available else "disabled",
            "storage": "in_memory",
            "rate_limiter": "in_memory",
        }
        ready = len(keys) > 0
        return JSONResponse(status_code=200 if ready else 503,
                            content={"status": "ready" if ready else "not_ready", "components": components})

    @app.get("/v1/capabilities", tags=["meta"])
    def get_capabilities():
        return capabilities(settings.reputation_provider, analyst.available, analyst.byok_available)

    @app.get("/v1/whoami", tags=["meta"])
    def whoami(principal: Annotated[Principal, Depends(authenticate)]):
        return {"tenant_id": principal.tenant_id, "key_id": principal.key_id,
                "scopes": sorted(principal.scopes), "cloud_ai_allowed": principal.cloud_ai_allowed}

    @app.get("/v1/policy", tags=["meta"])
    def policy(principal: Annotated[Principal, Depends(authenticate)]):
        return {
            "policy_version": POLICY_VERSION,
            "malicious_threshold": MALICIOUS_THRESHOLD,
            "suspicious_threshold": SUSPICIOUS_THRESHOLD,
            "unknown_when_required_intelligence_unavailable": True,
            "ai_can_change_verdict": False,
            "reputation_provider": settings.reputation_provider,
        }

    @app.post("/v1/analyses", response_model=ThreatVerdict, status_code=201, tags=["analysis"])
    def create_analysis(
        body: AnalysisRequest,
        request: Request,
        principal: Annotated[Principal, Depends(require("analyses:write"))],
        anthropic_key: Annotated[str | None, Header(
            alias="X-Anthropic-Api-Key",
            description="Optional: your own Anthropic API key (BYOK) for the AI explanation. "
                        "Used for this request only; never stored or logged.",
        )] = None,
    ) -> ThreatVerdict:
        byok_key = (anthropic_key or "").strip() or None
        if byok_key is not None and not is_valid_byok_key(byok_key):
            raise HTTPException(400, "The X-Anthropic-Api-Key header is not a valid Anthropic API key.")
        try:
            result = engine.analyze(url=body.url, content=body.content, content_type=body.content_type,
                                    sender=body.sender, subject=body.subject)
        except UrlValidationError as exc:
            raise HTTPException(422, str(exc)) from None

        decision = result.decision
        if not body.explain:
            explanation = AiExplanation(status=AiExplanationStatus.NOT_REQUESTED)
        elif not body.cloud_ai_consent:
            explanation = AiExplanation(status=AiExplanationStatus.CONSENT_REQUIRED,
                                        detail="Set cloud_ai_consent=true to send redacted content to the AI provider.")
        elif byok_key is None and not principal.cloud_ai_allowed:
            explanation = AiExplanation(
                status=AiExplanationStatus.NOT_PERMITTED,
                detail="Teger's AI key is not enabled for this API key. Supply your own Anthropic key (BYOK).",
            )
        elif byok_key is None and not analyst.available:
            explanation = AiExplanation(
                status=AiExplanationStatus.UNAVAILABLE,
                detail="Teger's AI key is not configured on this server. Supply your own Anthropic key (BYOK).",
            )
        else:
            explanation = analyst.explain(
                tenant_id=principal.tenant_id, verdict=decision.verdict, risk_score=decision.risk_score,
                recommended_action=decision.action.value, policy_version=decision.policy_version,
                evidence=result.evidence, content=result.subject.content,
                url=result.url.normalized if result.url else None,
                sender=result.subject.sender or None, subject=result.subject.subject or None,
                api_key=byok_key,
            )

        verdict = ThreatVerdict(
            analysis_id=f"an_{uuid.uuid4().hex}",
            created_at=datetime.now(timezone.utc),
            verdict=decision.verdict,
            risk_score=decision.risk_score,
            confidence=decision.confidence,
            recommended_action=decision.action,
            recommended_action_text=decision.action_text,
            evidence=result.evidence,
            detection_sources=result.reports,
            intelligence_coverage=decision.coverage,
            mock_intelligence_used=result.mock_intelligence_used,
            policy_version=decision.policy_version,
            url=result.url.to_contract() if result.url else None,
            content_type=body.content_type,
            explanation=explanation,
        )
        store.put(principal.tenant_id, verdict)
        audit.emit(
            "analysis.created", request_id=request.state.request_id, outcome="success",
            tenant_id=principal.tenant_id, key_id=principal.key_id, analysis_id=verdict.analysis_id,
            verdict=verdict.verdict.value, risk_score=verdict.risk_score, evidence_count=len(verdict.evidence),
            url_host=verdict.url.host if verdict.url else None, mock_intelligence=verdict.mock_intelligence_used,
            ai_status=explanation.status.value,
            ai_key_source=explanation.key_source,
            ai_tokens=(explanation.usage.input_tokens + explanation.usage.output_tokens) if explanation.usage else 0,
        )
        return verdict

    @app.get("/v1/analyses", response_model=list[AnalysisSummary], tags=["analysis"])
    def list_analyses(
        principal: Annotated[Principal, Depends(require("analyses:read"))],
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
    ) -> list[AnalysisSummary]:
        return store.list(principal.tenant_id, limit)

    @app.get("/v1/analyses/{analysis_id}", response_model=ThreatVerdict, tags=["analysis"])
    def get_analysis(
        analysis_id: str,
        request: Request,
        principal: Annotated[Principal, Depends(require("analyses:read"))],
    ) -> ThreatVerdict:
        verdict = store.get(principal.tenant_id, analysis_id)
        if verdict is None:
            # Same response whether the ID is unknown or belongs to another tenant.
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Analysis not found.")
        audit.emit("analysis.read", request_id=request.state.request_id, outcome="success",
                   tenant_id=principal.tenant_id, key_id=principal.key_id, analysis_id=analysis_id)
        return verdict

    @app.get("/v1/events", tags=["analysis"])
    def events(
        principal: Annotated[Principal, Depends(require("analyses:read"))],
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
    ):
        return audit.recent(principal.tenant_id, limit)

    return app
