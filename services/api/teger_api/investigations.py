"""Investigation routes: cases, approvals, trusted context, and the public fixture demo.

Live routes require a tenant API key with the right scope. Demo routes need no key but
are rate-limited per IP, only ever run inert fixtures, and are namespaced per visitor
session (``demo:<session>``), which can never collide with a real tenant.
"""
# No `from __future__ import annotations`: FastAPI must resolve closure-local Depends().

import re
from collections.abc import Callable
from typing import Annotated

import anthropic
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, ValidationError

from teger_ai_analyst import AnalystSettings, ClaudeAnalyst, is_valid_byok_key
from teger_investigator.demo import DEMO_CASES, DEMO_CONTEXT, demo_fetcher
from teger_investigator.fetch import RemoteFetcher, UnavailableFetcher
from teger_investigator.models import (
    ApprovalDecision,
    Case,
    CaseInput,
    CaseSummary,
    ContextEntry,
    ContextEntryInput,
    ExecuteRequest,
    Mode,
    ProposedAction,
    ResolutionInput,
)
from teger_investigator.planner import ClaudePlanner, DeterministicPlanner
from teger_investigator.service import InvalidState, InvestigationService, Limits, NotFound, RunConfig
from teger_investigator.store import Store
from teger_security_core.detectors.reputation import MockReputationProvider, UnconfiguredReputationProvider

from .keys import Principal
from .ratelimit import SlidingWindowLimiter
from .settings import ApiSettings

_DEMO_SESSION = re.compile(r"[a-f0-9]{32}")
DEMO_ACTOR = "Demo reviewer (you)"


class DemoStart(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fixture_id: str


def _actor(principal: Principal) -> str:
    return f"API key {principal.key_id} ({principal.tenant_id})"


def mount_investigations(
    app: FastAPI,
    settings: ApiSettings,
    authenticate: Callable,
    require: Callable[[str], Callable],
    client_ip: Callable[[Request], str],
    analyst: ClaudeAnalyst,
    analyst_settings: AnalystSettings | None = None,
    anthropic_factory: Callable[[str | None], object] | None = None,
) -> InvestigationService:
    store = Store(settings.db_path or ":memory:")
    service = InvestigationService(store, max_concurrent=settings.investigation_concurrency)
    analyst_settings = analyst_settings or analyst.settings
    anthropic_factory = anthropic_factory or (
        lambda key: anthropic.Anthropic(api_key=key, timeout=analyst_settings.timeout_seconds, max_retries=1)
        if key else anthropic.Anthropic(timeout=analyst_settings.timeout_seconds, max_retries=1)
    )
    demo_limiter = SlidingWindowLimiter(settings.demo_ip_rate_limit_per_minute)
    app.state.investigations = service

    live_limits = Limits(max_steps=settings.investigation_max_steps,
                         deadline_seconds=settings.investigation_deadline_seconds)
    demo_limits = Limits(max_steps=settings.investigation_max_steps, deadline_seconds=60,
                         step_delay_seconds=settings.demo_step_delay_ms / 1000)

    def live_fetcher():
        if settings.fetch_worker_url:
            return RemoteFetcher(settings.fetch_worker_url, settings.fetch_worker_token)
        return UnavailableFetcher()

    def live_reputation():
        if settings.reputation_provider == "mock":
            return MockReputationProvider.from_fixture()
        return UnconfiguredReputationProvider()

    def live_config(inp: CaseInput, principal: Principal, byok: str | None) -> RunConfig:
        if inp.ai_planning:
            if not inp.cloud_ai_consent:
                raise HTTPException(400, "Model-assisted planning needs cloud_ai_consent=true (redacted "
                                         "observations are sent to Anthropic).")
            if byok is None and not (principal.cloud_ai_allowed and analyst.available):
                raise HTTPException(400, "Model-assisted planning is not available: supply your own Anthropic key "
                                         "(BYOK) or ask an administrator to enable Teger's key for this API key.")
            client = anthropic_factory(byok)
            return RunConfig(
                fetcher=live_fetcher(), reputation=live_reputation(),
                planner_factory=lambda: ClaudePlanner(analyst_settings, client,
                                                      max_model_calls=settings.investigation_max_steps),
                planner_label=f"Claude planner ({analyst_settings.model}) with deterministic fallback"
                              + (" — your key" if byok else ""),
                limits=live_limits,
            )
        return RunConfig(fetcher=live_fetcher(), reputation=live_reputation(), planner_factory=DeterministicPlanner,
                         planner_label="deterministic planner", limits=live_limits)

    def demo_config() -> RunConfig:
        return RunConfig(fetcher=demo_fetcher(), reputation=None, planner_factory=DeterministicPlanner,
                         planner_label="deterministic planner · simulated on synthetic fixtures", limits=demo_limits)

    def guard(fn):
        try:
            return fn()
        except NotFound as exc:
            raise HTTPException(404, str(exc)) from None
        except InvalidState as exc:
            raise HTTPException(409, str(exc)) from None

    # ------------------------------------------------------------------ live: cases

    @app.get("/v1/cases", response_model=list[CaseSummary], tags=["investigations"])
    def list_cases(principal: Annotated[Principal, Depends(require("cases:read"))],
                   limit: Annotated[int, Query(ge=1, le=100)] = 50):
        return store.list_cases(principal.tenant_id, limit)

    @app.post("/v1/cases", response_model=Case, status_code=201, tags=["investigations"])
    def create_case(
        body: CaseInput,
        principal: Annotated[Principal, Depends(require("cases:write"))],
        anthropic_key: Annotated[str | None, Header(alias="X-Anthropic-Api-Key")] = None,
    ):
        byok = (anthropic_key or "").strip() or None
        if byok is not None and not is_valid_byok_key(byok):
            raise HTTPException(400, "The X-Anthropic-Api-Key header is not a valid Anthropic API key.")
        config = live_config(body, principal, byok if body.ai_planning else None)
        return service.create_case(principal.tenant_id, Mode.LIVE, body, config, _actor(principal))

    @app.get("/v1/cases/{case_id}", response_model=Case, tags=["investigations"])
    def get_case(case_id: str, principal: Annotated[Principal, Depends(require("cases:read"))]):
        return guard(lambda: service.get_case(principal.tenant_id, case_id))

    @app.get("/v1/cases/{case_id}/events", tags=["investigations"])
    def case_events(case_id: str, principal: Annotated[Principal, Depends(require("cases:read"))],
                    after: Annotated[int, Query(ge=0)] = 0):
        guard(lambda: service.get_case(principal.tenant_id, case_id))
        return store.events(principal.tenant_id, case_id, after)

    @app.post("/v1/cases/{case_id}/cancel", response_model=Case, tags=["investigations"])
    def cancel_case(case_id: str, principal: Annotated[Principal, Depends(require("cases:write"))]):
        return guard(lambda: service.cancel(principal.tenant_id, case_id, _actor(principal)))

    @app.post("/v1/cases/{case_id}/retry", response_model=Case, tags=["investigations"])
    def retry_case(case_id: str, principal: Annotated[Principal, Depends(require("cases:write"))]):
        case = guard(lambda: service.get_case(principal.tenant_id, case_id))
        config = live_config(case.input.model_copy(update={"ai_planning": False}), principal, None)
        return guard(lambda: service.retry(principal.tenant_id, case_id, config, _actor(principal)))

    @app.post("/v1/cases/{case_id}/resolution", response_model=Case, tags=["investigations"])
    def resolve_case(case_id: str, body: ResolutionInput,
                     principal: Annotated[Principal, Depends(require("actions:approve"))]):
        return guard(lambda: service.resolve(principal.tenant_id, case_id, body, _actor(principal)))

    @app.get("/v1/cases/{case_id}/export", tags=["investigations"])
    def export_case(case_id: str, principal: Annotated[Principal, Depends(require("cases:read"))]):
        return guard(lambda: service.export(principal.tenant_id, case_id))

    # ------------------------------------------------------------------ live: approvals

    @app.post("/v1/actions/{action_id}/approve", response_model=ProposedAction, tags=["approvals"])
    def approve(action_id: str, body: ApprovalDecision,
                principal: Annotated[Principal, Depends(require("actions:approve"))]):
        return guard(lambda: service.decide(principal.tenant_id, action_id, body, _actor(principal), approve=True))

    @app.post("/v1/actions/{action_id}/reject", response_model=ProposedAction, tags=["approvals"])
    def reject(action_id: str, body: ApprovalDecision,
               principal: Annotated[Principal, Depends(require("actions:approve"))]):
        return guard(lambda: service.decide(principal.tenant_id, action_id, body, _actor(principal), approve=False))

    @app.post("/v1/actions/{action_id}/execute", response_model=ProposedAction, tags=["approvals"])
    def execute(action_id: str, body: ExecuteRequest,
                principal: Annotated[Principal, Depends(require("actions:approve"))]):
        return guard(lambda: service.execute(principal.tenant_id, action_id, body.idempotency_key,
                                             _actor(principal)))

    # ------------------------------------------------------------------ live: context & history

    @app.get("/v1/context", response_model=list[ContextEntry], tags=["context"])
    def list_context(principal: Annotated[Principal, Depends(require("cases:read"))]):
        return store.list_context(principal.tenant_id)

    @app.post("/v1/context", response_model=ContextEntry, status_code=201, tags=["context"])
    def add_context(body: ContextEntryInput, principal: Annotated[Principal, Depends(require("context:write"))]):
        return service.add_context(principal.tenant_id, body, _actor(principal))

    @app.delete("/v1/context/{entry_id}", response_model=ContextEntry, tags=["context"])
    def revoke_context(entry_id: str, principal: Annotated[Principal, Depends(require("context:write"))]):
        return guard(lambda: service.revoke_context(principal.tenant_id, entry_id, _actor(principal)))

    @app.get("/v1/activity", tags=["context"])
    def activity(principal: Annotated[Principal, Depends(require("cases:read"))],
                 limit: Annotated[int, Query(ge=1, le=200)] = 100):
        return store.activity(principal.tenant_id, limit)

    @app.get("/v1/blocklist", tags=["context"])
    def blocklist(principal: Annotated[Principal, Depends(require("cases:read"))]):
        return store.blocklist(principal.tenant_id)

    # ------------------------------------------------------------------ public demo (fixtures only)

    def demo_tenant(request: Request,
                    session: Annotated[str, Header(alias="X-Teger-Demo-Session")] = "") -> str:
        if not settings.demo_enabled:
            raise HTTPException(404, "The public demo is disabled on this server.")
        allowed, retry_after = demo_limiter.check(f"demo-ip:{client_ip(request)}")
        if not allowed:
            raise HTTPException(429, "Rate limit exceeded.", headers={"Retry-After": str(retry_after)})
        if not _DEMO_SESSION.fullmatch(session or ""):
            raise HTTPException(400, "Missing or invalid demo session.")
        tenant = f"demo:{session}"
        if store.touch_demo_session(tenant):
            store.purge_demo_sessions()
            for entry in DEMO_CONTEXT:
                store.add_context(tenant, entry)
        return tenant

    Demo = Annotated[str, Depends(demo_tenant)]

    @app.get("/v1/demo/catalog", tags=["demo"])
    def demo_catalog():
        return [{"id": c.id, "label": c.label, "teaser": c.teaser, "subject": c.input.subject,
                 "sender": c.input.sender} for c in DEMO_CASES.values()]

    @app.post("/v1/demo/session/reset", tags=["demo"])
    def demo_reset(tenant: Demo):
        store.delete_tenant(tenant)
        return {"reset": True}

    @app.get("/v1/demo/cases", response_model=list[CaseSummary], tags=["demo"])
    def demo_list(tenant: Demo):
        return store.list_cases(tenant, 50)

    @app.post("/v1/demo/cases", response_model=Case, status_code=201, tags=["demo"])
    def demo_start(body: DemoStart, tenant: Demo):
        fixture = DEMO_CASES.get(body.fixture_id)
        if fixture is None:
            raise HTTPException(404, "Unknown demo case.")
        if len(store.list_cases(tenant, 30)) >= 30:
            raise HTTPException(409, "Demo case limit reached. Reset the demo to start again.")
        return service.create_case(tenant, Mode.DEMO, fixture.input, demo_config(), DEMO_ACTOR,
                                   fixture_id=fixture.id, title=f"{fixture.label}: {fixture.input.subject}")

    @app.get("/v1/demo/cases/{case_id}", response_model=Case, tags=["demo"])
    def demo_get(case_id: str, tenant: Demo):
        return guard(lambda: service.get_case(tenant, case_id))

    @app.get("/v1/demo/cases/{case_id}/events", tags=["demo"])
    def demo_events(case_id: str, tenant: Demo, after: Annotated[int, Query(ge=0)] = 0):
        guard(lambda: service.get_case(tenant, case_id))
        return store.events(tenant, case_id, after)

    @app.post("/v1/demo/cases/{case_id}/cancel", response_model=Case, tags=["demo"])
    def demo_cancel(case_id: str, tenant: Demo):
        return guard(lambda: service.cancel(tenant, case_id, DEMO_ACTOR))

    @app.post("/v1/demo/cases/{case_id}/retry", response_model=Case, tags=["demo"])
    def demo_retry(case_id: str, tenant: Demo):
        return guard(lambda: service.retry(tenant, case_id, demo_config(), DEMO_ACTOR))

    @app.post("/v1/demo/cases/{case_id}/resolution", response_model=Case, tags=["demo"])
    def demo_resolve(case_id: str, body: ResolutionInput, tenant: Demo):
        return guard(lambda: service.resolve(tenant, case_id, body, DEMO_ACTOR))

    @app.get("/v1/demo/cases/{case_id}/export", tags=["demo"])
    def demo_export(case_id: str, tenant: Demo):
        return guard(lambda: service.export(tenant, case_id))

    @app.post("/v1/demo/actions/{action_id}/{decision}", response_model=ProposedAction, tags=["demo"])
    def demo_action(action_id: str, decision: str, tenant: Demo, body: Annotated[dict, Body()]):
        try:
            if decision in {"approve", "reject"}:
                parsed = ApprovalDecision.model_validate(body)
            elif decision == "execute":
                parsed_exec = ExecuteRequest.model_validate(body)
        except ValidationError:
            raise HTTPException(422, "Invalid request body.") from None
        if decision in {"approve", "reject"}:
            return guard(lambda: service.decide(tenant, action_id, parsed, DEMO_ACTOR, approve=decision == "approve"))
        if decision == "execute":
            return guard(lambda: service.execute(tenant, action_id, parsed_exec.idempotency_key, DEMO_ACTOR))
        raise HTTPException(404, "Unknown decision.")

    @app.get("/v1/demo/context", response_model=list[ContextEntry], tags=["demo"])
    def demo_context(tenant: Demo):
        return store.list_context(tenant)

    @app.get("/v1/demo/activity", tags=["demo"])
    def demo_activity(tenant: Demo):
        return store.activity(tenant, 100)

    @app.get("/v1/demo/blocklist", tags=["demo"])
    def demo_blocklist(tenant: Demo):
        return store.blocklist(tenant)

    return service
