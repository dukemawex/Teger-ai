"""Opt-in anonymous, stateless analysis with the real local detection engine.

No tenant credentials, persistence, cloud AI, reputation fixtures, DNS lookup or URL
fetching. The public budget is shared across the whole process, so spoofed client
headers cannot bypass it. Deploy one worker or add an edge/shared limiter.
"""
import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, HTTPException

from teger_contracts import AiExplanation, AiExplanationStatus, AnalysisRequest, ThreatVerdict
from teger_security_core import ThreatEngine, UrlValidationError
from teger_security_core.redaction import redact

from .ratelimit import SlidingWindowLimiter
from .settings import ApiSettings


class PublicAnalysisRequest(AnalysisRequest):
    explain: Literal[False] = False
    cloud_ai_consent: Literal[False] = False


def public_router(settings: ApiSettings) -> APIRouter:
    router = APIRouter(prefix="/v1/public", tags=["public analysis"])
    # Deliberately independent of the private console's reputation/AI configuration.
    engine = ThreatEngine()
    limiter = SlidingWindowLimiter(settings.public_scan_limit_per_minute)

    def enabled() -> None:
        if not settings.public_scan_enabled:
            raise HTTPException(404, "Public analysis is not enabled.")

    @router.get("/status")
    def scan_status():
        enabled()
        return {"available": True, "mode": "local_rules", "stores_submissions": False,
                "fetches_urls": False, "cloud_ai": False, "live_reputation": False}

    @router.post("/analyses", response_model=ThreatVerdict)
    def analyze(body: PublicAnalysisRequest) -> ThreatVerdict:
        enabled()
        allowed, retry = limiter.check("public")
        if not allowed:
            raise HTTPException(429, "Public scanner is busy. Please try again shortly.",
                                headers={"Retry-After": str(retry)})
        try:
            result = engine.analyze(url=body.url, content=body.content, content_type=body.content_type,
                                    sender=body.sender, subject=body.subject)
        except UrlValidationError as exc:
            raise HTTPException(422, str(exc)) from None
        decision = result.decision
        normalized = result.url.to_contract() if result.url else None
        if normalized:
            normalized = normalized.model_copy(update={"normalized": redact(normalized.normalized).text})
        # Return once, without adding the result to any tenant's history or audit buffer.
        return ThreatVerdict(
            analysis_id=f"pub_{uuid.uuid4().hex}", created_at=datetime.now(timezone.utc),
            verdict=decision.verdict, risk_score=decision.risk_score, confidence=decision.confidence,
            recommended_action=decision.action, recommended_action_text=decision.action_text,
            evidence=result.evidence, detection_sources=result.reports,
            intelligence_coverage=decision.coverage, mock_intelligence_used=False,
            policy_version=decision.policy_version, url=normalized, content_type=body.content_type,
            explanation=AiExplanation(status=AiExplanationStatus.NOT_REQUESTED),
        )

    return router
