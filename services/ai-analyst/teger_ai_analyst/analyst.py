"""Claude explanation adapter.

Claude explains Teger's deterministic evidence; it never changes the verdict. Calls
are made only when the feature is enabled, an API key is configured, the tenant is
allowed, the request carries explicit consent, and the tenant has budget left.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

import anthropic
from pydantic import BaseModel, Field, ValidationError

from teger_contracts import AiExplanation, AiExplanationStatus, AiKeyPoint, AiUsage, Evidence, Verdict
from teger_security_core.redaction import redact

from .accounting import UsageLedger, estimate_cost_usd
from .config import AnalystSettings
from .prompt import build_prompt

log = logging.getLogger("teger.ai_analyst")

PROVIDER = "anthropic"
FALLBACK_BETA = "server-side-fallback-2026-07-01"


class _ModelKeyPoint(BaseModel):
    evidence_ids: list[str] = Field(description="IDs from the evidence list, e.g. ['ev-1'].")
    explanation: str


class ModelExplanation(BaseModel):
    """Schema Claude must return. It deliberately has no verdict field."""

    summary: str = Field(description="Two or three sentences explaining the verdict.")
    key_points: list[_ModelKeyPoint]
    user_guidance: str
    injection_attempt_observed: bool


def _status(status: AiExplanationStatus, detail: str, redactions: int = 0) -> AiExplanation:
    return AiExplanation(status=status, provider=PROVIDER, detail=detail, redactions_applied=redactions)


def _clip(text: str, limit: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


class ClaudeAnalyst:
    def __init__(
        self,
        settings: AnalystSettings,
        client: Any | None = None,
        client_factory: Callable[[AnalystSettings], Any] | None = None,
        ledger: UsageLedger | None = None,
    ):
        self.settings = settings
        self._client = client
        self._client_factory = client_factory or (
            lambda s: anthropic.Anthropic(timeout=s.timeout_seconds, max_retries=s.max_retries)
        )
        self.ledger = ledger or UsageLedger(settings.daily_token_budget_per_tenant)

    @property
    def available(self) -> bool:
        return self.settings.configured or (self.settings.enabled and self._client is not None)

    def _get_client(self) -> Any:
        if self._client is None:
            self._client = self._client_factory(self.settings)
        return self._client

    def explain(
        self,
        *,
        tenant_id: str,
        verdict: Verdict,
        risk_score: int,
        recommended_action: str,
        policy_version: str,
        evidence: list[Evidence],
        content: str = "",
        url: str | None = None,
        sender: str | None = None,
        subject: str | None = None,
    ) -> AiExplanation:
        if not self.available:
            return _status(AiExplanationStatus.UNAVAILABLE, "Cloud AI analysis is not configured.")
        if not self.ledger.has_budget(tenant_id):
            return _status(AiExplanationStatus.UNAVAILABLE, "Daily AI analysis budget reached for this tenant.")

        redacted_parts = [redact(part or "") for part in (content, url, sender, subject)]
        redactions = sum(r.total for r in redacted_parts)
        content_r, url_r, sender_r, subject_r = (r.text or None for r in redacted_parts)

        prompt = build_prompt(
            verdict=verdict, risk_score=risk_score, recommended_action=recommended_action,
            policy_version=policy_version, evidence=evidence, content=content_r or "",
            url=url_r, sender=sender_r, subject=subject_r, max_content_chars=self.settings.max_content_chars,
        )

        kwargs: dict[str, Any] = dict(
            model=self.settings.model,
            max_tokens=self.settings.max_tokens,
            system=prompt.system,
            messages=[{"role": "user", "content": prompt.user}],
            output_format=ModelExplanation,
            thinking={"type": "adaptive"},
            output_config={"effort": self.settings.effort},
        )
        if self.settings.refusal_fallback:
            kwargs.update(betas=[FALLBACK_BETA], fallbacks="default")

        try:
            response = self._get_client().beta.messages.parse(**kwargs)
        except anthropic.RateLimitError:
            return _status(AiExplanationStatus.UNAVAILABLE, "AI provider rate limit reached.", redactions)
        except anthropic.APITimeoutError:
            return _status(AiExplanationStatus.UNAVAILABLE, "AI provider timed out.", redactions)
        except anthropic.APIConnectionError:
            return _status(AiExplanationStatus.UNAVAILABLE, "AI provider could not be reached.", redactions)
        except (anthropic.AuthenticationError, anthropic.PermissionDeniedError):
            log.error("Anthropic credentials rejected")
            return _status(AiExplanationStatus.UNAVAILABLE, "AI provider is misconfigured.", redactions)
        except anthropic.BadRequestError:
            log.error("Anthropic rejected the request", exc_info=False)
            return _status(AiExplanationStatus.FAILED, "AI provider rejected the request.", redactions)
        except anthropic.APIStatusError:
            return _status(AiExplanationStatus.UNAVAILABLE, "AI provider error.", redactions)
        except (ValidationError, ValueError):
            return _status(AiExplanationStatus.FAILED, "AI response did not match the required format.", redactions)

        usage = self._account(tenant_id, response)

        if getattr(response, "stop_reason", None) == "refusal":
            return AiExplanation(status=AiExplanationStatus.DECLINED, provider=PROVIDER, usage=usage,
                                 redactions_applied=redactions, detail="The AI provider declined to explain this.")
        if getattr(response, "stop_reason", None) == "max_tokens":
            return AiExplanation(status=AiExplanationStatus.FAILED, provider=PROVIDER, usage=usage,
                                 redactions_applied=redactions, detail="AI response was truncated.")
        parsed = getattr(response, "parsed_output", None)
        if not isinstance(parsed, ModelExplanation):
            return AiExplanation(status=AiExplanationStatus.FAILED, provider=PROVIDER, usage=usage,
                                 redactions_applied=redactions, detail="AI response could not be parsed.")

        return self._ground(parsed, evidence, usage, redactions)

    def _ground(self, parsed: ModelExplanation, evidence: list[Evidence], usage: AiUsage | None,
                redactions: int) -> AiExplanation:
        known = {e.id for e in evidence}
        points: list[AiKeyPoint] = []
        removed = 0
        for point in parsed.key_points:
            cited = [i for i in dict.fromkeys(point.evidence_ids) if i in known][:10]
            if not cited or not point.explanation.strip():
                removed += 1
                continue
            points.append(AiKeyPoint(evidence_ids=cited, explanation=_clip(point.explanation, 600)))
        if len(points) > 12:
            removed += len(points) - 12
            points = points[:12]
        return AiExplanation(
            status=AiExplanationStatus.COMPLETED,
            provider=PROVIDER,
            summary=_clip(parsed.summary, 1200),
            key_points=points,
            user_guidance=_clip(parsed.user_guidance, 800),
            injection_attempt_observed=bool(parsed.injection_attempt_observed),
            ungrounded_points_removed=removed,
            redactions_applied=redactions,
            usage=usage,
        )

    def _account(self, tenant_id: str, response: Any) -> AiUsage | None:
        raw = getattr(response, "usage", None)
        if raw is None:
            return None
        input_tokens = int(getattr(raw, "input_tokens", 0) or 0)
        output_tokens = int(getattr(raw, "output_tokens", 0) or 0)
        cache_read = int(getattr(raw, "cache_read_input_tokens", 0) or 0)
        cache_write = int(getattr(raw, "cache_creation_input_tokens", 0) or 0)
        # Bill against the model that actually served the request (fallbacks may differ).
        model = str(getattr(response, "model", None) or self.settings.model)
        cost = estimate_cost_usd(model, input_tokens, output_tokens, cache_read, cache_write)
        self.ledger.record(tenant_id, input_tokens + output_tokens + cache_read + cache_write, cost)
        return AiUsage(
            model=model, input_tokens=input_tokens, output_tokens=output_tokens,
            cache_read_input_tokens=cache_read, cache_creation_input_tokens=cache_write,
            estimated_cost_usd=cost,
        )
