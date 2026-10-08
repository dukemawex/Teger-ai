"""Environment-based configuration. The API key itself is never stored on this object;
the Anthropic SDK reads ``ANTHROPIC_API_KEY`` from the environment."""
from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

DEFAULT_MODEL = "claude-opus-5-5"
_EFFORTS = {"low", "medium", "high", "xhigh", "max"}


def _bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class AnalystSettings:
    enabled: bool = False
    api_key_present: bool = False
    model: str = DEFAULT_MODEL
    effort: str = "medium"
    max_tokens: int = 8000
    timeout_seconds: float = 45.0
    max_retries: int = 2
    refusal_fallback: bool = True
    max_content_chars: int = 12_000
    daily_token_budget_per_tenant: int = 200_000

    @property
    def configured(self) -> bool:
        return self.enabled and self.api_key_present

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "AnalystSettings":
        env = os.environ if env is None else env
        effort = env.get("TEGER_AI_EFFORT", "medium").strip().lower()
        if effort not in _EFFORTS:
            raise ValueError(f"TEGER_AI_EFFORT must be one of {sorted(_EFFORTS)}")
        return cls(
            enabled=_bool(env.get("TEGER_AI_ENABLED")),
            api_key_present=bool(env.get("ANTHROPIC_API_KEY", "").strip()),
            model=env.get("TEGER_AI_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL,
            effort=effort,
            max_tokens=int(env.get("TEGER_AI_MAX_TOKENS", "8000")),
            timeout_seconds=float(env.get("TEGER_AI_TIMEOUT_SECONDS", "45")),
            max_retries=int(env.get("TEGER_AI_MAX_RETRIES", "2")),
            refusal_fallback=_bool(env.get("TEGER_AI_REFUSAL_FALLBACK"), default=True),
            max_content_chars=int(env.get("TEGER_AI_MAX_CONTENT_CHARS", "12000")),
            daily_token_budget_per_tenant=int(env.get("TEGER_AI_DAILY_TOKEN_BUDGET", "200000")),
        )
