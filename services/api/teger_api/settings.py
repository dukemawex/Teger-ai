"""API configuration from environment variables. See services/api/.env.example."""
from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field

ENVIRONMENTS = {"development", "test", "production"}
REPUTATION_PROVIDERS = {"none", "mock"}


def _bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _csv(value: str | None) -> tuple[str, ...]:
    return tuple(v.strip() for v in (value or "").split(",") if v.strip())


class ConfigurationError(RuntimeError):
    pass


@dataclass(frozen=True)
class ApiSettings:
    environment: str = "development"
    api_keys_json: str = ""
    api_keys_file: str = ""
    reputation_provider: str = "none"
    key_rate_limit_per_minute: int = 60
    ip_rate_limit_per_minute: int = 120
    max_body_bytes: int = 64 * 1024
    trust_proxy_headers: bool = False
    cors_origins: tuple[str, ...] = field(default_factory=tuple)
    expose_docs: bool = True
    max_analyses_per_tenant: int = 500

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "ApiSettings":
        env = os.environ if env is None else env
        environment = env.get("TEGER_ENV", "development").strip().lower()
        if environment not in ENVIRONMENTS:
            raise ConfigurationError(f"TEGER_ENV must be one of {sorted(ENVIRONMENTS)}")
        provider = env.get("TEGER_REPUTATION_PROVIDER", "none").strip().lower()
        if provider not in REPUTATION_PROVIDERS:
            raise ConfigurationError(f"TEGER_REPUTATION_PROVIDER must be one of {sorted(REPUTATION_PROVIDERS)}")
        settings = cls(
            environment=environment,
            api_keys_json=env.get("TEGER_API_KEYS", ""),
            api_keys_file=env.get("TEGER_API_KEYS_FILE", ""),
            reputation_provider=provider,
            key_rate_limit_per_minute=int(env.get("TEGER_KEY_RATE_LIMIT_PER_MINUTE", "60")),
            ip_rate_limit_per_minute=int(env.get("TEGER_IP_RATE_LIMIT_PER_MINUTE", "120")),
            max_body_bytes=int(env.get("TEGER_MAX_BODY_BYTES", str(64 * 1024))),
            trust_proxy_headers=_bool(env.get("TEGER_TRUST_PROXY_HEADERS")),
            cors_origins=_csv(env.get("TEGER_CORS_ORIGINS")),
            expose_docs=_bool(env.get("TEGER_EXPOSE_DOCS"), default=environment != "production"),
            max_analyses_per_tenant=int(env.get("TEGER_MAX_ANALYSES_PER_TENANT", "500")),
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        if self.environment == "production" and self.reputation_provider == "mock":
            raise ConfigurationError("The mock reputation provider cannot be used when TEGER_ENV=production.")
        if "*" in self.cors_origins:
            raise ConfigurationError("Wildcard CORS origins are not allowed.")
