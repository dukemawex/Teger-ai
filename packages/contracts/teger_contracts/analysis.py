"""Threat-analysis contracts for the v1 API.

These models are the public wire format. Changing a field name or enum value is a
breaking change and must bump the API version.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

URL_MAX_LENGTH = 2048
CONTENT_MAX_LENGTH = 20_000


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Verdict(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    NO_THREAT_DETECTED = "no_threat_detected"
    # Required intelligence was unavailable; this is never an implicit "safe".
    UNKNOWN = "unknown"


class RecommendedAction(str, Enum):
    BLOCK = "block"
    WARN = "warn"
    CAUTION = "caution"
    ALLOW = "allow"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectorStatus(str, Enum):
    OK = "ok"
    UNAVAILABLE = "unavailable"
    ERROR = "error"
    SKIPPED = "skipped"


class ProviderMode(str, Enum):
    LOCAL = "local"  # deterministic rules shipped with Teger
    LIVE = "live"  # external intelligence provider
    MOCK = "mock"  # deterministic test fixture; never live intelligence
    NONE = "none"  # no provider configured


class ContentType(str, Enum):
    EMAIL = "email"
    CHAT = "chat"
    SMS = "sms"
    WEB = "web"
    OTHER = "other"


class IntelligenceCoverage(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"


class Evidence(_Strict):
    id: str = Field(description="Stable within one analysis, e.g. 'ev-3'.")
    detector: str
    category: str = Field(description="Machine-readable indicator name, e.g. 'brand_lookalike_domain'.")
    tactic: str | None = Field(default=None, description="Taxonomy slug from dataset/taxonomy.py, if any.")
    severity: Severity
    weight: int = Field(ge=0, le=100)
    description: str = Field(max_length=500)
    indicator: str | None = Field(
        default=None, max_length=300, description="Redacted excerpt or value that triggered the rule."
    )


class DetectorReport(_Strict):
    name: str
    version: str
    status: DetectorStatus
    provider_mode: ProviderMode
    required: bool = Field(description="Whether a 'no threat' verdict requires this detector to succeed.")
    detail: str | None = Field(default=None, max_length=300)


class NormalizedUrl(_Strict):
    normalized: str
    scheme: str
    host: str = Field(description="ASCII (IDNA) host.")
    unicode_host: str | None = None
    registrable_domain: str | None = None
    port: int | None = None
    is_ip_literal: bool
    had_userinfo: bool


class AnalysisRequest(_Strict):
    url: str | None = Field(default=None, max_length=URL_MAX_LENGTH)
    content: str | None = Field(default=None, max_length=CONTENT_MAX_LENGTH)
    content_type: ContentType = ContentType.OTHER
    sender: str | None = Field(default=None, max_length=320)
    subject: str | None = Field(default=None, max_length=998)
    explain: bool = Field(default=False, description="Request an AI explanation of the evidence.")
    cloud_ai_consent: bool = Field(
        default=False,
        description="Explicit consent to send redacted content to the configured cloud AI provider.",
    )

    @model_validator(mode="after")
    def _require_subject(self) -> "AnalysisRequest":
        if not (self.url and self.url.strip()) and not (self.content and self.content.strip()):
            raise ValueError("Provide at least one of 'url' or 'content'.")
        return self


class AiExplanationStatus(str, Enum):
    NOT_REQUESTED = "not_requested"
    CONSENT_REQUIRED = "consent_required"
    NOT_PERMITTED = "not_permitted"
    UNAVAILABLE = "unavailable"
    DECLINED = "declined"
    FAILED = "failed"
    COMPLETED = "completed"


class AiKeyPoint(_Strict):
    evidence_ids: list[str] = Field(min_length=1, max_length=10)
    explanation: str = Field(max_length=600)


class AiUsage(_Strict):
    model: str
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    cache_read_input_tokens: int = Field(default=0, ge=0)
    cache_creation_input_tokens: int = Field(default=0, ge=0)
    estimated_cost_usd: float | None = Field(default=None, ge=0)


class AiExplanation(_Strict):
    status: AiExplanationStatus
    provider: str | None = None
    summary: str | None = Field(default=None, max_length=1200)
    key_points: list[AiKeyPoint] = Field(default_factory=list, max_length=12)
    user_guidance: str | None = Field(default=None, max_length=800)
    injection_attempt_observed: bool = False
    ungrounded_points_removed: int = 0
    redactions_applied: int = 0
    key_source: Literal["server", "byok"] | None = Field(
        default=None, description="Whose Anthropic key paid for the call: Teger's server key or the user's own (BYOK)."
    )
    usage: AiUsage | None = None
    detail: str | None = Field(default=None, max_length=300)


class ThreatVerdict(_Strict):
    analysis_id: str
    created_at: datetime
    verdict: Verdict
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(
        ge=0, le=1, description="Rule-based agreement score. Not a calibrated probability."
    )
    recommended_action: RecommendedAction
    recommended_action_text: str
    evidence: list[Evidence]
    detection_sources: list[DetectorReport]
    intelligence_coverage: IntelligenceCoverage
    mock_intelligence_used: bool
    policy_version: str
    url: NormalizedUrl | None = None
    content_type: ContentType
    explanation: AiExplanation


class AnalysisSummary(_Strict):
    analysis_id: str
    created_at: datetime
    verdict: Verdict
    risk_score: int
    recommended_action: RecommendedAction
    content_type: ContentType
    url_host: str | None = None
    evidence_count: int
    mock_intelligence_used: bool
