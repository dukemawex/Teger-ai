"""Wire models for investigations (cases), evidence, trusted context and approvals.

Every evidence item says where it came from, when, how it was collected, and whether it
is an observation, a deterministic derivation, or model output. Model output can never
be the sole support for a finding.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MESSAGE_MAX = 20_000
URL_MAX = 2048


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Mode(str, Enum):
    DEMO = "demo"  # inert fixtures, synthetic evidence, no network
    LIVE = "live"  # tenant data; tools use configured providers or report unavailable


class CaseStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Verdict(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    INCONCLUSIVE = "inconclusive"
    # Not a guarantee of safety: nothing checked contradicted the approved context.
    NO_THREAT_DETECTED = "no_threat_detected"


class EvidenceMethod(str, Enum):
    OBSERVED = "observed"  # read directly from submitted material or a fetched response
    DERIVED = "derived"  # deterministic comparison or rule over observations
    MODEL = "model_inference"  # produced by a language model; never sole support


class Stance(str, Enum):
    RISK = "risk"
    LEGITIMACY = "legitimacy"
    NEUTRAL = "neutral"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ToolState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    UNAVAILABLE = "unavailable"


class CaseInput(_Strict):
    url: str | None = Field(default=None, max_length=URL_MAX)
    message: str | None = Field(default=None, max_length=MESSAGE_MAX)
    sender: str | None = Field(default=None, max_length=320)
    subject: str | None = Field(default=None, max_length=998)
    source: Literal["email", "chat", "web", "other"] = "email"
    # Optional model-assisted planning; requires explicit consent (redacted content is sent).
    ai_planning: bool = False
    cloud_ai_consent: bool = False

    @model_validator(mode="after")
    def _need_material(self) -> "CaseInput":
        if not (self.url and self.url.strip()) and not (self.message and self.message.strip()):
            raise ValueError("Provide a website URL, message text, or both.")
        return self


class Evidence(_Strict):
    id: str
    tool: str
    source: str = Field(description="Where this came from, e.g. 'submitted message' or 'HTTP response'.")
    collected_at: datetime
    method: EvidenceMethod
    stance: Stance
    severity: Severity = Severity.INFO
    kind: str = Field(description="Machine-readable observation type.")
    summary: str = Field(max_length=500)
    details: dict[str, str | int | bool | None | list[str]] = Field(default_factory=dict)
    untrusted_excerpt: str | None = Field(
        default=None, max_length=600, description="Attacker-controllable text, shown as data only."
    )


class ToolRun(_Strict):
    seq: int
    tool: str
    purpose: str
    state: ToolState
    selected_by: str
    started_at: datetime | None = None
    finished_at: datetime | None = None
    detail: str | None = Field(default=None, max_length=300)
    evidence_ids: list[str] = Field(default_factory=list)


class Finding(_Strict):
    id: str
    statement: str
    evidence_ids: list[str] = Field(min_length=1)
    stance: Stance


class ProposedActionType(str, Enum):
    RECORD_WARNING = "record_warning"
    BLOCKLIST_DOMAIN = "blocklist_domain"
    REQUEST_VERIFICATION = "request_verification"
    CLOSE_AS_LEGITIMATE = "close_as_legitimate"


class ActionState(str, Enum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    EXECUTED = "executed"
    FAILED = "failed"


class ProposedAction(_Strict):
    id: str
    case_id: str
    case_version: int
    type: ProposedActionType
    title: str
    params: dict[str, str]
    params_hash: str
    enforcement_scope: str
    state: ActionState
    proposed_by: str
    proposed_at: datetime
    expires_at: datetime
    decided_by: str | None = None
    decided_at: datetime | None = None
    decision_note: str | None = None
    executed_at: datetime | None = None
    execution_result: str | None = None
    demo_only: bool = False


class Assessment(_Strict):
    verdict: Verdict
    headline: str
    findings: list[Finding]
    contradictions: list[Finding] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    recommended_next_action: str
    context_effect: str = Field(description="How approved business context changed the assessment.")
    policy_version: str


class CaseEvent(_Strict):
    seq: int
    ts: datetime
    type: str
    message: str
    data: dict[str, Any] = Field(default_factory=dict)


class Resolution(_Strict):
    outcome: Literal["confirmed_phishing", "confirmed_legitimate", "unresolved"]
    note: str | None = Field(default=None, max_length=500)
    recorded_by: str
    recorded_at: datetime


class Case(_Strict):
    id: str
    mode: Mode
    title: str
    status: CaseStatus
    version: int
    created_at: datetime
    updated_at: datetime
    input: CaseInput
    planner: str
    fixture_id: str | None = None
    tools: list[ToolRun] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    assessment: Assessment | None = None
    actions: list[ProposedAction] = Field(default_factory=list)
    resolution: Resolution | None = None
    error: str | None = None
    limits: dict[str, int] = Field(default_factory=dict)


class CaseSummary(_Strict):
    id: str
    mode: Mode
    title: str
    status: CaseStatus
    verdict: Verdict | None
    created_at: datetime
    updated_at: datetime
    pending_approvals: int


# ------------------------------------------------------------------ trusted context

class ContextKind(str, Enum):
    SUPPLIER = "supplier"
    IDENTITY_PROVIDER = "identity_provider"
    SERVICE = "service"


_DOMAIN = r"^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$"


class ApprovedService(_Strict):
    domain: str = Field(pattern=_DOMAIN, max_length=253)
    purpose: str = Field(max_length=120)


class ContextEntryInput(_Strict):
    kind: ContextKind
    name: str = Field(min_length=2, max_length=120)
    domains: list[str] = Field(min_length=1, max_length=20)
    approved_services: list[ApprovedService] = Field(default_factory=list, max_length=20)
    verified_contact: str | None = Field(default=None, max_length=200)
    verification_source: str = Field(min_length=3, max_length=200)
    notes: str | None = Field(default=None, max_length=300)

    @field_validator("domains")
    @classmethod
    def _domains(cls, value: list[str]) -> list[str]:
        import re
        cleaned = []
        for d in value:
            d = d.strip().lower().rstrip(".")
            if len(d) > 253 or not re.match(_DOMAIN, d):
                raise ValueError(f"Not a valid domain name: {d[:80]!r}")
            cleaned.append(d)
        return list(dict.fromkeys(cleaned))


class ContextEntry(ContextEntryInput):
    id: str
    approved_by: str
    approved_at: datetime
    revoked: bool = False


class ApprovalDecision(_Strict):
    case_version: int
    params_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    note: str | None = Field(default=None, max_length=300)


class ExecuteRequest(_Strict):
    idempotency_key: str = Field(pattern=r"^[A-Za-z0-9_-]{8,64}$")


class ResolutionInput(_Strict):
    outcome: Literal["confirmed_phishing", "confirmed_legitimate", "unresolved"]
    note: str | None = Field(default=None, max_length=500)
