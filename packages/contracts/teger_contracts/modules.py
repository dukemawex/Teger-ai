"""Contracts for modules that are PLANNED but not implemented.

They exist so clients, agents and services can be designed against a stable,
reviewed interface. No service in this repository accepts these messages yet, and
nothing here grants or performs privileged operations. See docs/contracts/README.md.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .analysis import RecommendedAction, Severity, Verdict

SCHEMA_VERSION = "0.1.0"

_SHA256 = r"^[a-f0-9]{64}$"


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["0.1.0"] = SCHEMA_VERSION
    tenant_id: str = Field(min_length=1, max_length=64)


# --------------------------------------------------------------------------- Windows endpoint


class EndpointEventType(str, Enum):
    PROCESS_START = "process_start"
    FILE_CREATED = "file_created"
    FILE_MODIFIED = "file_modified"
    NETWORK_CONNECTION = "network_connection"
    DETECTION = "detection"
    AGENT_HEALTH = "agent_health"


class WindowsEndpointEvent(_Contract):
    """Telemetry emitted by the (planned) user-mode Windows agent."""

    event_id: str = Field(min_length=1, max_length=64)
    device_id: str = Field(min_length=1, max_length=64)
    agent_version: str = Field(max_length=32)
    observed_at: datetime
    event_type: EndpointEventType
    process_image_sha256: str | None = Field(default=None, pattern=_SHA256)
    # Paths are reported relative to well-known roots with the user profile replaced by
    # %USERPROFILE% to avoid shipping user names.
    process_path: str | None = Field(default=None, max_length=1024)
    parent_process_sha256: str | None = Field(default=None, pattern=_SHA256)
    file_path: str | None = Field(default=None, max_length=1024)
    file_sha256: str | None = Field(default=None, pattern=_SHA256)
    remote_host: str | None = Field(default=None, max_length=253)
    remote_port: int | None = Field(default=None, ge=1, le=65535)
    severity: Severity = Severity.INFO
    detail: str | None = Field(default=None, max_length=500)


# --------------------------------------------------------------------------- File scanning


class FileScanRequest(_Contract):
    """Hash-first scan request. Content upload is opt-in and size-capped."""

    request_id: str = Field(min_length=1, max_length=64)
    sha256: str = Field(pattern=_SHA256)
    size_bytes: int = Field(ge=0, le=100 * 1024 * 1024)
    file_name: str | None = Field(default=None, max_length=255)
    mime_type: str | None = Field(default=None, max_length=127)
    source: Literal["endpoint", "email_attachment", "browser_download", "manual"]
    content_upload_consent: bool = False


class FileScanResult(_Contract):
    request_id: str
    sha256: str = Field(pattern=_SHA256)
    verdict: Verdict
    recommended_action: RecommendedAction
    engines: list[str] = Field(default_factory=list)
    matched_signatures: list[str] = Field(default_factory=list, max_length=50)
    policy_version: str


# --------------------------------------------------------------------------- Quarantine / restore


class QuarantineAction(str, Enum):
    QUARANTINE = "quarantine"
    RESTORE = "restore"


class QuarantineRequest(_Contract):
    """Command to an endpoint agent. Agents MUST verify the signature against a pinned
    tenant policy key and MUST refuse unsigned or expired commands. Destructive
    deletion is intentionally not representable in this contract."""

    command_id: str = Field(min_length=1, max_length=64)
    device_id: str = Field(min_length=1, max_length=64)
    action: QuarantineAction
    file_sha256: str = Field(pattern=_SHA256)
    original_path: str = Field(max_length=1024)
    reason: str = Field(max_length=500)
    requested_by: str = Field(max_length=128, description="Human approver identity.")
    approved_at: datetime
    expires_at: datetime
    signature: str = Field(min_length=1, max_length=1024, description="Detached signature over the canonical JSON.")


class QuarantineResult(_Contract):
    command_id: str
    device_id: str
    action: QuarantineAction
    status: Literal["completed", "rejected_signature", "expired", "not_found", "failed"]
    completed_at: datetime
    detail: str | None = Field(default=None, max_length=500)


# --------------------------------------------------------------------------- Email


class AuthenticationResult(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    UNKNOWN = "unknown"


class EmailAttachmentRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file_name: str = Field(max_length=255)
    mime_type: str | None = Field(default=None, max_length=127)
    size_bytes: int = Field(ge=0)
    sha256: str = Field(pattern=_SHA256)


class EmailMessageAnalysisRequest(_Contract):
    message_id: str = Field(max_length=998)
    from_address: str = Field(max_length=320)
    from_display_name: str | None = Field(default=None, max_length=256)
    reply_to: str | None = Field(default=None, max_length=320)
    return_path: str | None = Field(default=None, max_length=320)
    subject: str | None = Field(default=None, max_length=998)
    text_body: str | None = Field(default=None, max_length=20_000)
    urls: list[str] = Field(default_factory=list, max_length=100)
    attachments: list[EmailAttachmentRef] = Field(default_factory=list, max_length=50)
    spf: AuthenticationResult = AuthenticationResult.UNKNOWN
    dkim: AuthenticationResult = AuthenticationResult.UNKNOWN
    dmarc: AuthenticationResult = AuthenticationResult.UNKNOWN
    received_at: datetime


# --------------------------------------------------------------------------- Android


class AndroidEventType(str, Enum):
    URL_CHECK = "url_check"
    APP_INSTALLED = "app_installed"
    SMS_LINK = "sms_link"
    NOTIFICATION_LINK = "notification_link"
    DEVICE_POSTURE = "device_posture"


class AndroidSecurityEvent(_Contract):
    event_id: str = Field(min_length=1, max_length=64)
    device_id: str = Field(min_length=1, max_length=64)
    app_version: str = Field(max_length=32)
    observed_at: datetime
    event_type: AndroidEventType
    url: str | None = Field(default=None, max_length=2048)
    package_name: str | None = Field(default=None, max_length=255)
    package_signing_sha256: str | None = Field(default=None, pattern=_SHA256)
    os_patch_level: str | None = Field(default=None, max_length=10)
    is_rooted: bool | None = None
    severity: Severity = Severity.INFO


# --------------------------------------------------------------------------- Enterprise policy


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(max_length=64)
    applies_to: Literal["browser", "email", "endpoint", "android"]
    on_verdict: Verdict
    action: RecommendedAction
    allow_user_override: bool = True


class EnterprisePolicyBundle(_Contract):
    """Signed, versioned policy distributed to clients. Clients MUST verify the signature
    and reject bundles with a lower version than the one already applied (rollback)."""

    policy_id: str = Field(max_length=64)
    version: int = Field(ge=1)
    issued_at: datetime
    expires_at: datetime
    rules: list[PolicyRule] = Field(max_length=500)
    blocked_domains: list[str] = Field(default_factory=list, max_length=10_000)
    allowed_domains: list[str] = Field(default_factory=list, max_length=10_000)
    cloud_ai_allowed: bool = False
    signature: str = Field(min_length=1, max_length=1024)
