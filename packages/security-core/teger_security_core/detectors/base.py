"""Detector interface.

A detector inspects an :class:`AnalysisSubject` and returns findings plus an honest
status. Detectors must never perform network I/O on submitted URLs; external
intelligence goes through a provider adapter (see ``reputation.py``).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from teger_contracts import ContentType, DetectorStatus, ProviderMode, Severity

from ..urls import ParsedUrl

SEVERITY_WEIGHT = {
    Severity.INFO: 0,
    Severity.LOW: 8,
    Severity.MEDIUM: 18,
    Severity.HIGH: 35,
    Severity.CRITICAL: 60,
}


@dataclass(frozen=True)
class AnalysisSubject:
    content_type: ContentType
    primary_url: ParsedUrl | None = None
    content: str = ""
    sender: str = ""
    subject: str = ""
    content_urls: tuple[ParsedUrl, ...] = ()

    @property
    def urls(self) -> tuple[ParsedUrl, ...]:
        if self.primary_url is None:
            return self.content_urls
        rest = tuple(u for u in self.content_urls if u.normalized != self.primary_url.normalized)
        return (self.primary_url, *rest)

    @property
    def text(self) -> str:
        """All human-readable text, used by language detectors."""
        return "\n".join(part for part in (self.subject, self.content) if part)


@dataclass(frozen=True)
class Finding:
    category: str
    severity: Severity
    description: str
    indicator: str | None = None
    tactic: str | None = None
    weight: int | None = None  # defaults to SEVERITY_WEIGHT[severity]

    @property
    def effective_weight(self) -> int:
        return SEVERITY_WEIGHT[self.severity] if self.weight is None else self.weight


@dataclass(frozen=True)
class DetectorOutcome:
    status: DetectorStatus
    provider_mode: ProviderMode
    findings: tuple[Finding, ...] = ()
    detail: str | None = None
    # True when findings came from a mock provider; propagates to the API response.
    mock: bool = False


class Detector(Protocol):
    name: str
    version: str

    def is_required(self, subject: AnalysisSubject) -> bool:
        """Whether a 'no threat detected' verdict depends on this detector succeeding."""

    def run(self, subject: AnalysisSubject) -> DetectorOutcome: ...


@dataclass
class FindingCollector:
    """Keeps one finding per category so repeated cues do not inflate the score."""

    findings: list[Finding] = field(default_factory=list)
    _seen: set[str] = field(default_factory=set)

    def add(self, finding: Finding) -> None:
        if finding.category in self._seen:
            return
        self._seen.add(finding.category)
        self.findings.append(finding)

    def outcome(self, provider_mode: ProviderMode = ProviderMode.LOCAL) -> DetectorOutcome:
        return DetectorOutcome(DetectorStatus.OK, provider_mode, tuple(self.findings))
