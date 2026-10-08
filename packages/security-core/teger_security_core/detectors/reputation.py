"""Domain/URL reputation via pluggable providers.

Teger ships two providers:

* :class:`UnconfiguredReputationProvider` — the default. Always reports
  ``unavailable``; URL analyses then cannot reach a "no threat detected" verdict.
* :class:`MockReputationProvider` — deterministic fixture for tests and local
  development. Results are flagged ``mock`` end to end and refused in production.

Live providers (commercial or open feeds) implement :class:`ReputationProvider`.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from importlib import resources
from typing import Protocol

from teger_contracts import DetectorStatus, ProviderMode, Severity

from ..urls import ParsedUrl
from .base import AnalysisSubject, DetectorOutcome, Finding


class Listing(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"


@dataclass(frozen=True)
class ReputationHit:
    host: str
    listing: Listing
    source: str


@dataclass(frozen=True)
class ReputationResponse:
    available: bool
    mode: ProviderMode
    hits: tuple[ReputationHit, ...] = ()
    detail: str | None = None


class ReputationProvider(Protocol):
    name: str
    mode: ProviderMode

    def lookup(self, urls: list[ParsedUrl]) -> ReputationResponse: ...


class UnconfiguredReputationProvider:
    name = "none"
    mode = ProviderMode.NONE

    def lookup(self, urls: list[ParsedUrl]) -> ReputationResponse:
        return ReputationResponse(False, self.mode, detail="No reputation provider is configured.")


@dataclass
class MockReputationProvider:
    """Fixture-backed provider. Never represents live threat intelligence."""

    malicious: frozenset[str] = field(default_factory=frozenset)
    suspicious: frozenset[str] = field(default_factory=frozenset)
    unavailable_trigger: frozenset[str] = field(default_factory=frozenset)
    name: str = "mock-fixture"
    mode: ProviderMode = ProviderMode.MOCK

    @classmethod
    def from_fixture(cls) -> "MockReputationProvider":
        data = json.loads(
            resources.files("teger_security_core").joinpath("data/mock_reputation.json").read_text()
        )
        return cls(
            malicious=frozenset(data["malicious"]),
            suspicious=frozenset(data["suspicious"]),
            unavailable_trigger=frozenset(data["unavailable"]),
        )

    def _match(self, host: str, registrable: str | None, listed: frozenset[str]) -> bool:
        return host in listed or (registrable is not None and registrable in listed)

    def lookup(self, urls: list[ParsedUrl]) -> ReputationResponse:
        hits: list[ReputationHit] = []
        for url in urls:
            if self._match(url.host, url.registrable_domain, self.unavailable_trigger):
                return ReputationResponse(False, self.mode, detail="Mock provider simulated an outage.")
            if self._match(url.host, url.registrable_domain, self.malicious):
                hits.append(ReputationHit(url.host, Listing.MALICIOUS, self.name))
            elif self._match(url.host, url.registrable_domain, self.suspicious):
                hits.append(ReputationHit(url.host, Listing.SUSPICIOUS, self.name))
        return ReputationResponse(True, self.mode, tuple(hits))


class ReputationDetector:
    name = "reputation"
    version = "1.0.0"

    def __init__(self, provider: ReputationProvider):
        self.provider = provider

    def is_required(self, subject: AnalysisSubject) -> bool:
        return bool(subject.urls)

    def run(self, subject: AnalysisSubject) -> DetectorOutcome:
        urls = list(subject.urls)
        mock = self.provider.mode == ProviderMode.MOCK
        if not urls:
            return DetectorOutcome(DetectorStatus.SKIPPED, self.provider.mode, detail="No URLs to look up.", mock=mock)
        try:
            response = self.provider.lookup(urls)
        except Exception:  # provider faults must never become a silent "clean"
            return DetectorOutcome(
                DetectorStatus.ERROR, self.provider.mode, detail="Reputation provider failed.", mock=mock
            )
        if not response.available:
            return DetectorOutcome(DetectorStatus.UNAVAILABLE, response.mode, detail=response.detail, mock=mock)
        findings = tuple(
            Finding(
                "reputation_listed_malicious" if hit.listing is Listing.MALICIOUS else "reputation_listed_suspicious",
                Severity.CRITICAL if hit.listing is Listing.MALICIOUS else Severity.HIGH,
                f"Domain is listed as {hit.listing.value} by {hit.source}"
                + (" (MOCK fixture, not live intelligence)." if mock else "."),
                hit.host,
                weight=100 if hit.listing is Listing.MALICIOUS else None,
            )
            for hit in response.hits
        )
        return DetectorOutcome(DetectorStatus.OK, response.mode, findings, mock=mock)
