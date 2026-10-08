"""Threat engine: runs detectors and applies the deterministic policy."""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from teger_contracts import ContentType, DetectorReport, DetectorStatus, Evidence

from .detectors.base import AnalysisSubject, Detector
from .detectors.brand import BrandImpersonationDetector
from .detectors.language import CredentialHarvestingDetector, SocialEngineeringDetector
from .detectors.reputation import ReputationDetector, ReputationProvider, UnconfiguredReputationProvider
from .detectors.url_heuristics import UrlHeuristicsDetector
from .policy import Decision, decide
from .urls import ParsedUrl, extract_urls, normalize_url


@dataclass(frozen=True)
class EngineResult:
    url: ParsedUrl | None
    evidence: list[Evidence]
    reports: list[DetectorReport]
    decision: Decision
    mock_intelligence_used: bool
    subject: AnalysisSubject


class ThreatEngine:
    def __init__(
        self,
        reputation_provider: ReputationProvider | None = None,
        detectors: Sequence[Detector] | None = None,
    ):
        provider = reputation_provider or UnconfiguredReputationProvider()
        self.detectors: list[Detector] = list(detectors) if detectors is not None else [
            UrlHeuristicsDetector(),
            BrandImpersonationDetector(),
            CredentialHarvestingDetector(),
            SocialEngineeringDetector(),
            ReputationDetector(provider),
        ]

    def analyze(
        self,
        *,
        url: str | None = None,
        content: str | None = None,
        content_type: ContentType = ContentType.OTHER,
        sender: str | None = None,
        subject: str | None = None,
    ) -> EngineResult:
        """Analyze a URL and/or message. Raises ``UrlValidationError`` for a bad ``url``."""
        primary = normalize_url(url) if url and url.strip() else None
        text = (content or "").strip()
        analysis_subject = AnalysisSubject(
            content_type=content_type,
            primary_url=primary,
            content=text,
            sender=(sender or "").strip(),
            subject=(subject or "").strip(),
            content_urls=tuple(extract_urls(text)),
        )

        evidence: list[Evidence] = []
        reports: list[DetectorReport] = []
        mock_used = False
        for detector in self.detectors:
            required = detector.is_required(analysis_subject)
            try:
                outcome = detector.run(analysis_subject)
            except Exception:
                # A crashing detector reduces coverage; it must not read as "clean".
                reports.append(DetectorReport(
                    name=detector.name, version=detector.version, status=DetectorStatus.ERROR,
                    provider_mode=getattr(getattr(detector, "provider", None), "mode", "local"),
                    required=required, detail="Detector failed.",
                ))
                continue
            mock_used = mock_used or (outcome.mock and outcome.status is not DetectorStatus.SKIPPED)
            reports.append(DetectorReport(
                name=detector.name, version=detector.version, status=outcome.status,
                provider_mode=outcome.provider_mode, required=required, detail=outcome.detail,
            ))
            for finding in outcome.findings:
                evidence.append(Evidence(
                    id=f"ev-{len(evidence) + 1}",
                    detector=detector.name,
                    category=finding.category,
                    tactic=finding.tactic,
                    severity=finding.severity,
                    weight=finding.effective_weight,
                    description=finding.description[:500],
                    indicator=finding.indicator[:300] if finding.indicator else None,
                ))

        return EngineResult(primary, evidence, reports, decide(evidence, reports), mock_used, analysis_subject)
