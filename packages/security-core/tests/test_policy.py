from teger_contracts import (
    DetectorReport, DetectorStatus, Evidence, IntelligenceCoverage, ProviderMode, RecommendedAction, Severity,
    Verdict,
)
from teger_security_core.policy import POLICY_VERSION, decide


def ev(weight, severity=Severity.MEDIUM, category="x", detector="d"):
    return Evidence(id="ev-1", detector=detector, category=category, severity=severity, weight=weight,
                    description="test")


def report(status=DetectorStatus.OK, required=True):
    return DetectorReport(name="r", version="1", status=status, provider_mode=ProviderMode.LOCAL, required=required)


def test_no_evidence_complete_coverage_allows():
    d = decide([], [report()])
    assert d.verdict is Verdict.NO_THREAT_DETECTED and d.action is RecommendedAction.ALLOW
    assert d.coverage is IntelligenceCoverage.COMPLETE and d.policy_version == POLICY_VERSION


def test_no_evidence_missing_required_intel_is_unknown():
    d = decide([], [report(DetectorStatus.UNAVAILABLE)])
    assert d.verdict is Verdict.UNKNOWN and d.action is RecommendedAction.CAUTION


def test_unavailable_optional_detector_does_not_block_clean_verdict():
    assert decide([], [report(DetectorStatus.UNAVAILABLE, required=False)]).verdict is Verdict.NO_THREAT_DETECTED


def test_thresholds():
    assert decide([ev(24)], [report()]).verdict is Verdict.NO_THREAT_DETECTED
    assert decide([ev(24)], [report()]).action is RecommendedAction.CAUTION
    assert decide([ev(25)], [report()]).verdict is Verdict.SUSPICIOUS
    assert decide([ev(70)], [report()]).verdict is Verdict.MALICIOUS


def test_critical_finding_is_at_least_suspicious():
    assert decide([ev(10, Severity.CRITICAL)], [report()]).verdict is Verdict.SUSPICIOUS


def test_positive_evidence_wins_even_with_partial_coverage():
    d = decide([ev(80)], [report(DetectorStatus.UNAVAILABLE)])
    assert d.verdict is Verdict.MALICIOUS and d.coverage is IntelligenceCoverage.PARTIAL


def test_reputation_listing_forces_malicious():
    d = decide([ev(1, category="reputation_listed_malicious")], [report()])
    assert d.verdict is Verdict.MALICIOUS and d.action is RecommendedAction.BLOCK


def test_score_is_capped_and_confidence_bounded():
    d = decide([ev(60, detector=str(i)) for i in range(5)], [report()])
    assert d.risk_score == 100 and 0 <= d.confidence <= 0.95
