"""Deterministic verdict policy.

The verdict is a pure function of evidence and detector coverage. AI explanations are
computed afterwards and cannot change it. Bump ``POLICY_VERSION`` whenever thresholds,
weights or rules change so stored verdicts remain attributable.
"""
from __future__ import annotations

from dataclasses import dataclass

from teger_contracts import (
    DetectorReport,
    DetectorStatus,
    Evidence,
    IntelligenceCoverage,
    RecommendedAction,
    Severity,
    Verdict,
)

POLICY_VERSION = "2026.10.1"
MALICIOUS_THRESHOLD = 70
SUSPICIOUS_THRESHOLD = 25
FORCE_MALICIOUS_CATEGORIES = frozenset({"reputation_listed_malicious"})

ACTION_TEXT = {
    RecommendedAction.BLOCK: (
        "Do not open the link, reply, pay, or enter any information. Report it to your security team "
        "and delete it."
    ),
    RecommendedAction.WARN: (
        "Treat this as a likely attack. Do not act on the request; verify it with the sender through a "
        "phone number or channel you already trust."
    ),
    RecommendedAction.CAUTION: (
        "Teger could not fully check this. Do not enter credentials or make payments until you have "
        "verified it through a trusted channel."
    ),
    RecommendedAction.ALLOW: (
        "No threat indicators were found. Stay alert: absence of indicators is not a guarantee of safety."
    ),
}


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    risk_score: int
    confidence: float
    action: RecommendedAction
    action_text: str
    coverage: IntelligenceCoverage
    policy_version: str = POLICY_VERSION


def decide(evidence: list[Evidence], reports: list[DetectorReport]) -> Decision:
    score = min(100, sum(e.weight for e in evidence))
    forced = any(e.category in FORCE_MALICIOUS_CATEGORIES for e in evidence)
    has_critical = any(e.severity is Severity.CRITICAL for e in evidence)
    complete = all(r.status is DetectorStatus.OK for r in reports if r.required)
    coverage = IntelligenceCoverage.COMPLETE if complete else IntelligenceCoverage.PARTIAL
    contributing = len({e.detector for e in evidence if e.weight > 0})

    if forced or score >= MALICIOUS_THRESHOLD:
        verdict = Verdict.MALICIOUS
        confidence = 0.9 if forced else 0.55 + 0.1 * (contributing - 1) + (score - MALICIOUS_THRESHOLD) / 200
        confidence = min(0.95, confidence)
    elif score >= SUSPICIOUS_THRESHOLD or has_critical:
        verdict = Verdict.SUSPICIOUS
        confidence = min(0.85, 0.4 + 0.08 * max(0, contributing - 1) + max(0, score - SUSPICIOUS_THRESHOLD) / 250)
    elif not complete:
        # Unknown or unavailable intelligence is never reported as safe.
        verdict = Verdict.UNKNOWN
        confidence = 0.2
    else:
        verdict = Verdict.NO_THREAT_DETECTED
        confidence = 0.6 if score == 0 else 0.5

    action = {
        Verdict.MALICIOUS: RecommendedAction.BLOCK,
        Verdict.SUSPICIOUS: RecommendedAction.WARN,
        Verdict.UNKNOWN: RecommendedAction.CAUTION,
        Verdict.NO_THREAT_DETECTED: RecommendedAction.ALLOW if score == 0 else RecommendedAction.CAUTION,
    }[verdict]

    return Decision(verdict, score, round(confidence, 2), action, ACTION_TEXT[action], coverage)
