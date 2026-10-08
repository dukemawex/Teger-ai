"""Teger phishing evaluation harness.

    python ml/evaluation/harness.py              # validate, check leakage, evaluate, write report
    python ml/evaluation/harness.py --check-only # validation + leakage checks only (CI gate)

Samples live in samples/{malicious,benign}.jsonl. Each sample has an id, label, split
(dev|test), content and/or url, and provenance. Results are produced with NO
reputation provider (the honest default), so URL-only samples without heuristic hits
come out as 'unknown' and are reported as abstentions, not as correct answers.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from teger_contracts import ContentType, Verdict
from teger_security_core import POLICY_VERSION, ThreatEngine
from teger_security_core.urls import UrlValidationError, extract_urls, normalize_url

HERE = Path(__file__).resolve().parent
SAMPLES = {"malicious": HERE / "samples" / "malicious.jsonl", "benign": HERE / "samples" / "benign.jsonl"}
PATTERNS_DIR = HERE.parent.parent / "dataset" / "patterns"
REPORT_DIR = HERE / "reports"

SPLITS = {"dev", "test"}
SOURCES = {"synthetic", "public-dataset", "contributed"}
RESERVED_SUFFIXES = (".test", ".example", ".invalid", ".localhost")
RESERVED_DOMAINS = {"example.com", "example.net", "example.org"}
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
NEAR_DUPLICATE_JACCARD = 0.8
POSITIVE = {Verdict.MALICIOUS, Verdict.SUSPICIOUS}


@dataclass
class Sample:
    id: str
    label: str
    split: str
    content_type: str
    provenance: dict
    content: str | None = None
    url: str | None = None
    sender: str | None = None
    subject: str | None = None

    @property
    def text(self) -> str:
        return " ".join(p for p in (self.subject, self.content, self.url) if p)


@dataclass
class CheckReport:
    errors: list[str] = field(default_factory=list)

    def add(self, message: str) -> None:
        self.errors.append(message)


def load_samples() -> list[Sample]:
    samples = []
    for expected_label, path in SAMPLES.items():
        for line_no, line in enumerate(path.read_text().splitlines(), 1):
            if not line.strip():
                continue
            data = json.loads(line)
            sample = Sample(**data)
            if sample.label != expected_label:
                raise ValueError(f"{path.name}:{line_no} label '{sample.label}' does not match file")
            samples.append(sample)
    return samples


def _normalize_text(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()


def _shingles(text: str, k: int = 5) -> set[str]:
    norm = _normalize_text(text)
    return {norm[i:i + k] for i in range(max(1, len(norm) - k + 1))}


def jaccard(a: str, b: str) -> float:
    sa, sb = _shingles(a), _shingles(b)
    return len(sa & sb) / len(sa | sb) if sa and sb else 0.0


def _is_reserved_host(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return any(ip in net for net in DOC_NETS)
    except ValueError:
        pass
    return host.endswith(RESERVED_SUFFIXES) or any(host == d or host.endswith("." + d) for d in RESERVED_DOMAINS)


def _sample_urls(sample: Sample) -> list[str]:
    hosts = [u.host for u in extract_urls(sample.content or "")]
    if sample.url:
        try:
            hosts.append(normalize_url(sample.url).host)
        except UrlValidationError:
            pass
    for addr in re.findall(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", sample.sender or ""):
        hosts.append(addr.lower())
    return hosts


def check_samples(samples: list[Sample], patterns: list[str]) -> CheckReport:
    report = CheckReport()
    ids = Counter(s.id for s in samples)
    for dup, n in ids.items():
        if n > 1:
            report.add(f"duplicate id {dup}")

    for s in samples:
        if s.split not in SPLITS:
            report.add(f"{s.id}: split must be one of {sorted(SPLITS)}")
        if s.content_type not in {c.value for c in ContentType}:
            report.add(f"{s.id}: unknown content_type {s.content_type}")
        if not (s.content or s.url):
            report.add(f"{s.id}: needs content or url")
        prov = s.provenance or {}
        if prov.get("source") not in SOURCES:
            report.add(f"{s.id}: provenance.source must be one of {sorted(SOURCES)}")
        for key in ("author", "created", "license"):
            if not prov.get(key):
                report.add(f"{s.id}: provenance.{key} is required")
        if prov.get("source") != "synthetic" and not prov.get("reference"):
            report.add(f"{s.id}: non-synthetic samples need provenance.reference")
        if s.url:
            try:
                normalize_url(s.url)
            except UrlValidationError as exc:
                report.add(f"{s.id}: invalid url ({exc})")
        if s.label == "malicious":
            for host in _sample_urls(s):
                if not _is_reserved_host(host):
                    report.add(f"{s.id}: malicious samples may only reference reserved domains, found {host}")

    malicious_hosts = {h for s in samples if s.label == "malicious" for h in _sample_urls(s)}
    for s in samples:
        if s.label == "benign" and set(_sample_urls(s)) & malicious_hosts:
            report.add(f"{s.id}: benign sample shares a domain with a malicious sample")

    # Near-duplicate leakage between any two samples (catches cross-split and cross-label copies).
    for i, a in enumerate(samples):
        for b in samples[i + 1:]:
            score = jaccard(a.text, b.text)
            if score >= NEAR_DUPLICATE_JACCARD:
                report.add(f"near-duplicate samples {a.id} and {b.id} (jaccard={score:.2f})")

    # Leakage against the open pattern dataset the detector rules were written from.
    for s in samples:
        for pattern in patterns:
            if jaccard(s.text, pattern) >= NEAR_DUPLICATE_JACCARD:
                report.add(f"{s.id}: near-duplicate of a dataset/patterns example (rule-development leakage)")
                break

    for split in SPLITS:
        labels = {s.label for s in samples if s.split == split}
        if labels != {"malicious", "benign"}:
            report.add(f"split '{split}' must contain both labels, has {sorted(labels)}")
    return report


def load_pattern_texts() -> list[str]:
    texts = []
    for path in sorted(PATTERNS_DIR.glob("*.jsonl")):
        for line in path.read_text().splitlines():
            if line.strip():
                texts.append(json.loads(line)["example_text"])
    return texts


def evaluate(samples: list[Sample]) -> dict:
    engine = ThreatEngine()  # no reputation provider: measure what the deterministic layer does alone
    rows = []
    for s in samples:
        result = engine.analyze(url=s.url, content=s.content, content_type=ContentType(s.content_type),
                                sender=s.sender, subject=s.subject)
        rows.append({
            "id": s.id, "label": s.label, "split": s.split, "verdict": result.decision.verdict.value,
            "risk_score": result.decision.risk_score,
            "evidence": sorted({e.category for e in result.evidence}),
        })

    def metrics(subset: list[dict]) -> dict:
        tp = sum(r["label"] == "malicious" and Verdict(r["verdict"]) in POSITIVE for r in subset)
        fn = sum(r["label"] == "malicious" and Verdict(r["verdict"]) is Verdict.NO_THREAT_DETECTED for r in subset)
        fp = sum(r["label"] == "benign" and Verdict(r["verdict"]) in POSITIVE for r in subset)
        tn = sum(r["label"] == "benign" and Verdict(r["verdict"]) is Verdict.NO_THREAT_DETECTED for r in subset)
        unknown = Counter(r["label"] for r in subset if r["verdict"] == Verdict.UNKNOWN.value)
        malicious = sum(r["label"] == "malicious" for r in subset)
        benign = sum(r["label"] == "benign" for r in subset)
        return {
            "n": len(subset), "malicious": malicious, "benign": benign,
            "tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "unknown_malicious": unknown.get("malicious", 0), "unknown_benign": unknown.get("benign", 0),
            "precision": round(tp / (tp + fp), 3) if tp + fp else None,
            # Recall counts 'unknown' malicious samples as misses.
            "recall": round(tp / malicious, 3) if malicious else None,
            "false_positive_rate": round(fp / benign, 3) if benign else None,
        }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "policy_version": POLICY_VERSION,
        "reputation_provider": "none",
        "caveat": (
            "Small synthetic sample set written by the same maintainers who wrote the detector rules "
            "(author bias). Not a benchmark; do not quote as real-world accuracy."
        ),
        "splits": {split: metrics([r for r in rows if r["split"] == split]) for split in sorted(SPLITS)},
        "rows": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args(argv)

    samples = load_samples()
    checks = check_samples(samples, load_pattern_texts())
    if checks.errors:
        print(f"FAILED: {len(checks.errors)} sample/leakage errors", file=sys.stderr)
        for error in checks.errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print(f"OK: {len(samples)} samples pass schema, provenance and leakage checks.")
    if args.check_only:
        return 0

    report = evaluate(samples)
    REPORT_DIR.mkdir(exist_ok=True)
    out = REPORT_DIR / "latest.json"
    out.write_text(json.dumps(report, indent=2))
    for split, m in report["splits"].items():
        print(f"[{split}] n={m['n']} tp={m['tp']} fp={m['fp']} tn={m['tn']} fn={m['fn']} "
              f"unknown(mal/ben)={m['unknown_malicious']}/{m['unknown_benign']} "
              f"precision={m['precision']} recall={m['recall']} fpr={m['false_positive_rate']}")
    print(f"Report written to {out.relative_to(HERE.parent.parent)} ({report['caveat']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
