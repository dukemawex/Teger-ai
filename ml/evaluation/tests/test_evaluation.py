import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import harness  # noqa: E402
from harness import Sample, check_samples, jaccard  # noqa: E402

PROV = {"source": "synthetic", "author": "t", "created": "2026-10-08", "license": "MIT"}


def s(id, label="benign", split="dev", **kw):
    return Sample(id=id, label=label, split=split, content_type="email", provenance=dict(PROV), **kw)


def base():
    return [s("B1", content="team lunch on friday"), s("M1", "malicious", content="send gift cards now"),
            s("B2", split="test", content="build is green again"),
            s("M2", "malicious", split="test", content="verify your password today")]


def test_committed_samples_pass_all_checks():
    assert check_samples(harness.load_samples(), harness.load_pattern_texts()).errors == []


def test_detects_cross_split_near_duplicates():
    samples = base() + [s("B3", split="test", content="Team lunch on Friday!")]
    assert any("near-duplicate samples" in e for e in check_samples(samples, []).errors)


def test_detects_leakage_from_rule_development_patterns():
    pattern = "URGENT: Your account will be permanently deactivated in 24 hours unless you verify now."
    samples = base() + [s("M3", "malicious", content=pattern.lower())]
    assert any("dataset/patterns" in e for e in check_samples(samples, [pattern]).errors)


def test_malicious_samples_must_use_reserved_domains():
    samples = base() + [s("M3", "malicious", url="https://real-bank-login.com/")]
    assert any("reserved domains" in e for e in check_samples(samples, []).errors)
    ok = base() + [s("M3", "malicious", url="https://real-bank-login.test/"),
                   s("M4", "malicious", url="http://203.0.113.9/login")]
    assert check_samples(ok, []).errors == []


def test_benign_cannot_share_malicious_domain():
    samples = base() + [s("M3", "malicious", url="https://evil.test/a"), s("B3", url="https://evil.test/b")]
    assert any("shares a domain" in e for e in check_samples(samples, []).errors)


def test_provenance_required():
    bad = s("B3", content="hello world again")
    bad.provenance = {"source": "scraped"}
    errors = check_samples(base() + [bad], []).errors
    assert any("provenance.source" in e for e in errors) and any("provenance.author" in e for e in errors)


def test_non_synthetic_needs_reference():
    bad = s("B3", content="hello world again")
    bad.provenance = {**PROV, "source": "public-dataset"}
    assert any("reference" in e for e in check_samples(base() + [bad], []).errors)


def test_each_split_needs_both_labels():
    samples = [s("B1", content="a b c d e f"), s("M1", "malicious", content="x y z w v u")]
    assert any("split 'test'" in e for e in check_samples(samples, []).errors)


def test_duplicate_ids():
    assert any("duplicate id" in e for e in check_samples(base() + [s("B1", content="zzz qqq")], []).errors)


def test_jaccard_bounds():
    assert jaccard("abcdefgh", "abcdefgh") == 1.0
    assert jaccard("abcdefgh", "zyxwvuts") == 0.0


def test_evaluation_counts_unknown_as_abstention_not_success():
    report = harness.evaluate([
        s("B1", url="https://www.example.org/"), s("M1", "malicious", content="hello there friend"),
    ])
    m = report["splits"]["dev"]
    assert m["unknown_benign"] == 1 and m["tn"] == 0
    assert m["fn"] == 1 and m["recall"] == 0.0
