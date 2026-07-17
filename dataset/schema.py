"""Schema, loader, and validator for the open phishing-pattern dataset.

The dataset is JSONL under dataset/patterns/*.jsonl. Each line is one PhishingPattern.
Keeping it JSONL means contributors can append entries and diffs stay readable.
"""
from __future__ import annotations

import glob
import json
import os
from dataclasses import dataclass, field, asdict

from taxonomy import SEVERITY, SOURCE_TYPES, is_valid_tactic

_HERE = os.path.dirname(__file__)
_PATTERN_GLOB = os.path.join(_HERE, "patterns", "*.jsonl")


@dataclass
class PhishingPattern:
    id: str
    tactic: str                 # a slug from taxonomy.TACTICS
    title: str
    example_text: str           # a representative (sanitized/synthetic) message excerpt
    linguistic_cues: list[str]  # the concrete surface signals a human/AI can point to
    severity: str               # taxonomy.SEVERITY
    source_type: str            # taxonomy.SOURCE_TYPES
    explanation: str            # why this is manipulation — the 'explains its reasoning' text
    tags: list[str] = field(default_factory=list)

    def validate(self) -> list[str]:
        errs = []
        if not self.id:
            errs.append("missing id")
        if not is_valid_tactic(self.tactic):
            errs.append(f"unknown tactic '{self.tactic}'")
        if self.severity not in SEVERITY:
            errs.append(f"bad severity '{self.severity}'")
        if self.source_type not in SOURCE_TYPES:
            errs.append(f"bad source_type '{self.source_type}'")
        if not self.linguistic_cues:
            errs.append("linguistic_cues must not be empty")
        if not self.explanation:
            errs.append("explanation is required (the reasoning)")
        return errs


def load_patterns() -> list[PhishingPattern]:
    patterns: list[PhishingPattern] = []
    for path in sorted(glob.glob(_PATTERN_GLOB)):
        with open(path) as f:
            for i, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                patterns.append(PhishingPattern(**obj))
    return patterns


def validate_all() -> tuple[int, list[str]]:
    """Return (count, errors). Also enforces unique ids."""
    patterns = load_patterns()
    errors: list[str] = []
    seen: set[str] = set()
    for p in patterns:
        for e in p.validate():
            errors.append(f"{p.id or '?'}: {e}")
        if p.id in seen:
            errors.append(f"duplicate id: {p.id}")
        seen.add(p.id)
    return len(patterns), errors


if __name__ == "__main__":
    n, errs = validate_all()
    if errs:
        print(f"INVALID dataset ({n} patterns, {len(errs)} errors):")
        for e in errs:
            print("  -", e)
        raise SystemExit(1)
    print(f"OK: {n} phishing patterns, all valid.")
