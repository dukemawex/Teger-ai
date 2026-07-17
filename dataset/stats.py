"""Print dataset coverage stats and export a flat JSON for reuse.

Run: python dataset/stats.py        # prints coverage
     python dataset/stats.py --json # writes dataset/export.json
"""
from __future__ import annotations

import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(__file__))

from dataclasses import asdict
from schema import load_patterns
from taxonomy import TACTICS


def main():
    patterns = load_patterns()
    by_tactic = Counter(p.tactic for p in patterns)
    by_sev = Counter(p.severity for p in patterns)
    by_src = Counter(p.source_type for p in patterns)

    print(f"total patterns: {len(patterns)}")
    print(f"tactics covered: {len(by_tactic)}/{len(TACTICS)}")
    print("\nby tactic:")
    for t in TACTICS:
        print(f"  {t:24s} {by_tactic.get(t, 0)}")
    print("\nby severity:", dict(by_sev))
    print("by source:  ", dict(by_src))

    if "--json" in sys.argv:
        out = os.path.join(os.path.dirname(__file__), "export.json")
        with open(out, "w") as f:
            json.dump([asdict(p) for p in patterns], f, indent=2)
        print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
