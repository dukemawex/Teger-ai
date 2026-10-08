"""Export JSON Schemas for every public contract.

    python -m teger_contracts.export_schemas            # write packages/contracts/schemas
    python -m teger_contracts.export_schemas --check    # fail if committed schemas are stale
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import analysis, modules

CONTRACTS = {
    "analysis-request": analysis.AnalysisRequest,
    "threat-verdict": analysis.ThreatVerdict,
    "windows-endpoint-event": modules.WindowsEndpointEvent,
    "file-scan-request": modules.FileScanRequest,
    "file-scan-result": modules.FileScanResult,
    "quarantine-request": modules.QuarantineRequest,
    "quarantine-result": modules.QuarantineResult,
    "email-message-analysis-request": modules.EmailMessageAnalysisRequest,
    "android-security-event": modules.AndroidSecurityEvent,
    "enterprise-policy-bundle": modules.EnterprisePolicyBundle,
}

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas"


def render() -> dict[str, str]:
    return {
        f"{name}.schema.json": json.dumps(model.model_json_schema(), indent=2, sort_keys=True) + "\n"
        for name, model in CONTRACTS.items()
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    rendered = render()
    if args.check:
        stale = [
            name for name, text in rendered.items()
            if not (SCHEMA_DIR / name).exists() or (SCHEMA_DIR / name).read_text() != text
        ]
        if stale:
            print("Stale contract schemas: " + ", ".join(stale), file=sys.stderr)
            return 1
        print(f"OK: {len(rendered)} contract schemas up to date.")
        return 0

    SCHEMA_DIR.mkdir(exist_ok=True)
    for name, text in rendered.items():
        (SCHEMA_DIR / name).write_text(text)
    print(f"Wrote {len(rendered)} schemas to {SCHEMA_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
