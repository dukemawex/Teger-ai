import json
from pathlib import Path

from teger_investigator.demo import _semantic, record_demo_runs

RECORDING = Path(__file__).resolve().parents[3] / "apps" / "web" / "src" / "demo" / "recorded.json"


def test_committed_landing_recording_matches_the_engine():
    committed = json.loads(RECORDING.read_text(encoding="utf-8"))
    fresh = record_demo_runs()
    assert committed["synthetic"] is True
    assert committed["cases"].keys() == fresh["cases"].keys()
    for fixture_id, case in fresh["cases"].items():
        assert _semantic(committed["cases"][fixture_id]) == _semantic(case), (
            f"{fixture_id}: regenerate with `python -m teger_investigator.demo apps/web/src/demo/recorded.json`")
