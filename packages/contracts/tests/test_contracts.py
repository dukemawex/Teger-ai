from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from teger_contracts import AnalysisRequest
from teger_contracts.export_schemas import main as export_main
from teger_contracts.modules import QuarantineAction, QuarantineRequest

SHA = "a" * 64


def test_analysis_request_requires_url_or_content():
    with pytest.raises(ValidationError):
        AnalysisRequest()
    with pytest.raises(ValidationError):
        AnalysisRequest(content="   ")
    assert AnalysisRequest(url="https://example.com").url


def test_analysis_request_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        AnalysisRequest(content="hi", tenant_id="someone-else")


def test_consent_defaults_to_false():
    assert AnalysisRequest(content="hi").cloud_ai_consent is False


def test_quarantine_contract_cannot_express_delete():
    assert {a.value for a in QuarantineAction} == {"quarantine", "restore"}
    with pytest.raises(ValidationError):
        QuarantineRequest(
            tenant_id="t", command_id="c", device_id="d", action="delete", file_sha256=SHA,
            original_path="x", reason="r", requested_by="admin",
            approved_at=datetime.now(timezone.utc), expires_at=datetime.now(timezone.utc),
            signature="sig",
        )


def test_committed_schemas_are_current():
    assert export_main(["--check"]) == 0
