import pytest

from teger_api.app import create_app
from teger_api.settings import ApiSettings, ConfigurationError


def test_health(client):
    r = client.get("/healthz")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_ready_reports_components_without_secrets(client):
    body = client.get("/readyz").json()
    assert body["status"] == "ready"
    assert body["components"]["reputation_provider"] == "mock"
    assert body["components"]["ai_analyst"] == "disabled"


def test_not_ready_without_keys(make_client):
    assert make_client(api_keys_json="").get("/readyz").status_code == 503


def test_openapi_documents_v1_routes(client):
    paths = client.get("/openapi.json").json()["paths"]
    assert {"/v1/analyses", "/v1/analyses/{analysis_id}", "/healthz", "/readyz"} <= set(paths)


def test_docs_hidden_in_production(make_client):
    c = make_client(environment="production", reputation_provider="none", expose_docs=False)
    assert c.get("/openapi.json").status_code == 404 and c.get("/docs").status_code == 404


def test_production_refuses_mock_provider():
    with pytest.raises(ConfigurationError):
        ApiSettings.from_env({"TEGER_ENV": "production", "TEGER_REPUTATION_PROVIDER": "mock"})
    with pytest.raises(ConfigurationError):
        create_app(ApiSettings(environment="production", reputation_provider="mock"))


def test_rejects_wildcard_cors():
    with pytest.raises(ConfigurationError):
        ApiSettings.from_env({"TEGER_CORS_ORIGINS": "*"})


def test_capabilities_are_honest(client):
    modules = {m["id"]: m["status"] for m in client.get("/v1/capabilities").json()["modules"]}
    assert modules["endpoint_protection"] == "planned"
    assert modules["device_inventory"] == "unavailable"
    assert modules["ai_explanations"] == "experimental"  # BYOK is allowed by default
    assert modules["url_reputation"] == "experimental"  # mock in tests


def test_ai_capability_unavailable_without_server_key_or_byok(make_client):
    from teger_ai_analyst import AnalystSettings, ClaudeAnalyst

    client = make_client(analyst=ClaudeAnalyst(AnalystSettings(allow_byok=False)))
    modules = {m["id"]: m["status"] for m in client.get("/v1/capabilities").json()["modules"]}
    assert modules["ai_explanations"] == "unavailable"
