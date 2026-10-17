import socket

import pytest

from teger_api.settings import ApiSettings, ConfigurationError

PATH = "/v1/public/analyses"


def test_public_route_is_opt_in(client):
    assert client.get("/v1/public/status").status_code == 404
    assert client.post(PATH, json={"content": "Meeting at noon"}).status_code == 404


def test_real_detection_without_account_or_network(make_client, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Anonymous analysis must not use DNS or network")
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    c = make_client(public_scan_enabled=True, api_keys_json="")
    r = c.post(PATH, json={"content": "Urgent: provide your password. Your account will be suspended.",
                           "content_type": "email"})
    assert r.status_code == 200
    assert r.json()["verdict"] in ("malicious", "suspicious")
    assert any(e["category"] == "credential_request" for e in r.json()["evidence"])
    assert r.json()["explanation"]["status"] == "not_requested"
    assert r.headers["cache-control"] == "no-store"
    assert c.get("/v1/public/status").json()["fetches_urls"] is False
    assert c.get("/v1/analyses").status_code == 401


def test_no_mock_reputation_or_false_safe_url(make_client):
    c = make_client(public_scan_enabled=True, reputation_provider="mock")
    body = c.post(PATH, json={"url": "https://example.com"}).json()
    assert body["verdict"] == "unknown"
    assert body["intelligence_coverage"] == "partial"
    assert body["mock_intelligence_used"] is False
    assert all(d["provider_mode"] != "mock" for d in body["detection_sources"])


def test_public_results_are_not_in_any_tenant_history(make_client, keys):
    c = make_client(public_scan_enabled=True)
    result = c.post(PATH, json={"content": "Meeting at noon"}).json()
    for name in ("alice", "bob"):
        assert c.get("/v1/analyses", headers=keys.header(name)).json() == []
        assert c.get("/v1/events", headers=keys.header(name)).json() == []
        assert c.get(f"/v1/analyses/{result['analysis_id']}", headers=keys.header(name)).status_code == 404


@pytest.mark.parametrize("body", [{}, {"url": "javascript:alert(1)"}, {"content": "x" * 20001},
                                  {"content": "hello", "explain": True},
                                  {"content": "hello", "cloud_ai_consent": True},
                                  {"content": "hello", "tenant_id": "someone"}])
def test_rejects_invalid_or_privileged_inputs(make_client, body):
    c = make_client(public_scan_enabled=True)
    assert c.post(PATH, json=body).status_code == 422


def test_oversized_body_rejected(make_client):
    c = make_client(public_scan_enabled=True)
    assert c.post(PATH, content=b"x" * 70000).status_code == 413


def test_shared_limit_cannot_be_evaded_with_forwarded_headers(make_client):
    c = make_client(public_scan_enabled=True, public_scan_limit_per_minute=1)
    assert c.post(PATH, json={"content": "hello"}).status_code == 200
    r = c.post(PATH, json={"content": "hello"}, headers={"X-Forwarded-For": "192.0.2.25"})
    assert r.status_code == 429
    assert 1 <= int(r.headers["retry-after"]) <= 60


def test_redacts_url_secrets_and_never_runs_ai(make_client, fake_anthropic, ai_client):
    c = make_client(public_scan_enabled=True, analyst=ai_client.app.state.analyst)
    r = c.post(PATH, json={"url": "https://example.com/?token=private-value"})
    assert r.status_code == 200
    assert "private-value" not in r.text
    assert fake_anthropic.calls == []


def test_public_config_validation():
    assert ApiSettings.from_env({"TEGER_PUBLIC_SCAN_ENABLED": "true"}).public_scan_enabled
    with pytest.raises(ConfigurationError):
        ApiSettings.from_env({"TEGER_PUBLIC_SCAN_LIMIT_PER_MINUTE": "0"})
