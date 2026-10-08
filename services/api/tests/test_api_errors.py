import pytest

from teger_security_core.engine import ThreatEngine


def test_unhandled_errors_are_generic(make_client, keys, monkeypatch):
    def explode(self, **kwargs):
        raise RuntimeError("database password is hunter2")

    monkeypatch.setattr(ThreatEngine, "analyze", explode)
    client = make_client(raise_server_exceptions=False)
    r = client.post("/v1/analyses", json={"content": "x"}, headers=keys.header("alice"))
    assert r.status_code == 500
    assert "hunter2" not in r.text and r.json()["detail"] == "Internal error."
    assert r.json()["request_id"]


@pytest.mark.parametrize("chunked", [False, True])
def test_body_size_limit(make_client, keys, chunked):
    client = make_client(max_body_bytes=1024)
    payload = b'{"content": "' + b"a" * 4000 + b'"}'
    headers = {**keys.header("alice"), "Content-Type": "application/json"}
    if chunked:
        r = client.post("/v1/analyses", content=iter([payload[:500], payload[500:]]), headers=headers)
    else:
        r = client.post("/v1/analyses", content=payload, headers=headers)
    assert r.status_code == 413


def test_security_headers(client):
    r = client.get("/healthz")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["cache-control"] == "no-store"
    assert "default-src 'none'" in r.headers["content-security-policy"]


def test_request_id_echoed_only_when_well_formed(client):
    echoed = client.get("/healthz", headers={"X-Request-ID": "abcd-1234-efgh"}).headers["x-request-id"]
    assert echoed == "abcd-1234-efgh"
    injected = client.get("/healthz", headers={"X-Request-ID": "bad id\r\nx"}).headers["x-request-id"]
    assert injected != "bad id\r\nx" and len(injected) == 32


def test_hsts_in_production(make_client):
    c = make_client(environment="production", reputation_provider="none")
    assert "max-age" in c.get("/healthz").headers["strict-transport-security"]
