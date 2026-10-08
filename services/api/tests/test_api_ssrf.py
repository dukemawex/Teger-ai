"""SSRF regression: analysis must never open network connections to submitted URLs."""
import socket

import pytest

SSRF_TARGETS = [
    "http://127.0.0.1:8000/admin", "http://169.254.169.254/latest/meta-data/iam/",
    "http://[::ffff:169.254.169.254]/", "http://2130706433/", "http://0x7f.1/", "http://localhost:6379/",
    "http://metadata.google.internal/computeMetadata/v1/", "http://10.0.0.5/", "https://rebind.example/",
]


@pytest.fixture
def no_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError(f"network access attempted: {args[:2]}")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)


@pytest.mark.parametrize("url", SSRF_TARGETS)
def test_analysis_never_touches_network(client, keys, no_network, url):
    r = client.post("/v1/analyses", json={"url": url}, headers=keys.header("alice"))
    assert r.status_code == 201


@pytest.mark.parametrize("url", SSRF_TARGETS[:-1])
def test_internal_targets_are_flagged(client, keys, url):
    body = client.post("/v1/analyses", json={"url": url}, headers=keys.header("alice")).json()
    categories = {e["category"] for e in body["evidence"]}
    assert "private_network_target" in categories


def test_links_inside_content_are_not_fetched(client, keys, no_network):
    content = "Reset here: http://169.254.169.254/latest/ and http://localhost/admin"
    assert client.post("/v1/analyses", json={"content": content}, headers=keys.header("alice")).status_code == 201
