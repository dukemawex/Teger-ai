import json

import pytest

from teger_api.keys import ApiKeyStore, generate_key, main as keygen_main

BODY = {"content": "hello"}


@pytest.mark.parametrize("header", [
    None, "", "Bearer", "Bearer ", "Basic abc", "Bearer tgr_short_x",
    "Bearer tgr_aaaaaaaaaaaa_" + "x" * 43, "bearer not-a-token",
])
def test_rejects_missing_or_bad_tokens(client, header):
    headers = {"Authorization": header} if header is not None else {}
    r = client.post("/v1/analyses", json=BODY, headers=headers)
    assert r.status_code == 401
    assert r.json() == {"detail": "Invalid or missing API key."}
    assert r.headers["www-authenticate"] == "Bearer"


def test_wrong_secret_for_existing_key_id(client, keys):
    prefix = keys.tokens["alice"].rsplit("_", 1)[0]
    token = keys.tokens["alice"]
    tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
    assert tampered.startswith(prefix[:16])
    assert client.post("/v1/analyses", json=BODY, headers={"Authorization": f"Bearer {tampered}"}).status_code == 401


def test_scope_enforcement(client, keys):
    assert client.post("/v1/analyses", json=BODY, headers=keys.header("reader")).status_code == 403
    assert client.get("/v1/analyses", headers=keys.header("writer")).status_code == 403
    assert client.post("/v1/analyses", json=BODY, headers=keys.header("writer")).status_code == 201
    assert client.get("/v1/analyses", headers=keys.header("reader")).status_code == 200


def test_whoami(client, keys):
    body = client.get("/v1/whoami", headers=keys.header("alice")).json()
    assert body["tenant_id"] == "tenant-a" and "analyses:write" in body["scopes"]
    assert body["cloud_ai_allowed"] is False


def test_store_never_holds_plaintext_secret():
    token, record = generate_key("t", ["analyses:read"])
    secret = token.split("_", 2)[2]
    assert secret not in json.dumps(record)
    assert ApiKeyStore.from_config(json.dumps([record])).authenticate(token).tenant_id == "t"


@pytest.mark.parametrize("record", [
    {"key_id": "UPPERCASE123", "tenant_id": "t", "scopes": [], "secret_sha256": "a" * 64},
    {"key_id": "abcdefabcdef", "tenant_id": "t", "scopes": ["admin"], "secret_sha256": "a" * 64},
    {"key_id": "abcdefabcdef", "tenant_id": "t", "scopes": [], "secret_sha256": "short"},
    {"key_id": "abcdefabcdef", "tenant_id": "../etc", "scopes": [], "secret_sha256": "a" * 64},
])
def test_invalid_key_config_rejected(record):
    with pytest.raises(ValueError):
        ApiKeyStore.from_config(json.dumps([record]))


def test_duplicate_key_ids_rejected():
    _, record = generate_key("t", ["analyses:read"])
    with pytest.raises(ValueError):
        ApiKeyStore.from_config(json.dumps([record, record]))


def test_keygen_cli(capsys):
    assert keygen_main(["--tenant", "acme", "--scopes", "analyses:read"]) == 0
    out = capsys.readouterr().out
    assert "tgr_" in out and '"tenant_id": "acme"' in out


def test_trailing_newline_variants_rejected():
    token, record = generate_key("t", ["analyses:read"])
    store = ApiKeyStore.from_config(json.dumps([record]))
    assert store.authenticate(token) is not None
    assert store.authenticate(token + "\n") is None
    with pytest.raises(ValueError):
        ApiKeyStore.from_config(json.dumps([{**record, "tenant_id": "t\n"}]))
