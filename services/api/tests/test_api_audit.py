import json
import logging


def test_audit_log_never_contains_content(client, keys, caplog):
    secret_text = "send the wire to account 12345678 for jane.doe@victim.test"
    with caplog.at_level(logging.INFO, logger="teger.audit"):
        logging.getLogger("teger.audit").propagate = True
        r = client.post("/v1/analyses", headers=keys.header("alice"), json={
            "content": secret_text, "sender": "boss@corp.test", "url": "https://evil.example/path?token=abc",
        })
    assert r.status_code == 201
    logged = "\n".join(rec.getMessage() for rec in caplog.records)
    for fragment in ("wire to account", "jane.doe", "boss@corp.test", "token=abc", "/path"):
        assert fragment not in logged
    created = [json.loads(rec.getMessage()) for rec in caplog.records if "analysis.created" in rec.getMessage()]
    assert created and created[0]["details"]["url_host"] == "evil.example"
    assert created[0]["tenant_id"] == "tenant-a" and created[0]["request_id"]


def test_auth_failure_is_audited(client, caplog):
    with caplog.at_level(logging.INFO, logger="teger.audit"):
        logging.getLogger("teger.audit").propagate = True
        client.get("/v1/whoami", headers={"Authorization": "Bearer tgr_aaaaaaaaaaaa_" + "x" * 40})
    events = [json.loads(r.getMessage()) for r in caplog.records]
    assert any(e["event"] == "auth.failure" for e in events)
    assert all("tgr_aaaa" not in r.getMessage() for r in caplog.records)
