import time
import uuid

import pytest

APPROVER_SCOPES = ("cases:read", "cases:write", "context:write", "actions:approve")


@pytest.fixture
def case_keys(keys):
    keys.add("lead", "tenant-a", scopes=APPROVER_SCOPES)
    keys.add("analyst", "tenant-a", scopes=("cases:read", "cases:write"))
    keys.add("other", "tenant-b", scopes=APPROVER_SCOPES)
    return keys


@pytest.fixture
def api(make_client, case_keys):
    return make_client(demo_step_delay_ms=0)


def wait(api, path, headers, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        body = api.get(path, headers=headers).json()
        if body["status"] not in {"queued", "running"}:
            return body
        time.sleep(0.02)
    raise AssertionError("case did not finish")


def demo_headers(session=None):
    return {"X-Teger-Demo-Session": session or uuid.uuid4().hex}


# ------------------------------------------------------------------ live cases

def test_live_case_without_fetch_worker_reports_unavailable(api, case_keys):
    h = case_keys.header("lead")
    r = api.post("/v1/cases", headers=h, json={"url": "https://nwf-remit.example/r/7Hk2", "source": "web"})
    assert r.status_code == 201, r.text
    case = wait(api, f"/v1/cases/{r.json()['id']}", h)
    assert case["mode"] == "live"
    step = next(t for t in case["tools"] if t["tool"] == "resolve_redirects")
    assert step["state"] == "unavailable"
    # Never silently replaced by demo fixtures.
    assert not any(e["kind"] in {"page_read", "redirect_chain"} for e in case["evidence"])
    assert case["assessment"]["verdict"] == "inconclusive"


def test_case_requires_material_and_scopes(api, case_keys):
    assert api.post("/v1/cases", headers=case_keys.header("lead"), json={}).status_code == 422
    assert api.post("/v1/cases", headers=case_keys.header("alice"), json={"message": "hi"}).status_code == 403
    assert api.get("/v1/cases").status_code == 401


def test_ai_planning_requires_consent_and_a_key(api, case_keys):
    h = case_keys.header("lead")
    r = api.post("/v1/cases", headers=h, json={"message": "hello", "ai_planning": True})
    assert r.status_code == 400 and "consent" in r.json()["detail"]
    r = api.post("/v1/cases", headers=h, json={"message": "hello", "ai_planning": True, "cloud_ai_consent": True})
    assert r.status_code == 400 and "BYOK" in r.json()["detail"]


def test_context_approval_and_cross_tenant_isolation(api, case_keys):
    lead, analyst, other = (case_keys.header(n) for n in ("lead", "analyst", "other"))
    entry = {"kind": "supplier", "name": "Northwind Freight", "domains": ["northwind-freight.example"],
             "verified_contact": "+44 20 7946 0118", "verification_source": "Call-back"}
    assert api.post("/v1/context", headers=analyst, json=entry).status_code == 403
    created = api.post("/v1/context", headers=lead, json=entry)
    assert created.status_code == 201 and created.json()["approved_by"].startswith("API key")
    assert api.get("/v1/context", headers=other).json() == []

    case = api.post("/v1/cases", headers=lead, json={
        "sender": "Northwind Freight <a@northwind-freight-payments.example>",
        "message": "Northwind Freight: our bank details changed, update them at https://nwf-remit.example/r/1"})
    case_id = case.json()["id"]
    done = wait(api, f"/v1/cases/{case_id}", lead)
    assert any(e["kind"] == "domain_conflicts_with_record" for e in done["evidence"])
    assert api.get(f"/v1/cases/{case_id}", headers=other).status_code == 404
    assert api.get(f"/v1/cases/{case_id}/export", headers=other).status_code == 404
    action = done["actions"][0]
    decision = {"case_version": done["version"], "params_hash": action["params_hash"]}
    assert api.post(f"/v1/actions/{action['id']}/approve", headers=other, json=decision).status_code == 404
    assert api.post(f"/v1/actions/{action['id']}/approve", headers=analyst, json=decision).status_code == 403
    ok = api.post(f"/v1/actions/{action['id']}/approve", headers=lead, json=decision)
    assert ok.status_code == 200 and ok.json()["state"] == "approved"
    assert api.post(f"/v1/actions/{action['id']}/approve", headers=lead, json=decision).status_code == 409
    run = api.post(f"/v1/actions/{action['id']}/execute", headers=lead, json={"idempotency_key": "abcd1234"})
    assert run.status_code == 200 and run.json()["state"] == "executed"
    again = api.post(f"/v1/actions/{action['id']}/execute", headers=lead, json={"idempotency_key": "abcd1234"})
    assert again.json() == run.json()
    assert api.post(f"/v1/actions/{action['id']}/execute", headers=lead,
                    json={"idempotency_key": "zzzz9999"}).status_code == 409
    exported = api.get(f"/v1/cases/{case_id}/export", headers=lead).json()
    assert exported["export_format"] == "teger.case.v1" and exported["synthetic_demo_data"] is False
    activity = [a["type"] for a in api.get("/v1/activity", headers=lead).json()]
    assert "action.approved" in activity and "context.approved" in activity


# ------------------------------------------------------------------ demo

def test_demo_catalog_and_full_journey(api):
    catalog = api.get("/v1/demo/catalog").json()
    assert {c["id"] for c in catalog} == {"supplier-impersonation", "approved-service", "inconclusive",
                                          "prompt-injection"}
    h = demo_headers()
    r = api.post("/v1/demo/cases", headers=h, json={"fixture_id": "supplier-impersonation"})
    assert r.status_code == 201
    case = wait(api, f"/v1/demo/cases/{r.json()['id']}", h)
    assert case["mode"] == "demo" and case["assessment"]["verdict"] == "malicious"
    assert len(api.get("/v1/demo/context", headers=h).json()) == 5
    events = api.get(f"/v1/demo/cases/{case['id']}/events?after=0", headers=h).json()
    assert events[0]["type"] == "case.created" and any(e["type"] == "tool.started" for e in events)
    block = next(a for a in case["actions"] if a["type"] == "blocklist_domain")
    body = {"case_version": case["version"], "params_hash": block["params_hash"]}
    assert api.post(f"/v1/demo/actions/{block['id']}/approve", headers=h, json=body).json()["state"] == "approved"
    executed = api.post(f"/v1/demo/actions/{block['id']}/execute", headers=h, json={"idempotency_key": "demo-key-1"})
    assert "demo-only" in executed.json()["execution_result"]
    assert api.get("/v1/demo/blocklist", headers=h).json()[0]["domain"] == "secure-docs.test"
    assert api.post(f"/v1/demo/actions/{block['id']}/explode", headers=h, json={}).status_code == 404
    assert api.post(f"/v1/demo/actions/{block['id']}/approve", headers=h, json={"x": 1}).status_code == 422


def test_demo_sessions_are_isolated_and_reset_is_scoped(api, case_keys):
    a, b = demo_headers(), demo_headers()
    case = api.post("/v1/demo/cases", headers=a, json={"fixture_id": "inconclusive"}).json()
    api.post("/v1/demo/cases", headers=b, json={"fixture_id": "inconclusive"})
    assert api.get(f"/v1/demo/cases/{case['id']}", headers=b).status_code == 404
    assert api.get(f"/v1/cases/{case['id']}", headers=case_keys.header("lead")).status_code == 404
    assert api.post("/v1/demo/session/reset", headers=a).json() == {"reset": True}
    assert api.get("/v1/demo/cases", headers=a).json() == []
    assert len(api.get("/v1/demo/cases", headers=b).json()) == 1


def test_demo_rejects_arbitrary_input_and_bad_sessions(api):
    h = demo_headers()
    assert api.post("/v1/demo/cases", headers=h, json={"fixture_id": "nope"}).status_code == 404
    assert api.post("/v1/demo/cases", headers=h,
                    json={"fixture_id": "inconclusive", "url": "http://169.254.169.254/"}).status_code == 422
    assert api.get("/v1/demo/cases", headers={"X-Teger-Demo-Session": "../../etc"}).status_code == 400
    assert api.get("/v1/demo/cases").status_code == 400


def test_demo_can_be_disabled(make_client):
    c = make_client(demo_enabled=False)
    assert c.get("/v1/demo/cases", headers=demo_headers()).status_code == 404


def test_demo_rate_limited_per_ip(make_client):
    c = make_client(demo_ip_rate_limit_per_minute=3)
    h = demo_headers()
    codes = [c.get("/v1/demo/cases", headers=h).status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200] and codes[-1] == 429


def test_ready_reports_investigation_components(api):
    body = api.get("/readyz").json()["components"]
    assert body["investigation_storage"] == "in_memory" and body["fetch_worker"] == "not_configured"


def test_persistent_storage_survives_app_restart(make_client, case_keys, tmp_path):
    db = str(tmp_path / "cases.db")
    first = make_client(db_path=db, demo_step_delay_ms=0)
    h = case_keys.header("lead")
    case_id = first.post("/v1/cases", headers=h, json={"message": "Please sign in to review your account"}).json()["id"]
    wait(first, f"/v1/cases/{case_id}", h)
    second = make_client(db_path=db)
    restored = second.get(f"/v1/cases/{case_id}", headers=h)
    assert restored.status_code == 200 and restored.json()["status"] == "completed"
