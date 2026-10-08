def _create(client, keys, who, **body):
    r = client.post("/v1/analyses", json=body or {"content": "urgent: wire transfer today"}, headers=keys.header(who))
    assert r.status_code == 201
    return r.json()["analysis_id"]


def test_owner_can_read_own_analysis(client, keys):
    analysis_id = _create(client, keys, "alice")
    r = client.get(f"/v1/analyses/{analysis_id}", headers=keys.header("alice"))
    assert r.status_code == 200 and r.json()["analysis_id"] == analysis_id


def test_other_tenant_gets_404_not_403(client, keys):
    analysis_id = _create(client, keys, "alice")
    r = client.get(f"/v1/analyses/{analysis_id}", headers=keys.header("bob"))
    assert r.status_code == 404
    assert r.json() == client.get("/v1/analyses/an_doesnotexist", headers=keys.header("bob")).json()


def test_same_tenant_different_key_shares_data(client, keys):
    analysis_id = _create(client, keys, "alice")
    assert client.get(f"/v1/analyses/{analysis_id}", headers=keys.header("reader")).status_code == 200


def test_listing_is_tenant_scoped(client, keys):
    a = _create(client, keys, "alice")
    b = _create(client, keys, "bob")
    alice_ids = {x["analysis_id"] for x in client.get("/v1/analyses", headers=keys.header("alice")).json()}
    bob_ids = {x["analysis_id"] for x in client.get("/v1/analyses", headers=keys.header("bob")).json()}
    assert a in alice_ids and b not in alice_ids
    assert b in bob_ids and a not in bob_ids


def test_events_are_tenant_scoped(client, keys):
    _create(client, keys, "alice")
    bob_events = client.get("/v1/events", headers=keys.header("bob")).json()
    assert all(e["tenant_id"] == "tenant-b" for e in bob_events)
    alice_events = client.get("/v1/events", headers=keys.header("alice")).json()
    assert alice_events and all(e["tenant_id"] == "tenant-a" for e in alice_events)


def test_tenant_cannot_be_injected_via_body(client, keys):
    r = client.post("/v1/analyses", json={"content": "x", "tenant_id": "tenant-b"}, headers=keys.header("alice"))
    assert r.status_code == 422


def test_per_tenant_store_is_bounded(make_client, keys):
    client = make_client(max_analyses_per_tenant=3)
    ids = [_create(client, keys, "alice") for _ in range(5)]
    listed = [x["analysis_id"] for x in client.get("/v1/analyses", headers=keys.header("alice")).json()]
    assert listed == list(reversed(ids[-3:]))
