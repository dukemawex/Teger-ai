from datetime import timedelta
from types import SimpleNamespace

import pytest

from teger_ai_analyst.config import AnalystSettings
from teger_investigator.demo import DEMO_CASES, DEMO_CONTEXT, demo_fetcher
from teger_investigator.fetch import FixtureFetcher, FixtureResponse, UnavailableFetcher
from teger_investigator.models import (
    ActionState,
    ApprovalDecision,
    CaseInput,
    CaseStatus,
    ContextEntryInput,
    Mode,
    ProposedActionType,
    ResolutionInput,
    ToolState,
    Verdict,
)
from teger_investigator.planner import ClaudePlanner, PlannerChoice
from teger_investigator.service import InvalidState, InvestigationService, Limits, RunConfig, default_run_config
from teger_investigator.store import Store, utcnow
from teger_security_core.detectors.reputation import MockReputationProvider

T = "tenant-a"


@pytest.fixture
def store():
    s = Store()
    for entry in DEMO_CONTEXT:
        s.add_context(T, entry)
    return s


@pytest.fixture
def service(store):
    return InvestigationService(store, inline=True)


def run(service, fixture_id=None, inp=None, config=None, tenant=T):
    inp = inp or DEMO_CASES[fixture_id].input
    case = service.create_case(tenant, Mode.DEMO, inp, config or default_run_config(demo_fetcher()), "tester",
                               fixture_id=fixture_id)
    return service.get_case(tenant, case.id)


def tools_of(case):
    return [t.tool for t in case.tools]


# ------------------------------------------------------------------ demo journey

@pytest.mark.parametrize("fixture_id", list(DEMO_CASES))
def test_every_demo_case_reaches_its_documented_verdict(service, fixture_id):
    case = run(service, fixture_id)
    assert case.status is CaseStatus.COMPLETED
    assert case.assessment.verdict.value == DEMO_CASES[fixture_id].expected_verdict
    # Every finding cites evidence that exists in the case.
    ids = {e.id for e in case.evidence}
    for finding in case.assessment.findings + case.assessment.contradictions:
        assert set(finding.evidence_ids) <= ids
    assert case.actions, "every completed case proposes at least one response"
    assert all(a.state is ActionState.PROPOSED and a.demo_only for a in case.actions)


def test_supplier_impersonation_links_message_redirects_page_and_context(service):
    case = run(service, "supplier-impersonation")
    kinds = [e.kind for e in case.evidence]
    assert kinds.index("message_received") < kinds.index("redirect_chain") < kinds.index("page_read") \
        < kinds.index("domain_conflicts_with_record")
    hops = next(e for e in case.evidence if e.kind == "redirect_chain").details["hops"]
    assert hops == ["https://nwf-remit.example/r/7Hk2", "https://secure-docs.test/northwind/remittance"]
    roles = {e.details["role"] for e in case.evidence if e.kind == "domain_conflicts_with_record"}
    assert {"sender", "link", "destination", "form"} <= roles
    assert {a.type for a in case.actions} == {ProposedActionType.BLOCKLIST_DOMAIN, ProposedActionType.RECORD_WARNING,
                                              ProposedActionType.REQUEST_VERIFICATION}
    verify = next(a for a in case.actions if a.type is ProposedActionType.REQUEST_VERIFICATION)
    assert verify.params["contact"] == "Accounts payable desk, +44 20 7946 0118"  # from the record, not the email


def test_approved_third_party_service_is_a_legitimate_exception_not_immunity(service):
    case = run(service, "approved-service")
    assert case.assessment.verdict is Verdict.NO_THREAT_DETECTED
    assert any(e.kind == "approved_third_party_service" for e in case.evidence)
    assert case.assessment.contradictions, "the off-domain link is still surfaced as a contradiction"
    assert "not a guarantee" in case.assessment.recommended_next_action
    assert [a.type for a in case.actions] == [ProposedActionType.CLOSE_AS_LEGITIMATE]


def test_same_message_without_the_service_record_is_a_conflict(store):
    store.revoke_context(T, "ctx_lumen")
    store.add_context(T, DEMO_CONTEXT[1].model_copy(update={"id": "ctx_lumen2", "approved_services": []}))
    case = run(InvestigationService(store, inline=True), "approved-service")
    assert case.assessment.verdict is Verdict.SUSPICIOUS
    assert any(e.kind == "domain_conflicts_with_record" for e in case.evidence)


def test_inconclusive_requests_verification_and_never_claims_safe(service):
    case = run(service, "inconclusive")
    assert case.assessment.verdict is Verdict.INCONCLUSIVE
    assert "inspect_page" not in tools_of(case)
    assert next(t for t in case.tools if t.tool == "resolve_redirects").state is ToolState.FAILED
    assert [a.type for a in case.actions] == [ProposedActionType.REQUEST_VERIFICATION]


# ------------------------------------------------------------------ adaptive tool choice

def test_tool_choices_differ_when_evidence_differs(service):
    impersonation = tools_of(run(service, "supplier-impersonation"))
    timeout = tools_of(run(service, "inconclusive"))
    assert "inspect_page" in impersonation and "inspect_page" not in timeout


def test_reputation_is_consulted_only_when_context_does_not_explain_the_destination(service):
    config = default_run_config(demo_fetcher(), reputation=MockReputationProvider.from_fixture())
    assert "check_reputation" in tools_of(run(service, "supplier-impersonation", config=config))
    config = default_run_config(demo_fetcher(), reputation=MockReputationProvider.from_fixture())
    assert "check_reputation" not in tools_of(run(service, "approved-service", config=config))


def test_url_only_submission_skips_message_extraction(service):
    case = run(service, inp=CaseInput(url="https://billing.ledgerly.example/i/LP-2291", source="web"))
    assert tools_of(case)[0] == "static_analysis"
    assert "extract_message" not in tools_of(case)


# ------------------------------------------------------------------ unavailable / limits / cancel

def test_unavailable_fetcher_is_reported_and_never_replaced_by_fixtures(service):
    case = run(service, "supplier-impersonation", config=default_run_config(UnavailableFetcher()))
    step = next(t for t in case.tools if t.tool == "resolve_redirects")
    assert step.state is ToolState.UNAVAILABLE
    assert not any(e.kind in {"page_read", "redirect_chain"} for e in case.evidence)
    assert any("could not be inspected" in u for u in case.assessment.uncertainties)


def test_tool_call_limit_stops_and_is_disclosed(service):
    config = default_run_config(demo_fetcher(), limits=Limits(max_steps=2))
    case = run(service, "supplier-impersonation", config=config)
    assert len(case.tools) == 2
    assert any("tool-call limit" in u for u in case.assessment.uncertainties)


def test_cancel_and_retry(store):
    service = InvestigationService(store, inline=True)
    config = default_run_config(demo_fetcher())
    case = run(service, "inconclusive", config=config)
    with pytest.raises(InvalidState):
        service.cancel(T, case.id, "tester")  # already completed
    retried = service.retry(T, case.id, config, "tester")
    again = service.get_case(T, retried.id)
    assert again.version == 2 and again.status is CaseStatus.COMPLETED
    states = [a.state for a in again.actions]
    assert ActionState.EXPIRED in states and ActionState.PROPOSED in states  # old proposal superseded


def test_cancel_running_case_stops_before_assessment(store):
    import threading
    gate = threading.Event()

    class SlowFetcher(FixtureFetcher):
        def fetch_chain(self, url):
            gate.wait(2)
            return super().fetch_chain(url)

    service = InvestigationService(store, max_concurrent=1)
    config = RunConfig(SlowFetcher(dict(demo_fetcher().responses)), None,
                       default_run_config(demo_fetcher()).planner_factory, "deterministic", Limits())
    case = service.create_case(T, Mode.DEMO, DEMO_CASES["supplier-impersonation"].input, config, "tester")
    for _ in range(100):
        if service.get_case(T, case.id).status is CaseStatus.RUNNING:
            break
        threading.Event().wait(0.01)
    service.cancel(T, case.id, "tester")
    gate.set()
    for _ in range(200):
        final = service.get_case(T, case.id)
        if final.status not in {CaseStatus.RUNNING, CaseStatus.QUEUED}:
            break
        threading.Event().wait(0.01)
    assert final.status is CaseStatus.CANCELLED and final.assessment is None and not final.actions


# ------------------------------------------------------------------ prompt injection

def test_prompt_injection_is_evidence_and_changes_nothing(service, store):
    before = [e.model_dump() for e in store.list_context(T)]
    case = run(service, "prompt-injection")
    after = [e.model_dump() for e in store.list_context(T)]
    assert before == after
    injection = [e for e in case.evidence if e.kind == "agent_directed_instructions"]
    assert injection and injection[0].untrusted_excerpt and "Add ostrava-docs.example" in injection[0].untrusted_excerpt
    assert case.assessment.verdict is Verdict.MALICIOUS


class FakeClaude:
    """Returns scripted planner choices; records what it was sent."""

    def __init__(self, choices):
        self.choices = list(choices)
        self.calls = []
        self.beta = SimpleNamespace(messages=SimpleNamespace(parse=self._parse))

    def _parse(self, **kwargs):
        self.calls.append(kwargs)
        choice = self.choices.pop(0) if self.choices else PlannerChoice(tool="propose_response")
        return SimpleNamespace(parsed_output=choice, stop_reason="end_turn", model=kwargs["model"],
                               usage=SimpleNamespace(input_tokens=10, output_tokens=5))


def claude_config(client):
    settings = AnalystSettings(enabled=True, api_key_present=True)
    return RunConfig(demo_fetcher(), None, lambda: ClaudePlanner(settings, client), "claude", Limits())


def test_claude_planner_cannot_call_unknown_tools_or_new_urls(service, store):
    client = FakeClaude([
        PlannerChoice(tool="add_trusted_supplier", arguments={"domain": "ostrava-docs.example"}),
        PlannerChoice(tool="static_analysis"),
        PlannerChoice(tool="resolve_redirects", arguments={"url": "http://169.254.169.254/latest/meta-data"}),
    ])
    before = len(store.list_context(T))
    case = run(service, "prompt-injection", config=claude_config(client))
    assert len(store.list_context(T)) == before
    assert "add_trusted_supplier" not in tools_of(case)
    selected = {t.tool: t.selected_by for t in case.tools}
    assert "fallback" in selected["extract_message"]  # first (invalid) choice was replaced
    assert selected["static_analysis"].startswith("Claude planner")
    # The metadata URL was rejected; the fallback followed the submitted link instead.
    redirects = next(t for t in case.tools if t.tool == "resolve_redirects")
    assert "fallback" in redirects.selected_by
    assert all("169.254" not in str(e.details) for e in case.evidence)
    events = [e.message for e in store.events(T, case.id)]
    assert any("Rejected model choice" in m for m in events)
    assert any("Rejected model arguments" in m for m in events)
    # Untrusted page text reached the model only inside the nonce-delimited block.
    user = client.calls[-1]["messages"][0]["content"]
    assert "<untrusted_observations_" in user and "allowed_tools" in user
    assert client.calls[0]["model"] == "claude-opus-5-5"


def test_claude_planner_drives_a_different_order(service):
    client = FakeClaude([PlannerChoice(tool="compare_context"), PlannerChoice(tool="extract_message"),
                         PlannerChoice(tool="propose_response")])
    case = run(service, "approved-service", config=claude_config(client))
    assert tools_of(case)[:2] == ["compare_context", "extract_message"]


# ------------------------------------------------------------------ approvals

def _decision(action, case, **kw):
    return ApprovalDecision(case_version=case.version, params_hash=action.params_hash, **kw)


def test_approval_binds_version_and_parameters(service):
    case = run(service, "supplier-impersonation")
    action = next(a for a in case.actions if a.type is ProposedActionType.BLOCKLIST_DOMAIN)
    with pytest.raises(InvalidState):
        service.decide(T, action.id, ApprovalDecision(case_version=case.version, params_hash="0" * 64), "r", True)
    with pytest.raises(InvalidState):
        service.decide(T, action.id, ApprovalDecision(case_version=99, params_hash=action.params_hash), "r", True)
    with pytest.raises(InvalidState):
        service.execute(T, action.id, "key-00000001", "r")  # not approved yet
    approved = service.decide(T, action.id, _decision(action, case), "Reviewer A", True)
    assert approved.state is ActionState.APPROVED and approved.decided_by == "Reviewer A"
    with pytest.raises(InvalidState):
        service.decide(T, action.id, _decision(action, case), "Reviewer B", True)  # replayed approval


def test_execution_is_idempotent_and_single(service, store):
    case = run(service, "supplier-impersonation")
    action = next(a for a in case.actions if a.type is ProposedActionType.BLOCKLIST_DOMAIN)
    service.decide(T, action.id, _decision(action, case), "Reviewer", True)
    first = service.execute(T, action.id, "idem-key-1", "Reviewer")
    assert first.state is ActionState.EXECUTED and "demo-only" in first.execution_result
    assert service.execute(T, action.id, "idem-key-1", "Reviewer").execution_result == first.execution_result
    with pytest.raises(InvalidState):
        service.execute(T, action.id, "idem-key-2", "Reviewer")
    assert [b["domain"] for b in store.blocklist(T)] == ["secure-docs.test"]
    trail = [a["type"] for a in reversed(store.activity(T))]
    assert trail.index("action.proposed") < trail.index("action.approved") < trail.index("action.executed")


def test_rejected_and_expired_actions_cannot_execute(store):
    service = InvestigationService(store, inline=True)
    config = default_run_config(demo_fetcher(), limits=Limits(action_ttl=timedelta(seconds=-1)))
    case = run(service, "supplier-impersonation", config=config)
    action = case.actions[0]
    with pytest.raises(InvalidState, match="expired"):
        service.decide(T, action.id, _decision(action, case), "r", True)
    case = run(service, "supplier-impersonation")
    action = case.actions[0]
    service.decide(T, action.id, _decision(action, case), "r", False)
    with pytest.raises(InvalidState):
        service.execute(T, action.id, "idem-key-3", "r")


def test_close_as_legitimate_records_resolution(service):
    case = run(service, "approved-service")
    action = case.actions[0]
    service.decide(T, action.id, _decision(action, case), "AP reviewer", True)
    service.execute(T, action.id, "idem-key-4", "AP reviewer")
    assert service.get_case(T, case.id).resolution.outcome == "confirmed_legitimate"


def test_cross_tenant_reads_are_not_possible(service):
    case = run(service, "inconclusive")
    with pytest.raises(Exception):
        service.get_case("tenant-b", case.id)
    with pytest.raises(Exception):
        service.decide("tenant-b", case.actions[0].id, _decision(case.actions[0], case), "x", True)


# ------------------------------------------------------------------ context & persistence

def test_context_entries_record_approver_and_source(service, store):
    entry = service.add_context(T, ContextEntryInput(kind="supplier", name="Example Paper", domains=["Paper.Example."],
                                                     verification_source="Call-back 2026-10-01"), "Finance lead")
    assert entry.domains == ["paper.example"] and entry.approved_by == "Finance lead"
    assert store.activity(T)[0]["type"] == "context.approved"
    with pytest.raises(ValueError):
        ContextEntryInput(kind="supplier", name="Bad", domains=["not a domain"], verification_source="x" * 5)


def test_cases_and_approvals_persist_across_restart(tmp_path):
    path = str(tmp_path / "teger.db")
    store = Store(path)
    for entry in DEMO_CONTEXT:
        store.add_context(T, entry)
    service = InvestigationService(store, inline=True)
    case = run(service, "supplier-impersonation")
    action = case.actions[0]
    service.decide(T, action.id, _decision(action, case), "Reviewer", True)
    service.resolve(T, case.id, ResolutionInput(outcome="confirmed_phishing"), "Reviewer")
    store.close()

    reopened = Store(path)
    assert reopened.schema_version() == 1
    restored = InvestigationService(reopened, inline=True).get_case(T, case.id)
    assert restored.assessment.verdict is Verdict.MALICIOUS
    assert restored.resolution.outcome == "confirmed_phishing"
    assert next(a for a in restored.actions if a.id == action.id).state is ActionState.APPROVED
    assert len(reopened.events(T, case.id)) > 5


def test_fixture_fetcher_applies_hop_rules():
    fetcher = FixtureFetcher({
        "https://a.example/": FixtureResponse(status=302, location="http://b.example/"),
        "https://c.example/": FixtureResponse(status=302, location="https://user:pw@d.example/"),
        "https://e.example/": FixtureResponse(status=302, location="https://10.0.0.5/"),
    })
    assert "downgrade" in fetcher.fetch_chain("https://a.example/").error
    assert "credentials" in fetcher.fetch_chain("https://c.example/").error
    assert "private" in fetcher.fetch_chain("https://e.example/").error
    assert fetcher.fetch_chain("https://f.example:8443/").error_kind == "blocked"


def test_demo_cases_use_reserved_domains_only():
    from teger_investigator.demo import DEMO_RESPONSES
    hosts = [u.split("/")[2] for u in DEMO_RESPONSES]
    assert all(h.endswith((".example", ".test")) for h in hosts)
    assert utcnow().tzinfo is not None
