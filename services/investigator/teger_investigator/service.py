"""Investigation service: case lifecycle, bounded orchestration, approvals, trusted context.

Separation of duties:
* evidence collection — tools (fixture or configured live capabilities only);
* interpretation — optional Claude planner chooses tools; it cannot decide verdicts;
* policy — :func:`policy.assess`, deterministic;
* execution authorization — a human approval bound to tenant, case, case version and the
  exact action parameters, with expiry and idempotent execution.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from teger_security_core.detectors.reputation import ReputationProvider
from teger_security_core.urls import UrlValidationError, normalize_url

from .fetch import Fetcher
from .models import (
    ActionState,
    ApprovalDecision,
    Case,
    CaseInput,
    CaseStatus,
    ContextEntry,
    ContextEntryInput,
    Mode,
    ProposedAction,
    ProposedActionType,
    Resolution,
    ResolutionInput,
    ToolRun,
    ToolState,
    Verdict,
)
from .planner import DeterministicPlanner, Planner
from .policy import assess
from .store import ConflictError, Store, utcnow
from .tools import TOOLS, InvestigationState

AGENT_ACTOR = "Teger investigator (proposes only)"


class NotFound(Exception):
    pass


class InvalidState(Exception):
    """Client-safe message describing why a transition is not allowed."""


@dataclass(frozen=True)
class Limits:
    max_steps: int = 10
    deadline_seconds: float = 60.0
    step_delay_seconds: float = 0.0  # demo pacing so progress is readable; no effect on results
    action_ttl: timedelta = timedelta(hours=24)

    def as_dict(self) -> dict[str, int]:
        return {"max_tool_calls": self.max_steps, "deadline_seconds": int(self.deadline_seconds),
                "action_ttl_minutes": int(self.action_ttl.total_seconds() // 60)}


@dataclass
class RunConfig:
    fetcher: Fetcher
    reputation: ReputationProvider | None
    planner_factory: Callable[[], Planner]
    planner_label: str
    limits: Limits


def params_hash(action_type: str, params: dict[str, str], case_id: str, case_version: int) -> str:
    canonical = json.dumps({"type": action_type, "params": params, "case": case_id, "version": case_version},
                           sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _title(inp: CaseInput) -> str:
    if inp.subject:
        return inp.subject[:120]
    if inp.url:
        try:
            return f"Website check: {normalize_url(inp.url).host}"
        except UrlValidationError:
            return "Website check"
    return (inp.message or "Message")[:80]


class InvestigationService:
    def __init__(self, store: Store, max_concurrent: int = 4, inline: bool = False):
        self.store = store
        self.inline = inline
        self._executor = None if inline else ThreadPoolExecutor(max_workers=max_concurrent,
                                                                thread_name_prefix="teger-investigation")
        self._cancel: dict[tuple[str, str], threading.Event] = {}
        self._configs: dict[tuple[str, str], RunConfig] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ cases

    def create_case(self, tenant: str, mode: Mode, inp: CaseInput, config: RunConfig, actor: str,
                    fixture_id: str | None = None, title: str | None = None) -> Case:
        now = utcnow()
        case = Case(id=f"case_{uuid.uuid4().hex[:16]}", mode=mode, title=title or _title(inp),
                    status=CaseStatus.QUEUED, version=1, created_at=now, updated_at=now, input=inp,
                    planner=config.planner_label, fixture_id=fixture_id, limits=config.limits.as_dict())
        self.store.save_case(tenant, case)
        self.store.append_event(tenant, case.id, "case.created", "Case created.", {"mode": mode.value})
        self.store.add_activity(tenant, "case.created", actor, f"Opened case “{case.title}”.", case.id)
        self._start(tenant, case.id, config)
        return case

    def _start(self, tenant: str, case_id: str, config: RunConfig) -> None:
        event = threading.Event()
        with self._lock:
            self._cancel[(tenant, case_id)] = event
            self._configs[(tenant, case_id)] = config
        if self._executor is None:
            self._run(tenant, case_id, config, event)
        else:
            self._executor.submit(self._run, tenant, case_id, config, event)

    def get_case(self, tenant: str, case_id: str) -> Case:
        case = self.store.get_case(tenant, case_id)
        if case is None:
            raise NotFound("Case not found.")
        return case

    def cancel(self, tenant: str, case_id: str, actor: str) -> Case:
        case = self.get_case(tenant, case_id)
        if case.status not in {CaseStatus.QUEUED, CaseStatus.RUNNING}:
            raise InvalidState("Only a queued or running investigation can be cancelled.")
        with self._lock:
            event = self._cancel.get((tenant, case_id))
        if event is None:
            # Process restarted while the case was running: mark it cancelled directly.
            case = case.model_copy(update={"status": CaseStatus.CANCELLED, "updated_at": utcnow(),
                                           "error": "Cancelled after a service restart."})
            self.store.save_case(tenant, case)
        else:
            event.set()
        self.store.append_event(tenant, case_id, "case.cancel_requested", "Cancellation requested.")
        self.store.add_activity(tenant, "case.cancel_requested", actor, "Requested cancellation.", case_id)
        return case

    def retry(self, tenant: str, case_id: str, config: RunConfig, actor: str) -> Case:
        case = self.get_case(tenant, case_id)
        if case.status in {CaseStatus.QUEUED, CaseStatus.RUNNING}:
            raise InvalidState("The investigation is still running.")
        superseded = self.store.supersede_open_actions(tenant, case_id)
        case = case.model_copy(update={
            "status": CaseStatus.QUEUED, "version": case.version + 1, "tools": [], "evidence": [],
            "assessment": None, "error": None, "resolution": None, "updated_at": utcnow(),
            "planner": config.planner_label, "limits": config.limits.as_dict(),
        })
        self.store.save_case(tenant, case)
        self.store.append_event(tenant, case_id, "case.retried", f"Investigation restarted (version {case.version}).",
                                {"superseded_actions": superseded})
        self.store.add_activity(tenant, "case.retried", actor, f"Re-ran the investigation (v{case.version}).",
                                case_id)
        self._start(tenant, case_id, config)
        return case

    # ------------------------------------------------------------------ orchestration

    def _context_for(self, tenant: str) -> list[ContextEntry]:
        return self.store.list_context(tenant)

    def _run(self, tenant: str, case_id: str, config: RunConfig, cancel: threading.Event) -> None:
        case = self.store.get_case(tenant, case_id)
        if case is None:
            return
        inp = case.input
        state = InvestigationState(mode=case.mode, input=inp, context=self._context_for(tenant),
                                   fetcher=config.fetcher, reputation=config.reputation)
        if inp.url and inp.url.strip():
            try:
                state.target_url = normalize_url(inp.url).normalized
                state.candidate_urls = [state.target_url]
            except UrlValidationError:
                state.target_url = None
        planner = config.planner_factory()
        limits = config.limits
        deadline = time.monotonic() + limits.deadline_seconds
        tools: list[ToolRun] = []
        stopped_early: str | None = None
        case = case.model_copy(update={"status": CaseStatus.RUNNING, "updated_at": utcnow()})
        self.store.save_case(tenant, case)
        self.store.append_event(tenant, case_id, "case.running", f"Investigation started ({config.planner_label}).")

        def persist(**updates: Any) -> None:
            nonlocal case
            case = case.model_copy(update={"tools": list(tools), "evidence": list(state.evidence),
                                           "updated_at": utcnow(), **updates})
            self.store.save_case(tenant, case)

        try:
            for _ in range(limits.max_steps):
                if cancel.is_set():
                    break
                if time.monotonic() > deadline:
                    stopped_early = "The investigation reached its time limit before finishing."
                    self.store.append_event(tenant, case_id, "limit.deadline", stopped_early)
                    break
                step = planner.next_step(state)
                if step is None:
                    break
                tool = TOOLS[step.tool]
                if step.note:
                    self.store.append_event(tenant, case_id, "planner.note", step.note)
                try:
                    args = tool.parse_args(state, step.args)
                except ValueError as exc:
                    state.done.add(step.tool)
                    tools.append(ToolRun(seq=len(tools) + 1, tool=step.tool, purpose=tool.purpose,
                                         state=ToolState.SKIPPED, selected_by=step.selected_by,
                                         detail=str(exc)[:300]))
                    self.store.append_event(tenant, case_id, "tool.rejected", str(exc))
                    persist()
                    continue
                run = ToolRun(seq=len(tools) + 1, tool=step.tool, purpose=tool.purpose, state=ToolState.RUNNING,
                              selected_by=step.selected_by, started_at=utcnow())
                tools.append(run)
                persist()
                self.store.append_event(tenant, case_id, "tool.started", tool.purpose,
                                        {"tool": step.tool, "seq": run.seq})
                if limits.step_delay_seconds:
                    cancel.wait(limits.step_delay_seconds)
                try:
                    result = tool.run(state, args)
                except Exception:  # a broken tool reduces coverage; it never reads as clean
                    result_state, detail, ids = ToolState.FAILED, "Tool failed unexpectedly.", ()
                else:
                    result_state, detail, ids = result.state, result.detail, result.evidence_ids
                state.done.add(step.tool)
                tools[-1] = run.model_copy(update={"state": result_state, "finished_at": utcnow(),
                                                   "detail": (detail or "")[:300] or None,
                                                   "evidence_ids": list(ids)})
                persist()
                self.store.append_event(tenant, case_id, "tool.finished", f"{step.tool}: {result_state.value}",
                                        {"tool": step.tool, "seq": run.seq, "state": result_state.value,
                                         "evidence_ids": list(ids)})
                if step.tool == "propose_response":
                    break
            else:
                stopped_early = "The investigation reached its tool-call limit before finishing."
                self.store.append_event(tenant, case_id, "limit.tool_calls", stopped_early)

            if cancel.is_set():
                persist(status=CaseStatus.CANCELLED, error="Cancelled by a reviewer before completion.")
                self.store.append_event(tenant, case_id, "case.cancelled", "Investigation cancelled.")
                return

            assessment = assess(state, stopped_early)
            for name in getattr(planner, "rejections", []):
                self.store.append_event(tenant, case_id, "planner.rejected", f"Rejected planner choice: {name}")
            persist(status=CaseStatus.COMPLETED, assessment=assessment)
            self.store.append_event(tenant, case_id, "case.assessed", assessment.headline,
                                    {"verdict": assessment.verdict.value})
            self._propose(tenant, case, state, config.limits)
        except Exception as exc:  # pragma: no cover - defensive
            persist(status=CaseStatus.FAILED, error=f"Investigation failed ({type(exc).__name__}).")
            self.store.append_event(tenant, case_id, "case.failed", "Investigation failed.")
        finally:
            with self._lock:
                self._cancel.pop((tenant, case_id), None)

    def _propose(self, tenant: str, case: Case, state: InvestigationState, limits: Limits) -> None:
        assessment = case.assessment
        assert assessment is not None
        demo = case.mode is Mode.DEMO
        record = state.claimed[0].entry if state.claimed else None
        proposals: list[tuple[ProposedActionType, str, dict[str, str], str]] = []
        destination = None
        if state.chain and state.chain.final_url:
            destination = normalize_url(state.chain.final_url).host
        elif state.target_url:
            destination = normalize_url(state.target_url).host
        blocklist_scope = ("Demo-only blocklist for this visitor session (synthetic)." if demo else
                           "This tenant's Teger blocklist: future Teger investigations will flag the domain. "
                           "Not enforced in browsers, DNS or email — no enforcement integration is connected.")
        warning_scope = ("Demo-only warning record." if demo else
                         "Recorded in Teger activity for this tenant. Not sent to anyone's inbox or chat.")
        verify_scope = "Creates a verification task in Teger. Nobody is contacted automatically."
        if assessment.verdict is Verdict.MALICIOUS and destination:
            proposals.append((ProposedActionType.BLOCKLIST_DOMAIN, f"Add {destination} to the blocklist",
                              {"domain": destination}, blocklist_scope))
        if assessment.verdict in {Verdict.MALICIOUS, Verdict.SUSPICIOUS}:
            proposals.append((ProposedActionType.RECORD_WARNING, "Record a warning for the team",
                              {"summary": assessment.headline[:200]}, warning_scope))
        needs_verification = assessment.verdict in {Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.INCONCLUSIVE} \
            or any(e.kind == "requests_payment_change" for e in state.evidence)
        if needs_verification:
            contact = (record.verified_contact if record and record.verified_contact
                       else "a contact you already hold (not one from the message)")
            org = record.name if record else "the sender"
            params = {"organization": org, "contact": contact}
            if record:
                params["record"] = record.id
            proposals.append((ProposedActionType.REQUEST_VERIFICATION, f"Verify with {org} independently",
                              params, verify_scope))
        if assessment.verdict is Verdict.NO_THREAT_DETECTED:
            proposals.append((ProposedActionType.CLOSE_AS_LEGITIMATE, "Close the case as legitimate",
                              {"reason": assessment.context_effect[:200]},
                              "Closes the Teger case. Changes nothing outside Teger."))
        now = utcnow()
        for action_type, title, params, scope in proposals:
            action = ProposedAction(
                id=f"act_{uuid.uuid4().hex[:16]}", case_id=case.id, case_version=case.version, type=action_type,
                title=title, params=params, params_hash=params_hash(action_type.value, params, case.id, case.version),
                enforcement_scope=scope, state=ActionState.PROPOSED, proposed_by=AGENT_ACTOR, proposed_at=now,
                expires_at=now + limits.action_ttl, demo_only=demo,
            )
            self.store.put_action(tenant, action)
            self.store.add_activity(tenant, "action.proposed", AGENT_ACTOR, f"Proposed: {title}.", case.id, action.id)
        self.store.append_event(tenant, case.id, "actions.proposed",
                                f"{len(proposals)} response(s) proposed for approval.")

    # ------------------------------------------------------------------ approvals

    def _load_action(self, tenant: str, action_id: str) -> tuple[ProposedAction, str | None]:
        found = self.store.get_action(tenant, action_id)
        if found is None:
            raise NotFound("Action not found.")
        return found

    def _expire_if_needed(self, tenant: str, action: ProposedAction) -> ProposedAction:
        if action.state is ActionState.PROPOSED and utcnow() >= action.expires_at:
            expired = action.model_copy(update={"state": ActionState.EXPIRED,
                                                "decision_note": "Approval window expired."})
            try:
                self.store.transition_action(tenant, expired, ActionState.PROPOSED)
                self.store.add_activity(tenant, "action.expired", "system", f"Expired: {action.title}.",
                                        action.case_id, action.id)
            except ConflictError:
                pass
            return expired
        return action

    def decide(self, tenant: str, action_id: str, decision: ApprovalDecision, actor: str,
               approve: bool) -> ProposedAction:
        action, _ = self._load_action(tenant, action_id)
        action = self._expire_if_needed(tenant, action)
        if action.state is not ActionState.PROPOSED:
            raise InvalidState(f"This action is {action.state.value}; it can no longer be decided.")
        case = self.get_case(tenant, action.case_id)
        if decision.case_version != case.version or action.case_version != case.version:
            raise InvalidState("The case changed since this proposal was made. Reload the case.")
        if decision.params_hash != action.params_hash:
            raise InvalidState("The approved parameters do not match the proposal.")
        updated = action.model_copy(update={
            "state": ActionState.APPROVED if approve else ActionState.REJECTED, "decided_by": actor[:120],
            "decided_at": utcnow(), "decision_note": decision.note,
        })
        try:
            self.store.transition_action(tenant, updated, ActionState.PROPOSED)
        except ConflictError as exc:
            raise InvalidState(str(exc)) from None
        verb = "Approved" if approve else "Rejected"
        self.store.add_activity(tenant, f"action.{updated.state.value}", actor, f"{verb}: {action.title}.",
                                action.case_id, action.id)
        self.store.append_event(tenant, action.case_id, f"action.{updated.state.value}", f"{verb}: {action.title}",
                                {"action_id": action.id, "by": actor[:120]})
        return updated

    def execute(self, tenant: str, action_id: str, idempotency_key: str, actor: str) -> ProposedAction:
        action, existing_key = self._load_action(tenant, action_id)
        if action.state is ActionState.EXECUTED:
            if existing_key == idempotency_key:
                return action  # idempotent replay
            raise InvalidState("This action was already executed.")
        if action.state is not ActionState.APPROVED:
            raise InvalidState("Only an approved action can be executed.")
        case = self.get_case(tenant, action.case_id)
        if action.case_version != case.version:
            raise InvalidState("The case changed since this action was approved.")
        claimed = action.model_copy(update={"state": ActionState.EXECUTED, "executed_at": utcnow(),
                                            "execution_result": "Executing…"})
        try:
            # Claim execution atomically: a concurrent second execute loses here.
            self.store.transition_action(tenant, claimed, ActionState.APPROVED, idempotency_key)
        except ConflictError:
            again, key = self._load_action(tenant, action_id)
            if again.state is ActionState.EXECUTED and key == idempotency_key:
                return again
            raise InvalidState("This action was already executed.") from None
        try:
            result = self._perform(tenant, case, action, actor)
            final = claimed.model_copy(update={"execution_result": result})
        except Exception:
            final = claimed.model_copy(update={"state": ActionState.FAILED,
                                               "execution_result": "Execution failed; nothing was changed."})
        self.store.transition_action(tenant, final, ActionState.EXECUTED)
        self.store.add_activity(tenant, f"action.{final.state.value}", actor,
                                f"{'Executed' if final.state is ActionState.EXECUTED else 'Failed'}: {action.title}. "
                                f"{final.execution_result}", action.case_id, action.id)
        self.store.append_event(tenant, action.case_id, f"action.{final.state.value}", final.execution_result or "",
                                {"action_id": action.id})
        return final

    def _perform(self, tenant: str, case: Case, action: ProposedAction, actor: str) -> str:
        demo = action.demo_only
        if action.type is ProposedActionType.BLOCKLIST_DOMAIN:
            domain = action.params["domain"]
            added = self.store.add_blocklist(tenant, domain, actor, case.id, action.id)
            where = "the demo-only blocklist (synthetic)" if demo else "this tenant's Teger blocklist"
            return (f"{domain} {'added to' if added else 'was already on'} {where}. "
                    + ("" if demo else "Not enforced in browsers, DNS or email."))
        if action.type is ProposedActionType.RECORD_WARNING:
            self.store.add_activity(tenant, "warning.recorded", actor, f"Team warning: {action.params['summary']}",
                                    case.id, action.id)
            return "Warning recorded in Teger activity. It was not sent to anyone's inbox or chat."
        if action.type is ProposedActionType.REQUEST_VERIFICATION:
            source = f" (from approved record {action.params['record']})" if "record" in action.params else ""
            return (f"Verification task recorded: contact {action.params['organization']} via "
                    f"{action.params['contact']}{source}. Teger did not contact anyone.")
        if action.type is ProposedActionType.CLOSE_AS_LEGITIMATE:
            self._set_resolution(tenant, case, ResolutionInput(outcome="confirmed_legitimate",
                                                               note="Closed via approved action."), actor)
            return "Case closed as legitimate."
        raise ValueError("Unknown action type.")

    # ------------------------------------------------------------------ resolution & export

    def _set_resolution(self, tenant: str, case: Case, data: ResolutionInput, actor: str) -> Case:
        current = self.get_case(tenant, case.id)
        updated = current.model_copy(update={"resolution": Resolution(outcome=data.outcome, note=data.note,
                                                                      recorded_by=actor[:120], recorded_at=utcnow()),
                                             "updated_at": utcnow()})
        self.store.save_case(tenant, updated)
        self.store.append_event(tenant, case.id, "case.resolved", f"Outcome recorded: {data.outcome}.")
        self.store.add_activity(tenant, "case.resolved", actor, f"Recorded outcome: {data.outcome.replace('_', ' ')}.",
                                case.id)
        return updated

    def resolve(self, tenant: str, case_id: str, data: ResolutionInput, actor: str) -> Case:
        case = self.get_case(tenant, case_id)
        if case.status is not CaseStatus.COMPLETED:
            raise InvalidState("An outcome can be recorded once the investigation has completed.")
        return self._set_resolution(tenant, case, data, actor)

    def export(self, tenant: str, case_id: str) -> dict:
        case = self.get_case(tenant, case_id)
        return {
            "export_format": "teger.case.v1",
            "exported_at": utcnow().isoformat(),
            "synthetic_demo_data": case.mode is Mode.DEMO,
            "case": json.loads(case.model_dump_json()),
            "events": [json.loads(e.model_dump_json()) for e in self.store.events(tenant, case_id)],
        }

    # ------------------------------------------------------------------ trusted context

    def add_context(self, tenant: str, data: ContextEntryInput, actor: str) -> ContextEntry:
        entry = ContextEntry(**data.model_dump(), id=f"ctx_{uuid.uuid4().hex[:10]}", approved_by=actor[:120],
                             approved_at=utcnow())
        self.store.add_context(tenant, entry)
        self.store.add_activity(tenant, "context.approved", actor,
                                f"Approved {entry.kind.value.replace('_', ' ')} {entry.name} "
                                f"({', '.join(entry.domains)}); verified via {entry.verification_source}.")
        return entry

    def revoke_context(self, tenant: str, entry_id: str, actor: str) -> ContextEntry:
        entry = self.store.revoke_context(tenant, entry_id)
        if entry is None:
            raise NotFound("Context entry not found.")
        self.store.add_activity(tenant, "context.revoked", actor, f"Revoked approved record {entry.name}.")
        return entry


def default_run_config(fetcher: Fetcher, reputation: ReputationProvider | None = None,
                       limits: Limits | None = None) -> RunConfig:
    return RunConfig(fetcher=fetcher, reputation=reputation, planner_factory=DeterministicPlanner,
                     planner_label="deterministic planner", limits=limits or Limits())
