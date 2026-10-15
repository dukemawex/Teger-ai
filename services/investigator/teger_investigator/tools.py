"""Typed investigation tools.

Each tool reads the investigation state, may call one bounded capability (fixture or live
fetcher, reputation provider, deterministic detectors), and returns evidence. Tools never
write trusted context, never grant permissions and never execute responses: proposing a
response is the only "action" a tool can take, and execution requires human approval.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, ValidationError

from teger_contracts import ContentType
from teger_security_core import ThreatEngine
from teger_security_core.detectors.brand import BrandImpersonationDetector
from teger_security_core.detectors.language import CredentialHarvestingDetector, SocialEngineeringDetector
from teger_security_core.detectors.reputation import ReputationProvider
from teger_security_core.detectors.url_heuristics import UrlHeuristicsDetector
from teger_security_core.urls import UrlValidationError, normalize_url

from .fetch import FetchChain, Fetcher
from .inspect import MessageFacts, PageFacts, domain_matches, inspect_message, inspect_page, lookalike_of
from .models import CaseInput, ContextEntry, ContextKind, Evidence, EvidenceMethod, Mode, Severity, Stance, ToolState


def _poss(name: str) -> str:
    return f"{name}'" if name.endswith("s") else f"{name}'s"


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class ContextMatch:
    entry: ContextEntry
    claimed_in: str  # "message" | "page"


@dataclass
class InvestigationState:
    mode: Mode
    input: CaseInput
    context: list[ContextEntry]
    fetcher: Fetcher
    reputation: ReputationProvider | None
    evidence: list[Evidence] = field(default_factory=list)
    done: set[str] = field(default_factory=set)
    message: MessageFacts | None = None
    target_url: str | None = None
    candidate_urls: list[str] = field(default_factory=list)
    chain: FetchChain | None = None
    page: PageFacts | None = None
    static_verdict: str | None = None
    claimed: list[ContextMatch] = field(default_factory=list)
    context_checked: bool = False
    impersonation: list[str] = field(default_factory=list)  # evidence ids
    exceptions: list[str] = field(default_factory=list)
    reputation_listed: bool = False
    injection_ids: list[str] = field(default_factory=list)
    proposals_requested: bool = False

    @property
    def org_names(self) -> list[str]:
        return [e.name for e in self.context]

    def add(self, tool: str, *, source: str, method: EvidenceMethod, stance: Stance, kind: str, summary: str,
            severity: Severity = Severity.INFO, details: dict | None = None, excerpt: str | None = None) -> str:
        evidence = Evidence(
            id=f"ev-{len(self.evidence) + 1}", tool=tool, source=source, collected_at=_now(), method=method,
            stance=stance, severity=severity, kind=kind, summary=summary[:500], details=details or {},
            untrusted_excerpt=excerpt[:600] if excerpt else None,
        )
        self.evidence.append(evidence)
        return evidence.id

    def observed_hosts(self) -> list[tuple[str, str]]:
        """(host, role) pairs for everything the user could be sent to or asked to trust."""
        hosts: list[tuple[str, str]] = []
        if self.message and self.message.sender_domain:
            hosts.append((self.message.sender_domain, "sender"))
        if self.target_url:
            try:
                hosts.append((normalize_url(self.target_url).host, "link"))
            except UrlValidationError:
                pass
        if self.chain and self.chain.final_url and self.chain.final_url != self.target_url:
            hosts.append((normalize_url(self.chain.final_url).host, "destination"))
        if self.page:
            for form in self.page.forms:
                if form.action_host:
                    hosts.append((form.action_host, "form"))
        return list(dict.fromkeys(hosts))


@dataclass(frozen=True)
class ToolResult:
    state: ToolState
    detail: str | None = None
    evidence_ids: tuple[str, ...] = ()


class NoArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")


class UrlArg(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str


@dataclass(frozen=True)
class Tool:
    name: str
    purpose: str
    args_model: type[BaseModel]
    available: Callable[[InvestigationState], bool]
    run: Callable[[InvestigationState, BaseModel], ToolResult]

    def parse_args(self, state: InvestigationState, raw: dict | None) -> BaseModel:
        """Validates planner-supplied arguments. Raises ValueError on anything invalid."""
        try:
            args = self.args_model.model_validate(raw or {})
        except ValidationError as exc:
            raise ValueError(f"Invalid arguments for {self.name}: {exc.errors()[0]['msg']}") from None
        if isinstance(args, UrlArg):
            # The planner may only choose among URLs present in the submitted material;
            # it can never introduce a new destination for the fetcher.
            try:
                normalized = normalize_url(args.url).normalized
            except UrlValidationError:
                raise ValueError("Invalid URL argument.") from None
            if normalized not in state.candidate_urls:
                raise ValueError("URL argument is not one of the submitted links.")
            args = UrlArg(url=normalized)
        return args


# ------------------------------------------------------------------ implementations

def _extract_message(state: InvestigationState, _: BaseModel) -> ToolResult:
    inp = state.input
    facts = inspect_message(inp.message or "", inp.sender, inp.subject, state.org_names)
    state.message = facts
    ids = []
    src = "submitted message"
    ids.append(state.add("extract_message", source=src, method=EvidenceMethod.OBSERVED, stance=Stance.NEUTRAL,
                         kind="message_received", summary=(
                             f"Message from {inp.sender or 'an unknown sender'}"
                             f"{f' with subject “{inp.subject}”' if inp.subject else ''}; "
                             f"{len(facts.links)} link(s) found."),
                         details={"sender_domain": facts.sender_domain, "links": facts.links[:5]}))
    if facts.requests_payment_change:
        ids.append(state.add("extract_message", source=src, method=EvidenceMethod.OBSERVED, stance=Stance.RISK,
                             severity=Severity.MEDIUM, kind="requests_payment_change",
                             summary="The message asks the reader to change or confirm payment or bank details."))
    elif facts.requests_payment:
        ids.append(state.add("extract_message", source=src, method=EvidenceMethod.OBSERVED, stance=Stance.NEUTRAL,
                             kind="mentions_payment", summary="The message concerns an invoice or payment."))
    if facts.requests_credentials:
        ids.append(state.add("extract_message", source=src, method=EvidenceMethod.OBSERVED, stance=Stance.RISK,
                             severity=Severity.LOW, kind="requests_sign_in",
                             summary="The message asks the reader to sign in or confirm an account."))
    if facts.urgency:
        ids.append(state.add("extract_message", source=src, method=EvidenceMethod.OBSERVED, stance=Stance.RISK,
                             severity=Severity.LOW, kind="urgency", summary="The message applies time pressure."))
    if facts.claimed_orgs:
        ids.append(state.add("extract_message", source=src, method=EvidenceMethod.OBSERVED, stance=Stance.NEUTRAL,
                             kind="claims_organization",
                             summary=f"The message presents itself as coming from {', '.join(facts.claimed_orgs)}."))
    if facts.agent_directed_text:
        eid = state.add("extract_message", source=src, method=EvidenceMethod.OBSERVED, stance=Stance.RISK,
                        severity=Severity.MEDIUM, kind="agent_directed_instructions",
                        summary="The message contains text addressed to an AI or security tool. It was treated as "
                                "data and ignored.", excerpt=facts.agent_directed_text)
        state.injection_ids.append(eid)
        ids.append(eid)
    state.candidate_urls = list(dict.fromkeys(([state.target_url] if state.target_url else []) + facts.links))
    if not state.target_url and facts.links:
        state.target_url = facts.links[0]
    return ToolResult(ToolState.COMPLETED, f"{len(facts.links)} link(s), {len(ids)} observation(s).", tuple(ids))


def _static_analysis(state: InvestigationState, _: BaseModel) -> ToolResult:
    engine = ThreatEngine(detectors=[UrlHeuristicsDetector(), BrandImpersonationDetector(),
                                     CredentialHarvestingDetector(), SocialEngineeringDetector()])
    inp = state.input
    try:
        result = engine.analyze(url=state.target_url, content=inp.message, sender=inp.sender, subject=inp.subject,
                                content_type=ContentType(inp.source) if inp.source in ContentType._value2member_map_
                                else ContentType.OTHER)
    except UrlValidationError as exc:
        eid = state.add("static_analysis", source="Teger deterministic detectors", method=EvidenceMethod.DERIVED,
                        stance=Stance.RISK, severity=Severity.MEDIUM, kind="url_rejected",
                        summary=f"The link was rejected by Teger's URL validation: {exc}")
        return ToolResult(ToolState.COMPLETED, "URL rejected.", (eid,))
    state.static_verdict = result.decision.verdict.value
    ids = []
    for item in result.evidence[:6]:
        ids.append(state.add("static_analysis", source=f"Teger detector: {item.detector}",
                             method=EvidenceMethod.DERIVED,
                             stance=Stance.RISK if item.weight >= 10 else Stance.NEUTRAL,
                             severity=Severity(item.severity.value), kind=item.category,
                             summary=item.description, excerpt=item.indicator))
    return ToolResult(ToolState.COMPLETED,
                      f"{len(result.evidence)} rule match(es); deterministic verdict {result.decision.verdict.value}.",
                      tuple(ids))


def _resolve_redirects(state: InvestigationState, args: BaseModel) -> ToolResult:
    url = args.url if isinstance(args, UrlArg) else state.target_url
    if not url:
        return ToolResult(ToolState.SKIPPED, "No link to follow.")
    if url != state.target_url:
        state.target_url = url
    if not state.fetcher.available:
        chain = state.fetcher.fetch_chain(url)
        state.chain = chain
        eid = state.add("resolve_redirects", source="destination fetcher", method=EvidenceMethod.OBSERVED,
                        stance=Stance.NEUTRAL, kind="inspection_unavailable", summary=chain.error or "Unavailable.")
        return ToolResult(ToolState.UNAVAILABLE, chain.error, (eid,))
    chain = state.fetcher.fetch_chain(url)
    state.chain = chain
    source = "fixture network (synthetic)" if chain.provider == "fixture" else f"HTTP via {chain.provider}"
    ids = []
    hops = [h.url for h in chain.hops]
    if len(chain.hops) > 1:
        ids.append(state.add("resolve_redirects", source=source, method=EvidenceMethod.OBSERVED,
                             stance=Stance.NEUTRAL, kind="redirect_chain",
                             summary=f"The link redirected {len(chain.hops) - 1} time(s) before reaching "
                                     f"{chain.final_url or 'a destination'}.", details={"hops": hops}))
        first, last = normalize_url(hops[0]).host, normalize_url(hops[-1]).host
        if first != last:
            ids.append(state.add("resolve_redirects", source=source, method=EvidenceMethod.DERIVED,
                                 stance=Stance.RISK, severity=Severity.LOW, kind="cross_domain_redirect",
                                 summary=f"The link's domain ({first}) differs from where it lands ({last}).",
                                 details={"from": first, "to": last}))
    if chain.error:
        ids.append(state.add("resolve_redirects", source=source, method=EvidenceMethod.OBSERVED,
                             stance=Stance.NEUTRAL, severity=Severity.INFO, kind=f"fetch_{chain.error_kind}",
                             summary=f"Destination could not be inspected: {chain.error}",
                             details={"url": chain.final_url or url}))
        return ToolResult(ToolState.FAILED, chain.error, tuple(ids))
    if len(chain.hops) <= 1:
        ids.append(state.add("resolve_redirects", source=source, method=EvidenceMethod.OBSERVED,
                             stance=Stance.NEUTRAL, kind="no_redirect",
                             summary=f"The link responded directly (HTTP {chain.final_status}) without redirecting.",
                             details={"url": chain.final_url}))
    return ToolResult(ToolState.COMPLETED, f"{len(chain.hops)} hop(s); final HTTP {chain.final_status}.", tuple(ids))


def _inspect_page(state: InvestigationState, _: BaseModel) -> ToolResult:
    chain = state.chain
    if not chain or not chain.ok or chain.body is None:
        return ToolResult(ToolState.SKIPPED, "No fetched page to read.")
    page = inspect_page(chain.body, chain.final_url or chain.requested_url, state.org_names)
    state.page = page
    source = f"page at {chain.final_url}" + (" (fixture)" if chain.provider == "fixture" else "")
    ids = [state.add("inspect_page", source=source, method=EvidenceMethod.OBSERVED, stance=Stance.NEUTRAL,
                     kind="page_read", summary=f"Page title: “{page.title or 'untitled'}”. "
                     f"{len(page.forms)} form(s); scripts were not executed.",
                     details={"scripts_not_run": page.script_count}, excerpt=page.text_excerpt)]
    if page.claimed_orgs:
        ids.append(state.add("inspect_page", source=source, method=EvidenceMethod.OBSERVED, stance=Stance.NEUTRAL,
                             kind="page_claims_organization",
                             summary=f"The page presents itself as {', '.join(page.claimed_orgs)}."))
    for form in page.forms:
        if form.has_password or form.has_payment_fields:
            wanted = (("a password", form.has_password), ("bank or card details", form.has_payment_fields))
            asks = " and ".join(label for label, present in wanted if present)
            ids.append(state.add("inspect_page", source=source, method=EvidenceMethod.OBSERVED, stance=Stance.RISK,
                                 severity=Severity.MEDIUM, kind="form_requests_sensitive_data",
                                 summary=f"A form asks for {asks} and submits to {form.action_host or 'this page'}. "
                                         "Teger did not submit it.",
                                 details={"form_action_host": form.action_host, "fields": form.field_names[:10]}))
    if page.agent_directed_text:
        eid = state.add("inspect_page", source=source, method=EvidenceMethod.OBSERVED, stance=Stance.RISK,
                        severity=Severity.HIGH, kind="agent_directed_instructions",
                        summary=("Hidden page text" if page.agent_directed_hidden else "Page text") +
                        " tries to instruct an AI or security tool. It was treated as untrusted data; it cannot "
                        "change Teger's context, permissions or verdict.", excerpt=page.agent_directed_text)
        state.injection_ids.append(eid)
        ids.append(eid)
    return ToolResult(ToolState.COMPLETED, f"Title read; {len(page.forms)} form(s).", tuple(ids))


def _compare_context(state: InvestigationState, _: BaseModel) -> ToolResult:
    state.context_checked = True
    ids: list[str] = []
    claimed_names = set((state.message.claimed_orgs if state.message else []) +
                        (state.page.claimed_orgs if state.page else []))
    hosts = state.observed_hosts()
    claimed = [e for e in state.context if e.name in claimed_names]
    state.claimed = [ContextMatch(e, "message" if state.message and e.name in state.message.claimed_orgs
                                  else "page") for e in claimed]
    registry = "approved business context"
    if not claimed:
        # No organization claim; still check whether any observed host belongs to a record.
        for host, role in hosts:
            for entry in state.context:
                if any(domain_matches(host, d) for d in entry.domains):
                    ids.append(state.add("compare_context", source=registry, method=EvidenceMethod.DERIVED,
                                         stance=Stance.LEGITIMACY, kind="host_in_context",
                                         summary=f"The {role} domain {host} belongs to approved "
                                                 f"{entry.kind.value.replace('_', ' ')} {entry.name} "
                                                 f"(record {entry.id}).",
                                         details={"record": entry.id, "host": host}))
        if not ids:
            ids.append(state.add("compare_context", source=registry, method=EvidenceMethod.DERIVED,
                                 stance=Stance.NEUTRAL, kind="no_context_record",
                                 summary="No approved supplier, service or identity provider matches this "
                                         "material, so business context cannot confirm or contradict it."))
        return ToolResult(ToolState.COMPLETED, "No claimed organization matched a record.", tuple(ids))

    for entry in claimed:
        label = "supplier" if entry.kind is ContextKind.SUPPLIER else entry.kind.value.replace("_", " ")
        ids.append(state.add("compare_context", source=registry, method=EvidenceMethod.DERIVED, stance=Stance.NEUTRAL,
                             kind="claim_matches_record",
                             summary=f"{entry.name} is an approved {label} (record {entry.id}, approved by "
                                     f"{entry.approved_by} on {entry.approved_at.date().isoformat()}).",
                             details={"record": entry.id, "approved_domains": entry.domains}))
        for host, role in hosts:
            if any(domain_matches(host, d) for d in entry.domains):
                ids.append(state.add("compare_context", source=registry, method=EvidenceMethod.DERIVED,
                                     stance=Stance.LEGITIMACY, kind="domain_approved",
                                     summary=f"The {role} domain {host} is one of {_poss(entry.name)} "
                                             "approved domains.",
                                     details={"record": entry.id, "host": host, "role": role}))
                continue
            service = next((s for s in entry.approved_services if domain_matches(host, s.domain)), None)
            if service:
                eid = state.add("compare_context", source=registry, method=EvidenceMethod.DERIVED,
                                stance=Stance.LEGITIMACY, kind="approved_third_party_service",
                                summary=f"The {role} domain {host} is not {_poss(entry.name)} own domain, but it is "
                                        f"recorded as {_poss(entry.name)} approved {service.purpose} "
                                        f"(record {entry.id}, "
                                        f"verified via {entry.verification_source}).",
                                details={"record": entry.id, "host": host, "role": role})
                state.exceptions.append(eid)
                ids.append(eid)
                continue
            look = lookalike_of(host, entry.domains)
            severity = Severity.HIGH if role in {"destination", "link", "form"} else Severity.MEDIUM
            eid = state.add("compare_context", source=registry, method=EvidenceMethod.DERIVED, stance=Stance.RISK,
                            severity=severity, kind="domain_conflicts_with_record",
                            summary=f"The {role} domain {host} is not among {_poss(entry.name)} approved domains "
                                    f"({', '.join(entry.domains)}) or approved services"
                                    + (f"; it imitates {look}." if look else "."),
                            details={"record": entry.id, "host": host, "role": role, "lookalike_of": look})
            state.impersonation.append(eid)
            ids.append(eid)
    return ToolResult(ToolState.COMPLETED, f"Compared {len(hosts)} domain(s) with {len(claimed)} record(s).",
                      tuple(ids))


def _check_reputation(state: InvestigationState, _: BaseModel) -> ToolResult:
    provider = state.reputation
    if provider is None or getattr(provider, "mode", "none") == "none":
        eid = state.add("check_reputation", source="reputation provider", method=EvidenceMethod.OBSERVED,
                        stance=Stance.NEUTRAL, kind="reputation_unavailable",
                        summary="No reputation provider is configured; no reputation result was used.")
        return ToolResult(ToolState.UNAVAILABLE, "No reputation provider configured.", (eid,))
    urls = []
    for candidate in [state.target_url, state.chain.final_url if state.chain else None]:
        if candidate:
            try:
                urls.append(normalize_url(candidate))
            except UrlValidationError:
                pass
    response = provider.lookup(urls)
    mode = getattr(provider, "mode", "live")
    source = f"reputation provider ({mode}{', test fixture — not live intelligence' if mode == 'mock' else ''})"
    if not response.available:
        eid = state.add("check_reputation", source=source, method=EvidenceMethod.OBSERVED, stance=Stance.NEUTRAL,
                        kind="reputation_unavailable", summary=response.detail or "Reputation lookup failed.")
        return ToolResult(ToolState.FAILED, response.detail, (eid,))
    if not response.hits:
        eid = state.add("check_reputation", source=source, method=EvidenceMethod.OBSERVED, stance=Stance.NEUTRAL,
                        kind="reputation_not_listed",
                        summary="Not listed by the reputation provider. New phishing sites are often unlisted.")
        return ToolResult(ToolState.COMPLETED, "No listing.", (eid,))
    ids = []
    for hit in response.hits[:3]:
        state.reputation_listed = True
        ids.append(state.add("check_reputation", source=source, method=EvidenceMethod.OBSERVED, stance=Stance.RISK,
                             severity=Severity.HIGH, kind="reputation_listed",
                             summary=f"{hit.url} is listed as {hit.listing.value}.", details={"url": hit.url}))
    return ToolResult(ToolState.COMPLETED, f"{len(ids)} listing(s).", tuple(ids))


def _propose_response(state: InvestigationState, _: BaseModel) -> ToolResult:
    state.proposals_requested = True
    return ToolResult(ToolState.COMPLETED, "Assessment and response proposals prepared for human approval.")


def _has_link(s: InvestigationState) -> bool:
    return bool(s.target_url)


TOOLS: dict[str, Tool] = {t.name: t for t in [
    Tool("extract_message", "Reading the submitted message for links, the claimed sender and the requested action.",
         NoArgs, lambda s: bool(s.input.message and s.input.message.strip()), _extract_message),
    Tool("static_analysis", "Running Teger's deterministic URL and language checks.",
         NoArgs, lambda s: True, _static_analysis),
    Tool("resolve_redirects", "Following the link's redirects under destination policy (no cookies, no credentials).",
         UrlArg, _has_link, _resolve_redirects),
    Tool("inspect_page", "Reading the destination page as data — scripts are not run and forms are not submitted.",
         NoArgs, lambda s: bool(s.chain and s.chain.ok and s.chain.body is not None), _inspect_page),
    Tool("compare_context", "Checking the sender and destination against approved supplier, service and "
                            "identity-provider records.", NoArgs, lambda s: True, _compare_context),
    Tool("check_reputation", "Querying the configured reputation provider.", NoArgs, _has_link, _check_reputation),
    Tool("propose_response", "Preparing an assessment and response proposals for human approval.",
         NoArgs, lambda s: True, _propose_response),
]}
