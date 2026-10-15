"""Deterministic assessment policy for investigations.

The verdict is computed from evidence by fixed rules. Model output (if any) can never
change it. Each finding cites the evidence IDs that support it.
"""
from __future__ import annotations

from .models import Assessment, Finding, Stance, Verdict
from .tools import InvestigationState, _poss

POLICY_VERSION = "investigation-2026.10.1"


def _ids(state: InvestigationState, *kinds: str, stance: Stance | None = None) -> list[str]:
    return [e.id for e in state.evidence if e.kind in kinds and (stance is None or e.stance is stance)]


def assess(state: InvestigationState, stopped_early: str | None = None) -> Assessment:
    findings: list[Finding] = []
    contradictions: list[Finding] = []
    uncertainties: list[str] = []

    def add(target: list[Finding], statement: str, ids: list[str], stance: Stance) -> None:
        if ids:
            target.append(Finding(id=f"f-{len(findings) + len(contradictions) + 1}", statement=statement,
                                  evidence_ids=ids[:8], stance=stance))

    conflict = _ids(state, "domain_conflicts_with_record")
    conflict_dest = [e.id for e in state.evidence if e.kind == "domain_conflicts_with_record"
                     and e.details.get("role") in {"link", "destination", "form"}]
    exceptions = _ids(state, "approved_third_party_service")
    approved = _ids(state, "domain_approved", "host_in_context")
    sensitive_form = _ids(state, "form_requests_sensitive_data")
    payment_change = _ids(state, "requests_payment_change")
    sign_in = _ids(state, "requests_sign_in")
    injection = list(state.injection_ids)
    listed = _ids(state, "reputation_listed")
    fetch_failed = [e.id for e in state.evidence if e.kind.startswith("fetch_") or e.kind == "inspection_unavailable"]
    static_risk = [e.id for e in state.evidence if e.tool == "static_analysis" and e.stance is Stance.RISK]
    claim = _ids(state, "claim_matches_record")
    claimed_names = sorted({m.entry.name for m in state.claimed})
    org = claimed_names[0] if claimed_names else None

    impersonates = bool(conflict_dest) and bool(claim)
    asks_sensitive = bool(sensitive_form or payment_change)

    # ---------------------------------------------------------------- findings
    if impersonates:
        add(findings, f"The destination presents itself as {org}, an approved organization, but is not on "
                      f"{_poss(org)} approved domains or services.", claim[:1] + conflict_dest, Stance.RISK)
    elif conflict:
        add(findings, "A sender or link domain conflicts with the approved record for the organization it claims "
                      "to be.", claim[:1] + conflict, Stance.RISK)
    if sensitive_form:
        add(findings, "The destination asks for a password or bank/card details.", sensitive_form, Stance.RISK)
    if payment_change:
        add(findings, "The message asks for a change to payment or bank details — a common fraud pattern that "
                      "needs independent verification regardless of the link.", payment_change, Stance.RISK)
    if injection:
        add(findings, "The material contains instructions aimed at AI or security tools. Teger treated them as "
                      "data; they changed nothing.", injection, Stance.RISK)
    if listed:
        add(findings, "A reputation provider lists the destination.", listed, Stance.RISK)
    if exceptions:
        add(findings, "The destination is not the organization's own domain, but it is an independently approved "
                      "third-party service for that organization.", claim[:1] + exceptions, Stance.LEGITIMACY)
    if approved and not conflict:
        add(findings, "The observed domains match approved business context.", approved, Stance.LEGITIMACY)

    # ---------------------------------------------------------------- contradictions & uncertainty
    if exceptions:
        cross = _ids(state, "cross_domain_redirect") or [e.id for e in state.evidence
                                                         if e.kind == "redirect_chain"] or exceptions
        add(contradictions, "The link does not point at the supplier's own domain; this is explained only by the "
                            "approved-service record.", cross, Stance.RISK)
    if impersonates and approved:
        add(contradictions, "Some observed domains do match the approved record (for example the sender), which "
                            "a compromised or spoofed mailbox can also produce.", approved, Stance.LEGITIMACY)
    if fetch_failed:
        uncertainties.append("The destination could not be inspected, so its content and any forms are unknown.")
    if not state.context_checked:
        uncertainties.append("Approved business context was not compared before the investigation stopped.")
    elif not claim and not approved:
        uncertainties.append("No approved record matches this material, so business context could not confirm or "
                             "contradict it.")
    if any(e.kind == "reputation_unavailable" for e in state.evidence):
        uncertainties.append("No reputation provider was available; no reputation result was used.")
    if any(e.kind == "reputation_not_listed" for e in state.evidence):
        uncertainties.append("Not being listed by a reputation provider is weak evidence; new sites are often "
                             "unlisted.")
    if stopped_early:
        uncertainties.append(stopped_early)

    # ---------------------------------------------------------------- verdict
    if (impersonates and asks_sensitive) or listed:
        verdict = Verdict.MALICIOUS
    elif impersonates or conflict or injection or (
            static_risk and state.static_verdict in {"malicious", "suspicious"}):
        verdict = Verdict.SUSPICIOUS
    elif fetch_failed or stopped_early or (not claim and not approved and (asks_sensitive or sign_in)):
        verdict = Verdict.INCONCLUSIVE
    else:
        verdict = Verdict.NO_THREAT_DETECTED

    record = state.claimed[0].entry if state.claimed else None
    contact = f" using the verified contact on record ({record.verified_contact})" if record and \
        record.verified_contact else " using contact details you already hold, not those in the message"

    if verdict is Verdict.MALICIOUS:
        headline = (f"Impersonation of approved {'supplier' if record else 'organization'} {org}" if impersonates
                    else "Destination listed as malicious")
        action = (f"Do not enter anything on the page or change payment details. Confirm with {org}{contact}. "
                  "Approve the proposed blocklist entry and team warning." if org else
                  "Do not interact with the destination. Approve the proposed blocklist entry and team warning.")
    elif verdict is Verdict.SUSPICIOUS:
        headline = "Conflicts with approved context — treat as untrusted"
        action = f"Do not act on the request until it is confirmed{contact}."
    elif verdict is Verdict.INCONCLUSIVE:
        headline = "Not enough evidence to decide"
        action = (f"Teger could not establish whether this is legitimate. Verify independently{contact} before "
                  "signing in, paying, or replying.")
    else:
        headline = "No threat detected against approved context"
        action = ("Nothing checked contradicts your approved business context. Continue through your normal process"
                  + (" — the payment-change request still needs independent verification." if payment_change
                     else ". This is not a guarantee of safety."))

    if exceptions:
        effect = (f"Without the approved-service record, the off-domain link would have been treated as a conflict. "
                  f"The record for {org} (approved by {record.approved_by}) explains it." if record else
                  "An approved-service record explained an off-domain destination.")
    elif impersonates:
        effect = (f"The claim to be {org} was checked against {_poss(org)} approved record; the destination is not on "
                  "it. Generic URL checks alone could not establish who the page was imitating.")
    elif claim or approved:
        effect = "Observed domains were consistent with approved records; context alone does not prove safety."
    else:
        effect = "No approved record applied, so the assessment relies on observed evidence only."

    return Assessment(verdict=verdict, headline=headline, findings=findings, contradictions=contradictions,
                      uncertainties=uncertainties, recommended_next_action=action, context_effect=effect,
                      policy_version=POLICY_VERSION)
