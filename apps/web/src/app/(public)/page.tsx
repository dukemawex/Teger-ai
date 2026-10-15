import Link from "next/link";
import { AtlasPlate } from "@/components/public/AtlasPlate";
import { VerdictSeal } from "@/components/VerdictSeal";
import { plateCases, RECORDED_CASES } from "@/demo/plate";

export const metadata = { alternates: { canonical: "/" } };

function Ev({ id }: { id: string }) {
  return <span className="evid">{id}</span>;
}

export default function LandingPage() {
  const plates = plateCases();
  const a = RECORDED_CASES["supplier-impersonation"];
  const b = RECORDED_CASES["approved-service"];
  const find = (c: typeof a, kind: string) => c.evidence.find((e) => e.kind === kind);
  const payment = find(a, "requests_payment_change");
  const hops = find(a, "redirect_chain");
  const form = find(a, "form_requests_sensitive_data");
  const record = find(a, "claim_matches_record");
  const conflict = a.evidence.find((e) => e.kind === "domain_conflicts_with_record" && e.details.role === "destination");
  const block = a.actions.find((x) => x.type === "blocklist_domain");
  const verify = a.actions.find((x) => x.type === "request_verification");
  const exception = find(b, "approved_third_party_service");

  return (
    <>
      <section className="hero" aria-labelledby="hero-title">
        <div className="inner">
          <div>
            <span className="eyebrow on-ink">Agentic phishing investigation · private beta</span>
            <h1 id="hero-title" className="display">Inspect the message.<br />Trace the site.<br /><em>Decide with evidence.</em></h1>
            <p className="lede">Teger investigates suspicious emails and websites against the context of your
              business — so your team knows what to do next.</p>
            <div className="btn-row hero-cta">
              <Link className="btn btn-bronze" href="/demo">Try an investigation</Link>
              <Link className="btn btn-ghost-ink" href="/app/analyze">Check a website</Link>
            </div>
            <p className="hero-note">
              The demo needs no account and uses synthetic evidence only. Checking a real website needs a Teger
              console key during the private beta — the console opens the link in an isolated fetch worker, never in
              your browser. <Link href="/connect">Console sign-in</Link>.
            </p>
          </div>
          <AtlasPlate cases={plates} />
        </div>
        <div className="frieze" aria-hidden="true" />
      </section>

      <section className="section" id="how" aria-labelledby="worked">
        <div className="inner">
          <div className="section-head">
            <div><span className="numeral">I.</span><h2 id="worked">A worked investigation</h2></div>
            <p className="lede">A “new bank details” email that names a real supplier. Every line below is taken from a
              recorded run of the investigator on synthetic fixtures — evidence identifiers included.</p>
          </div>
          <div className="ledger">
            <div className="ledger-row"><span className="n">1</span><h3>What was submitted</h3>
              <div><p>An email from <span className="mono">{a.input.sender}</span> asking accounts to update remittance
                details before the payment run, with one link.</p>
                {payment && <p className="small muted"><Ev id={payment.id} /> {payment.summary}</p>}</div></div>
            <div className="ledger-row"><span className="n">2</span><h3>Which checks ran, and why</h3>
              <div><p>The link redirected, so Teger followed it hop by hop and read the destination as data — no
                scripts, no form submission. Because the page named a supplier, it then checked approved context.</p>
                {hops && <p className="small muted"><Ev id={hops.id} /> {hops.summary}</p>}</div></div>
            <div className="ledger-row"><span className="n">3</span><h3>The evidence</h3>
              <div>{form && <p><Ev id={form.id} /> {form.summary}</p>}
                {conflict && <p><Ev id={conflict.id} /> {conflict.summary}</p>}</div></div>
            <div className="ledger-row"><span className="n">4</span><h3>Business context</h3>
              <div>{record && <p><Ev id={record.id} /> {record.summary}</p>}
                <p className="small muted">{a.assessment?.context_effect}</p></div></div>
            <div className="ledger-row"><span className="n">5</span><h3>Proposed response</h3>
              <div><p><VerdictSeal verdict={a.assessment!.verdict} /> {a.assessment?.recommended_next_action}</p>
                {block && <p className="small muted">{block.title}. Scope: {block.enforcement_scope}</p>}
                {verify && <p className="small muted">{verify.title} — {verify.params.contact}, taken from the approved
                  record, not from the email.</p>}</div></div>
            <div className="ledger-row"><span className="n">6</span><h3>Who approved it, and what happened</h3>
              <div><p>Nothing executes on the investigator&apos;s say-so. A reviewer approves each response; the approval is
                bound to the case version and the exact parameters, expires, and executes once. In the demo you are that
                reviewer, and the outcome is recorded in the case history.</p>
                <Link className="btn btn-small" href="/demo?case=supplier-impersonation">Approve it yourself in the demo</Link></div></div>
          </div>
        </div>
      </section>

      <section className="section section-limestone" aria-labelledby="context-title">
        <div className="inner">
          <div className="section-head">
            <div><span className="numeral">II.</span><h2 id="context-title">Approved context changes the answer</h2></div>
            <p className="lede">Not every unfamiliar domain is phishing. Teger compares what it observes with suppliers,
              services and identity providers your team approved — and records who approved them, when, and how.</p>
          </div>
          <div className="compare">
            <div>
              <span className="label-caps muted">Without the approved-service record</span>
              <h3>An invoice link that leaves the supplier&apos;s domain</h3>
              <p>Lumen Print Co sends invoice LP-2291 via <span className="mono">billing.ledgerly.example</span>. Compared
                only with Lumen Print&apos;s own domain, the link conflicts with its record.</p>
              <VerdictSeal verdict="suspicious" />
              <p className="small muted mt">Covered by the test <span className="mono">test_same_message_without_the_service_record_is_a_conflict</span>.</p>
            </div>
            <div>
              <span className="label-caps muted">With the record approved by J. Okafor</span>
              <h3>A third-party service the supplier really uses</h3>
              {exception && <p><Ev id={exception.id} /> {exception.summary}</p>}
              <VerdictSeal verdict={b.assessment!.verdict} />
              <p className="small muted mt">{b.assessment?.recommended_next_action} The off-domain link stays listed as
                contradictory evidence.</p>
            </div>
          </div>
        </div>
      </section>

      <section className="section" aria-labelledby="duties-title">
        <div className="inner">
          <div className="section-head">
            <div><span className="numeral">III.</span><h2 id="duties-title">What the agent may do — and what it may not</h2></div>
            <p className="lede">One orchestrator with a small set of typed tools, bounded by call limits, time limits and
              cancellation. It proposes; people decide.</p>
          </div>
          <div className="duties">
            <div><h3>Investigates on its own</h3><ul>
              <li>Reads the message for links, claimed sender and requested action</li>
              <li>Follows redirects under destination policy</li>
              <li>Reads the destination page without running scripts</li>
              <li>Compares domains with approved context</li>
              <li>Queries a reputation provider, when one is configured</li>
            </ul></div>
            <div><h3>Needs a person&apos;s approval</h3><ul>
              <li>Adding a domain to the tenant blocklist</li>
              <li>Recording a warning for the team</li>
              <li>Opening a verification task with the supplier</li>
              <li>Closing a case as legitimate</li>
            </ul></div>
            <div><h3>Never does</h3><ul>
              <li>Submit forms, enter credentials or download files</li>
              <li>Add or change trusted context</li>
              <li>Approve its own proposals</li>
              <li>Let a language model set the verdict</li>
              <li>Follow instructions found inside a message or page</li>
            </ul></div>
          </div>
        </div>
      </section>

      <section className="section section-ink" aria-labelledby="surfaces-title">
        <div className="inner">
          <div className="section-head">
            <div><span className="numeral">IV.</span><h2 id="surfaces-title">Web app and browser extension</h2></div>
            <p className="lede">Two surfaces with deliberately different responsibilities.</p>
          </div>
          <div className="split-panels">
            <div><span className="eyebrow on-ink">Web application</span><h3>Investigates what you submit</h3>
              <p>Paste a message or a website address. The console opens a case, runs the checks, keeps message,
                redirect chain, destination, findings and response together, and records approvals.</p>
              <p>It checks only what is submitted. It does not watch your other browser tabs.</p></div>
            <div><span className="eyebrow on-ink">Browser extension · private beta</span><h3>Sends a page when you ask</h3>
              <p>Scan a Gmail or Slack message you select, or press “Check this page” to hand the current page&apos;s
                address to your Teger console. No passwords, cookies, form contents or browsing history are collected.</p>
              <p>It does not block pages automatically, and an investigation may finish after you have already acted —
                so check before you type anything sensitive.</p></div>
          </div>
        </div>
      </section>

      <section className="section" id="status" aria-labelledby="status-title">
        <div className="inner">
          <div className="section-head">
            <div><span className="numeral">V.</span><h2 id="status-title">Privacy, limits and actual status</h2></div>
            <p className="lede">Teger is in private beta. This table says what exists today.</p>
          </div>
          <div className="table-wrap">
            <table className="status-table">
              <thead><tr><th>Capability</th><th>Status</th><th>Notes</th></tr></thead>
              <tbody>
                <tr><td>Interactive demo</td><td>Available</td><td>Synthetic fixtures on reserved domains; a simulated run with the deterministic planner. No network access.</td></tr>
                <tr><td>Case workspace, approvals, approved context</td><td>Implemented, experimental</td><td>Tenant API keys; SQLite persistence when configured. Not yet deployed for customers.</td></tr>
                <tr><td>Live website inspection</td><td>Implemented, needs configuration</td><td>Runs only in a separate fetch worker with destination checks at connection time; unavailable until an operator deploys it.</td></tr>
                <tr><td>Model-assisted planning (Claude)</td><td>Optional, consent-gated</td><td>Bring your own Anthropic key. Redacted observations only; the model picks among allowed checks and cannot change verdicts.</td></tr>
                <tr><td>Reputation lookups</td><td>Not connected</td><td>Reported as unavailable — never invented.</td></tr>
                <tr><td>Email quarantine, company-wide blocking</td><td>Not available</td><td>No mail or enforcement integration exists, so Teger proposes these rather than claiming them.</td></tr>
                <tr><td>Gmail / Slack message scanning extension</td><td>Private beta</td><td>Scans only the message you select. Raw text is not kept in extension history.</td></tr>
              </tbody>
            </table>
          </div>
          <p className="small muted mt">“No threat detected” means nothing checked contradicted your approved context; it
            is not a guarantee. The demo cases show how the product behaves — they do not measure real-world detection
            accuracy, and Teger publishes no accuracy figures.</p>
        </div>
      </section>
    </>
  );
}
