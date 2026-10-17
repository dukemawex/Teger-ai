import Link from "next/link";
import type { Metadata } from "next";

export const metadata: Metadata = { title: "Our method and limits", alternates: { canonical: "/method" } };

export default function MethodPage() {
  return <article className="public-document"><p className="public-kicker">THE METHOD / OPEN TO INSPECTION</p>
    <h1>Understand the finding.<br /><em>Know its limits.</em></h1>
    <p className="document-intro">Teger helps you investigate suspicious requests. The public scanner uses the same local detection engine as the Teger security platform, with each finding linked to a specific rule.</p>
    <div className="document-sections">
      <section><h2>What the public scanner checks</h2><ul>
        <li><strong>Message language:</strong> pressure, credential requests, payment redirection, executive impersonation, secrecy, and attempts to instruct an AI reader.</li>
        <li><strong>URL structure:</strong> misleading user information, unusual hosts, encoded addresses, and other address-level indicators.</li>
        <li><strong>Brand and sender cues:</strong> lookalike names and mismatches against the engine's built-in brand directory.</li>
      </ul><p>The rules run on Teger's server after you submit. This public workflow does not invoke a cloud AI model or require an AI-provider key.</p></section>
      <section><h2>How to read your result</h2><table><thead><tr><th>Finding</th><th>Meaning</th></tr></thead><tbody>
        <tr><td>Strong attack indicators</td><td>The accumulated rule evidence reaches the policy's high-risk threshold.</td></tr>
        <tr><td>Reasons to be cautious</td><td>The rules found suspicious signals that warrant independent verification.</td></tr>
        <tr><td>More verification needed</td><td>Evidence is insufficient and at least one required check was unavailable.</td></tr>
        <tr><td>No indicators detected</td><td>The configured checks completed without enough evidence to flag a threat. This does not establish safety.</td></tr>
      </tbody></table><p>The 0–100 score is a weighted rule score, not a calibrated probability. False positives and false negatives are possible. Context matters: a legitimate message can contain urgent language.</p></section>
      <section><h2>What has not been verified</h2><p>The public scanner does not visit websites, follow redirects, inspect page contents or attachments, check live threat databases, verify sender ownership, or authenticate a business relationship. It does not inspect your inbox automatically.</p>
        <p>Brand coverage is limited to the built-in directory. Rules focus on English-language patterns. Domain interpretation uses an approximate suffix list. Shortened URLs and new attack patterns may hide evidence from these checks.</p></section>
      <section><h2>Your next action stays yours</h2><p>Read the evidence, contact the sender through a channel you already trust, and verify payment changes independently. Teger can prepare a report or a verification note; it does not send that note, block a site, quarantine mail, or make a payment.</p></section>
      <section><h2>Public scanner and security console</h2><p>The public scanner is stateless and account-free. The separate, experimental security console uses tenant API keys and supports optional, consent-based Claude explanations with a user's own key. Those explanations cannot change the deterministic verdict.</p>
        <p>The browser-extension beta remains a separate product. Website visits, automatic response, endpoint protection, and enterprise integrations should not be inferred from the public scanner.</p>
        <a href="https://github.com/dukemawex/Teger-ai">Inspect the source and tests on GitHub ↗</a></section>
    </div><Link className="public-button" href="/scan">Start an investigation <span aria-hidden="true">↗</span></Link>
  </article>;
}
