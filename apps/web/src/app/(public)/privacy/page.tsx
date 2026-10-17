import type { Metadata } from "next";

export const metadata: Metadata = { title: "Public scanner privacy", alternates: { canonical: "/privacy" } };

export default function PrivacyPage() {
  return <article className="public-document"><p className="public-kicker">PRIVACY / PUBLIC SCANNER</p>
    <h1>Only what<br /><em>you choose to submit.</em></h1>
    <p className="document-intro">The public scanner processes the message, URL, and optional sender and subject fields you explicitly submit. Remove personal information and secrets before sending.</p>
    <div className="document-sections">
      <section><h2>Processing</h2><p>Your submission goes through the website's server to the Teger detection API. Local rules analyze it there. The public scanner does not send it to a cloud AI provider, fetch the submitted URL, or access your email account.</p></section>
      <section><h2>Retention</h2><p>The public analysis route does not save submissions or results to an application database, tenant history, or audit buffer. The form and result stay in the current browser page's memory; this workflow does not write them to local storage.</p>
        <p>Hosting providers may process request metadata such as IP address, time, and response status in operational logs. This page does not promise that infrastructure metadata is never retained.</p></section>
      <section><h2>Results and exports</h2><p>Evidence excerpts use best-effort redaction. This is not a guarantee that every personal detail will be removed. Review a report before sharing it. When you choose Download report, a text file is created on your device. Copy verification note writes a generic note to your clipboard.</p></section>
      <section><h2>Scope</h2><p>This notice describes the public scanner. Connecting to the experimental security console introduces a separate encrypted session cookie and tenant analysis history. The extension and optional cloud explanations have their own documented processing behavior.</p></section>
      <section><h2>Contact</h2><p>Teger AI is operated by DUKERS LTD. Contact <a href="mailto:hello@tegerai.tech">hello@tegerai.tech</a> with privacy questions.</p></section>
    </div></article>;
}
