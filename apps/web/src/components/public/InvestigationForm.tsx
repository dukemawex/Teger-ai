"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import type { ThreatVerdict } from "@/lib/types";
import { InvestigationResult } from "./InvestigationResult";

const EXAMPLES = [
  { label: "Urgent payment", mode: "message", input: "Urgent: our bank details have changed. Send payment today to the new bank account. Do not call to verify; I'm in a meeting.", sender: "", subject: "Updated invoice" },
  { label: "Account warning", mode: "message", input: "Your account will be suspended. Verify your account immediately at https://microsoft-login.example/verify and enter your password and verification code.", sender: "Microsoft Support <support@helpdesk.example>", subject: "Final notice" },
  { label: "Suspicious URL", mode: "url", input: "https://microsoft.com@account-check.example/login", sender: "", subject: "" },
  { label: "Everyday message", mode: "message", input: "Hi, the team meeting is at 10 tomorrow. Please bring your notes from last week. Thanks!", sender: "", subject: "Team meeting" },
] as const;

export function InvestigationForm() {
  const [mode, setMode] = useState<"message" | "url">("message");
  const [input, setInput] = useState("");
  const [sender, setSender] = useState("");
  const [subject, setSubject] = useState("");
  const [sample, setSample] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<ThreatVerdict | null>(null);
  const [error, setError] = useState("");
  const resultHeading = useRef<HTMLHeadingElement>(null);
  useEffect(() => { if (result) resultHeading.current?.focus(); }, [result]);

  function invalidate() { setResult(null); setError(""); setSample(""); }
  function clear() { invalidate(); setInput(""); setSender(""); setSubject(""); }
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (busy) return;
    setError(""); setResult(null); setBusy(true);
    try {
      const response = await fetch("/api/scan", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(mode === "url" ? { url: input.trim(), content_type: "web" }
          : { content: input.trim(), content_type: "email", sender, subject }),
        signal: AbortSignal.timeout(20000),
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.detail || "The scan could not be completed. Please try again.");
      setResult(body);
    } catch (e) {
      setError(e instanceof Error && e.name !== "TimeoutError" && e.name !== "AbortError"
        ? e.message : "The analysis timed out. No verdict was produced. Please try again.");
    } finally { setBusy(false); }
  }

  return <div className="investigation-grid">
    <div className="submission-panel">
      <div className="desk-panel-heading"><span className="public-kicker">01 / SUBMIT EVIDENCE</span><span className="private-label">No account needed</span></div>
      <form onSubmit={submit}>
        <fieldset disabled={busy}>
          <legend className="sr-only">Investigation input</legend>
          <div className="scan-modes" role="group" aria-label="What would you like to check?">
            <button type="button" aria-pressed={mode === "message"} onClick={() => { clear(); setMode("message"); }}>Message</button>
            <button type="button" aria-pressed={mode === "url"} onClick={() => { clear(); setMode("url"); }}>Website URL</button>
          </div>
          <label className="input-label" htmlFor="scan-content">{mode === "message" ? "Paste the message you want to check" : "Enter the URL you want to examine"}</label>
          <textarea id="scan-content" value={input} onChange={e => { invalidate(); setInput(e.target.value); }}
            required maxLength={mode === "url" ? 2048 : 20000} rows={8} spellCheck={false} autoComplete="off"
            aria-describedby="scan-input-help scan-counter" placeholder={mode === "message" ? "Paste an email, SMS, or chat message here…" : "https://example.com/account"} />
          <div className="input-caption"><span id="scan-input-help">{mode === "message" ? "Remove passwords and personal details first." : "The address is analyzed. The website is not visited."}</span>
            <span id="scan-counter">{input.length.toLocaleString()} / {mode === "url" ? "2,048" : "20,000"}</span></div>
          {mode === "message" && <details className="message-context"><summary>Add sender & subject <span>Optional</span></summary>
            <label htmlFor="scan-sender">Sender name and email</label><input id="scan-sender" value={sender} maxLength={320} autoComplete="off" spellCheck={false}
              onChange={e => { invalidate(); setSender(e.target.value); }} placeholder="Support <support@example.com>" />
            <label htmlFor="scan-subject">Subject</label><input id="scan-subject" value={subject} maxLength={998} autoComplete="off"
              onChange={e => { invalidate(); setSubject(e.target.value); }} placeholder="Subject line, if available" />
          </details>}
          <div className="submit-actions"><button className="public-button" type="submit" disabled={busy || !input.trim()}>
            {busy ? "Examining evidence…" : "Investigate"}<span aria-hidden="true">↗</span></button>
            {input && <button className="quiet-button" type="button" onClick={clear}>Clear</button>}</div>
          <p className="submission-privacy">Submitted content is processed on our server, without cloud AI, and is not saved to scan history. <Link href="/privacy">Privacy details</Link></p>
          <div className="sample-inputs"><p>Or start with a fictional example</p><div>{EXAMPLES.map(example =>
            <button type="button" key={example.label} onClick={() => {
              invalidate(); setMode(example.mode); setInput(example.input); setSender(example.sender);
              setSubject(example.subject); setSample(example.label);
            }}>{example.label}<span aria-hidden="true"> ↗</span></button>)}</div>
            <span>Examples fill the form. Press Investigate to run a real analysis.</span></div>
        </fieldset>
      </form>
      {error && <div className="scan-error" role="alert"><strong>Investigation not completed</strong><p>{error}</p></div>}
    </div>
    <section className="findings-panel" aria-label="Investigation results" aria-busy={busy}>
      <div className="desk-panel-heading"><span className="public-kicker">02 / FOLLOW THE EVIDENCE</span><span className="private-label">Rule-based analysis</span></div>
      {busy && <div className="scan-progress" role="status"><span className="progress-line" /><h2>Examining your submission</h2><p>Checking language, identity indicators, and URL structure.</p></div>}
      {!busy && !result && <div className="findings-empty"><span className="empty-symbol" aria-hidden="true">⌕</span>
        <h2>Your next move starts<br /><em>with better evidence.</em></h2><p>Submit a message or URL to see the findings here.</p>
        <ol><li><span>01</span>Specific warning signs</li><li><span>02</span>What could and could not be checked</li><li><span>03</span>A recommended next action</li></ol>
        <p className="empty-note">Teger offers decision support. It does not block websites, send messages, or take action for you.</p></div>}
      {result && <><h2 className="sr-only" tabIndex={-1} ref={resultHeading}>Investigation complete</h2>
        <InvestigationResult result={result} sample={sample} /></>}
    </section>
  </div>;
}
