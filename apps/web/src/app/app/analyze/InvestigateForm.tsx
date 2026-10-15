"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";
import { caseApi } from "@/components/case/useCaseApi";
import type { InvestigationCase } from "@/lib/cases";

const api = caseApi("/api/live");

export function InvestigateForm({ aiPossible, byokHint, liveFetch }: {
  aiPossible: boolean; byokHint: string | null; liveFetch: boolean;
}) {
  const router = useRouter();
  const params = useSearchParams();
  const [url, setUrl] = useState(params.get("url") ?? "");
  const [message, setMessage] = useState("");
  const [sender, setSender] = useState("");
  const [subject, setSubject] = useState("");
  const [aiPlanning, setAiPlanning] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const fromExtension = params.get("from") === "extension";

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const body: Record<string, unknown> = { source: message.trim() ? "email" : "web" };
      if (url.trim()) body.url = url.trim();
      if (message.trim()) body.message = message.trim();
      if (sender.trim()) body.sender = sender.trim();
      if (subject.trim()) body.subject = subject.trim();
      if (aiPlanning) { body.ai_planning = true; body.cloud_ai_consent = true; }
      const created = await api.post<InvestigationCase>("cases", body);
      router.push(`/app/cases/${created.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not start the investigation.");
      setBusy(false);
    }
  }

  return (
    <form className="panel panel-pad form" onSubmit={submit}>
      {fromExtension && (
        <p className="notice">This URL was sent from the Teger browser extension after you pressed “Check this page”.
          Review it before starting; nothing has been checked yet.</p>
      )}
      <label htmlFor="url">Website URL</label>
      <input id="url" type="url" inputMode="url" value={url} onChange={(e) => setUrl(e.target.value)} maxLength={2048}
        placeholder="https://…" autoComplete="off" spellCheck={false} />
      <span className="hint">
        {liveFetch ? "The destination is fetched by Teger's isolated fetch worker: no cookies, no scripts, forms are never submitted."
          : "Live destination inspection is not configured on this server, so Teger will report it as unavailable rather than guess."}
      </span>

      <label htmlFor="sender">Sender (optional)</label>
      <input id="sender" type="text" value={sender} onChange={(e) => setSender(e.target.value)} maxLength={320}
        placeholder="Name <address@example.com>" autoComplete="off" />
      <label htmlFor="subject">Subject (optional)</label>
      <input id="subject" type="text" value={subject} onChange={(e) => setSubject(e.target.value)} maxLength={998} autoComplete="off" />
      <div className="label-row"><label htmlFor="message">Message text</label>
        <span className="tiny muted">{message.length.toLocaleString()} / 20,000</span></div>
      <textarea id="message" value={message} onChange={(e) => setMessage(e.target.value)} maxLength={20000}
        placeholder="Paste the suspicious email or chat message. Links inside it are investigated." />
      <span className="hint">Screenshot and .eml upload are not available yet — paste the text instead.</span>

      <label className="check">
        <input type="checkbox" checked={aiPlanning} disabled={!aiPossible} onChange={(e) => setAiPlanning(e.target.checked)} />
        <span>Let Claude choose the order of checks (optional). I consent to sending <b>redacted</b> observations
          to Anthropic{byokHint ? <> using my own key (<code>{byokHint}</code>)</> : " using Teger's key"}. The model
          cannot change the verdict, approve responses, or introduce new URLs.
          {!aiPossible && <> Add your own Anthropic key in <a href="/app/settings">Settings</a> to enable this.</>}</span>
      </label>

      <div className="btn-row">
        <button className="btn btn-primary" type="submit" disabled={busy || (!url.trim() && !message.trim())}>
          {busy ? "Opening case…" : "Start investigation"}
        </button>
        <button className="btn" type="button" onClick={() => { setUrl(""); setMessage(""); setSender(""); setSubject(""); setError(""); }}>
          Clear
        </button>
      </div>
      {error && <p className="notice notice-danger" role="alert">{error}</p>}
    </form>
  );
}
