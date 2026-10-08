"use client";

import { useState } from "react";
import { VerdictView } from "@/components/VerdictView";
import type { ThreatVerdict } from "@/lib/types";

const CONTENT_TYPES = ["email", "chat", "sms", "web", "other"] as const;

export function AnalyzeForm({ cloudAiAllowed, byokHint }: { cloudAiAllowed: boolean; byokHint: string | null }) {
  const aiPossible = cloudAiAllowed || Boolean(byokHint);
  const [url, setUrl] = useState("");
  const [content, setContent] = useState("");
  const [sender, setSender] = useState("");
  const [subject, setSubject] = useState("");
  const [contentType, setContentType] = useState<(typeof CONTENT_TYPES)[number]>("email");
  const [explain, setExplain] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<ThreatVerdict | null>(null);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError("");
    setResult(null);
    const body: Record<string, unknown> = { content_type: contentType };
    if (url.trim()) body.url = url.trim();
    if (content.trim()) body.content = content.trim();
    if (sender.trim()) body.sender = sender.trim();
    if (subject.trim()) body.subject = subject.trim();
    if (explain) {
      // The checkbox label states exactly what is sent; ticking it is the consent.
      body.explain = true;
      body.cloud_ai_consent = true;
    }
    try {
      const response = await fetch("/api/analyses", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await response.json();
      if (!response.ok) {
        const detail = Array.isArray(data?.detail)
          ? data.detail.map((d: { msg: string }) => d.msg).join("; ")
          : data?.detail;
        throw new Error(detail || `Analysis failed (${response.status})`);
      }
      setResult(data as ThreatVerdict);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Analysis failed.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="split">
      <form className="panel form" onSubmit={onSubmit}>
        <label htmlFor="url">URL</label>
        <input id="url" value={url} onChange={(e) => setUrl(e.target.value)} maxLength={2048}
          placeholder="https://example.com/login" autoComplete="off" />

        <div className="row">
          <div>
            <label htmlFor="type">Source</label>
            <select id="type" value={contentType}
              onChange={(e) => setContentType(e.target.value as (typeof CONTENT_TYPES)[number])}>
              {CONTENT_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </div>
          <div>
            <label htmlFor="sender">Sender</label>
            <input id="sender" value={sender} onChange={(e) => setSender(e.target.value)} maxLength={320}
              placeholder="Name <address@example.com>" autoComplete="off" />
          </div>
        </div>

        <label htmlFor="subject">Subject</label>
        <input id="subject" value={subject} onChange={(e) => setSubject(e.target.value)} maxLength={998}
          autoComplete="off" />

        <div className="label-row">
          <label htmlFor="content">Message content</label>
          <span className="muted small">{content.length.toLocaleString()} / 20,000</span>
        </div>
        <textarea id="content" rows={10} value={content} onChange={(e) => setContent(e.target.value)}
          maxLength={20000} placeholder="Paste only the message you want Teger to analyze." />

        <label className={`check ${aiPossible ? "" : "disabled"}`}>
          <input type="checkbox" checked={explain} disabled={!aiPossible}
            onChange={(e) => setExplain(e.target.checked)} />
          <span>
            Explain with Teger Intelligence. I consent to sending a <b>redacted</b> copy of this content to Anthropic
            Claude{byokHint ? <> using <b>my own key</b> (<code>{byokHint}</code>)</> : " using Teger's key"}.
            {!aiPossible && <> Add your own Anthropic key in <a href="/settings">Settings</a> to enable this.</>}
          </span>
        </label>

        <button className="primary" type="submit" disabled={loading || (!url.trim() && !content.trim())}>
          {loading ? "Analyzing…" : "Analyze"}
        </button>
        {error && <p className="notice notice-danger" role="alert">{error}</p>}
      </form>

      <section className="panel" aria-live="polite">
        {result ? <VerdictView result={result} /> : (
          <p className="muted">Results appear here. Unknown results mean Teger could not fully check something —
            they are never shown as safe.</p>
        )}
      </section>
    </div>
  );
}
