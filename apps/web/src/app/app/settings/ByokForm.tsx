"use client";

import { useState } from "react";

export function ByokForm({ initialHint, byokAllowed }: { initialHint: string | null; byokAllowed: boolean }) {
  const [hint, setHint] = useState(initialHint);
  const [key, setKey] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  async function save(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setMessage("");
    const response = await fetch("/api/byok", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ anthropicKey: key }),
    });
    const body = await response.json().catch(() => ({}));
    setBusy(false);
    if (!response.ok) {
      setMessage(body?.detail || "Could not save the key.");
      return;
    }
    setKey("");
    setHint(body.hint);
    setMessage("Saved for this browser session.");
  }

  async function remove() {
    setBusy(true);
    await fetch("/api/byok", { method: "DELETE" });
    setBusy(false);
    setHint(null);
    setMessage("Removed.");
  }

  if (!byokAllowed) {
    return <p className="muted">Bring-your-own-key is disabled on this server.</p>;
  }

  return (
    <div className="form">
      <p className="muted small">
        Use your own Anthropic API key for Teger Intelligence explanations. Usage is billed to your Anthropic account.
        The key is kept only in an encrypted, HttpOnly cookie in this browser for 8 hours, sent to the Teger API with
        an analysis only when you ask for an explanation, and never stored or logged by Teger.
      </p>
      {hint ? (
        <p>Current key: <code>{hint}</code></p>
      ) : (
        <p className="muted">No key saved.</p>
      )}
      <form className="form" onSubmit={save}>
        <label htmlFor="anthropic-key">Anthropic API key</label>
        <input id="anthropic-key" type="password" value={key} onChange={(e) => setKey(e.target.value)}
          placeholder="sk-ant-…" autoComplete="off" spellCheck={false} />
        <div className="button-row">
          <button className="primary" type="submit" disabled={busy || !key}>Save key</button>
          {hint && <button className="secondary" type="button" disabled={busy} onClick={remove}>Remove key</button>}
        </div>
      </form>
      {message && <p className="notice" role="status">{message}</p>}
    </div>
  );
}
