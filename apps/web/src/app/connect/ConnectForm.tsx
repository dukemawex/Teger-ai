"use client";

import { useState } from "react";

export function ConnectForm() {
  const [apiKey, setApiKey] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError("");
    try {
      const response = await fetch("/api/session", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ apiKey }),
      });
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body?.detail || "Could not connect.");
      }
      window.location.href = "/";
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not connect.");
      setLoading(false);
    }
  }

  return (
    <form className="form" onSubmit={onSubmit}>
      <label htmlFor="key">API key</label>
      <input id="key" type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)}
        autoComplete="off" spellCheck={false} required />
      <button className="primary" type="submit" disabled={loading || !apiKey}>
        {loading ? "Checking…" : "Connect"}
      </button>
      {error && <p className="notice notice-danger" role="alert">{error}</p>}
    </form>
  );
}
