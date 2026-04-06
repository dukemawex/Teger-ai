import { useState } from "react";

const API_BASE = process.env.REACT_APP_API_URL || "http://localhost:8000";

export default function App() {
  const [content, setContent] = useState("");
  const [context, setContext] = useState("Email");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const onAnalyze = async () => {
    if (!content.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);

    try {
      const res = await fetch(`${API_BASE}/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content, context }),
      });

      if (!res.ok) {
        throw new Error(`Backend request failed (${res.status})`);
      }

      const data = await res.json();
      setResult(data);
    } catch (err) {
      setError(err.message || "Failed to analyze message");
    } finally {
      setLoading(false);
    }
  };

  return (
    <main style={{ maxWidth: 860, margin: "0 auto", padding: 24, fontFamily: "Arial, sans-serif" }}>
      <h1>Teger AI Dashboard</h1>
      <p>Analyze suspicious messages with the OpenAI-backed Teger AI backend.</p>

      <label htmlFor="context">Platform context</label>
      <input
        id="context"
        value={context}
        onChange={(e) => setContext(e.target.value)}
        style={{ display: "block", width: "100%", margin: "8px 0 16px", padding: 8 }}
      />

      <label htmlFor="content">Message content</label>
      <textarea
        id="content"
        rows={10}
        value={content}
        onChange={(e) => setContent(e.target.value)}
        style={{ display: "block", width: "100%", margin: "8px 0 16px", padding: 8 }}
      />

      <button onClick={onAnalyze} disabled={loading || !content.trim()}>
        {loading ? "Analyzing..." : "Analyze"}
      </button>

      {error && <p style={{ color: "crimson" }}>{error}</p>}

      {result && (
        <section style={{ marginTop: 16 }}>
          <h2>Result</h2>
          <pre style={{ background: "#f4f4f4", padding: 12, overflowX: "auto" }}>
            {JSON.stringify(result, null, 2)}
          </pre>
        </section>
      )}
    </main>
  );
}
