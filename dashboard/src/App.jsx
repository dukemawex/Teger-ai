import { useMemo, useState } from "react";
import "./App.css";

const API_BASE = (process.env.REACT_APP_API_URL || "http://localhost:8000").replace(/\/$/, "");
const TOKEN_KEY = "teger-installation-token";
const HISTORY_KEY = "teger-scan-history";

function loadHistory() {
  try {
    const parsed = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

async function getInstallationToken(forceRefresh = false) {
  if (!forceRefresh) {
    const existing = localStorage.getItem(TOKEN_KEY);
    if (existing) return existing;
  }

  const response = await fetch(`${API_BASE}/installations`, { method: "POST" });
  if (!response.ok) {
    throw new Error("Could not create a secure Teger session.");
  }

  const data = await response.json();
  if (!data?.token) {
    throw new Error("Teger returned an invalid installation session.");
  }

  localStorage.setItem(TOKEN_KEY, data.token);
  return data.token;
}

async function analyzeWithAuth(payload, retry = true) {
  const token = await getInstallationToken();
  const response = await fetch(`${API_BASE}/analyze`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(payload),
  });

  if (response.status === 401 && retry) {
    localStorage.removeItem(TOKEN_KEY);
    await getInstallationToken(true);
    return analyzeWithAuth(payload, false);
  }

  if (!response.ok) {
    let message = `Analysis failed (${response.status})`;
    try {
      const body = await response.json();
      message = body?.detail || message;
    } catch {
      // Use the generic message when the API does not return JSON.
    }
    throw new Error(message);
  }

  return response.json();
}

function titleCase(value) {
  return String(value || "")
    .replaceAll("_", " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

export default function App() {
  const [content, setContent] = useState("");
  const [context, setContext] = useState("Email");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [history, setHistory] = useState(loadHistory);

  const metrics = useMemo(() => {
    const highRisk = history.filter((item) =>
      ["high", "critical"].includes(item.threatLevel)
    ).length;
    const feedback = history.filter((item) => item.feedback);
    const accurate = feedback.filter((item) => item.feedback === "accurate").length;
    const agreement = feedback.length ? Math.round((accurate / feedback.length) * 100) : null;

    return {
      scans: history.length,
      highRisk,
      agreement,
    };
  }, [history]);

  const saveHistory = (analysis) => {
    const entry = {
      id: crypto.randomUUID(),
      createdAt: new Date().toISOString(),
      context: context.trim() || "Unknown",
      threatLevel: analysis.threat_level,
      confidence: analysis.confidence,
      tactics: analysis.tactics || [],
      feedback: null,
    };
    const next = [entry, ...history].slice(0, 50);
    setHistory(next);
    localStorage.setItem(HISTORY_KEY, JSON.stringify(next));
  };

  const updateFeedback = (id, feedback) => {
    const next = history.map((item) =>
      item.id === id ? { ...item, feedback } : item
    );
    setHistory(next);
    localStorage.setItem(HISTORY_KEY, JSON.stringify(next));
  };

  const onAnalyze = async () => {
    if (!content.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);

    try {
      const data = await analyzeWithAuth({
        content: content.trim(),
        context: context.trim(),
      });
      setResult(data);
      saveHistory(data);
    } catch (err) {
      setError(err.message || "Failed to analyze message.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="shell">
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark">T</span>
          <div>
            <span className="eyebrow">TEGER AI</span>
            <strong>Security Console</strong>
          </div>
        </div>
        <div className="beta-pill"><span /> MVP v0.2 · Private Beta</div>
      </header>

      <section className="hero">
        <div>
          <span className="eyebrow">HUMAN-LAYER THREAT INTELLIGENCE</span>
          <h1>Explain the attack, not just the alert.</h1>
          <p>
            Analyze suspicious communication for social-engineering tactics,
            concrete linguistic cues, and a safe next action.
          </p>
        </div>
        <div className="security-note">
          <span className="pulse" />
          <div>
            <strong>Privacy-first MVP</strong>
            <small>Raw message text is not added to browser scan history.</small>
          </div>
        </div>
      </section>

      <section className="metrics">
        <article>
          <span>Total scans</span>
          <strong>{metrics.scans}</strong>
          <small>stored in this browser</small>
        </article>
        <article>
          <span>High-risk detections</span>
          <strong>{metrics.highRisk}</strong>
          <small>high + critical</small>
        </article>
        <article>
          <span>User agreement</span>
          <strong>{metrics.agreement === null ? "—" : `${metrics.agreement}%`}</strong>
          <small>from local feedback</small>
        </article>
      </section>

      <section className="workspace">
        <article className="panel analyze-panel">
          <div className="panel-head">
            <div>
              <span className="eyebrow">MANUAL ANALYSIS</span>
              <h2>Inspect a suspicious message</h2>
            </div>
            <span className="secure-chip">Authenticated API</span>
          </div>

          <label htmlFor="context">Context</label>
          <input
            id="context"
            value={context}
            onChange={(event) => setContext(event.target.value)}
            placeholder="Gmail | Sender: finance@example.com"
            maxLength={1000}
          />

          <div className="label-row">
            <label htmlFor="content">Message content</label>
            <span>{content.length.toLocaleString()} / 20,000</span>
          </div>
          <textarea
            id="content"
            rows={12}
            maxLength={20000}
            value={content}
            onChange={(event) => setContent(event.target.value)}
            placeholder="Paste only the message you want Teger to analyze..."
          />

          <button
            className="primary-button"
            onClick={onAnalyze}
            disabled={loading || !content.trim()}
          >
            {loading ? "Analyzing threat signals…" : "Analyze message"}
          </button>

          {error && <div className="error-box">{error}</div>}
        </article>

        <article className="panel result-panel">
          <div className="panel-head">
            <div>
              <span className="eyebrow">EXPLAINABLE DETECTION</span>
              <h2>Threat assessment</h2>
            </div>
          </div>

          {!result ? (
            <div className="empty-state">
              <div className="radar" />
              <strong>No active analysis</strong>
              <p>Teger will show risk, tactics, evidence, and recommended action here.</p>
            </div>
          ) : (
            <div className="analysis-result">
              <div className="risk-row">
                <div>
                  <span>Threat level</span>
                  <strong className={`risk-${result.threat_level}`}>
                    {titleCase(result.threat_level)}
                  </strong>
                </div>
                <div>
                  <span>Confidence</span>
                  <strong>{result.confidence}%</strong>
                </div>
              </div>

              <div className="result-section">
                <span className="eyebrow">DETECTED TACTICS</span>
                <div className="chips">
                  {(result.tactics || []).length ? (
                    result.tactics.map((tactic) => (
                      <span key={tactic}>{titleCase(tactic)}</span>
                    ))
                  ) : (
                    <p>No known tactic detected.</p>
                  )}
                </div>
              </div>

              <div className="result-section">
                <span className="eyebrow">SUSPICIOUS CUES</span>
                <ul>
                  {(result.cues || []).map((cue, index) => (
                    <li key={`${cue}-${index}`}>{cue}</li>
                  ))}
                </ul>
              </div>

              <div className="result-section">
                <span className="eyebrow">WHY TEGER FLAGGED IT</span>
                <p>{result.reasoning}</p>
              </div>

              <div className="recommendation">
                <span className="eyebrow">RECOMMENDED ACTION</span>
                <p>{result.recommended_action}</p>
              </div>
            </div>
          )}
        </article>
      </section>

      <section className="panel history-panel">
        <div className="panel-head">
          <div>
            <span className="eyebrow">LOCAL HISTORY</span>
            <h2>Recent scans</h2>
          </div>
          <small>Metadata only · latest 50 scans</small>
        </div>

        {history.length === 0 ? (
          <p className="muted">Your recent assessments will appear here.</p>
        ) : (
          <div className="history-list">
            {history.slice(0, 8).map((item) => (
              <div className="history-item" key={item.id}>
                <div>
                  <strong>{titleCase(item.threatLevel)}</strong>
                  <span>{item.context}</span>
                  <small>{new Date(item.createdAt).toLocaleString()}</small>
                </div>
                <div className="history-right">
                  <strong>{item.confidence}%</strong>
                  <div className="feedback">
                    <button
                      className={item.feedback === "accurate" ? "selected" : ""}
                      onClick={() => updateFeedback(item.id, "accurate")}
                    >
                      Accurate
                    </button>
                    <button
                      className={item.feedback === "false_positive" ? "selected" : ""}
                      onClick={() => updateFeedback(item.id, "false_positive")}
                    >
                      False positive
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </main>
  );
}
