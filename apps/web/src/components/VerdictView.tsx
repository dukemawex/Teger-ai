import { humanize, VERDICT_LABEL } from "@/lib/labels";
import type { ThreatVerdict } from "@/lib/types";

export function VerdictView({ result }: { result: ThreatVerdict }) {
  const ai = result.explanation;
  return (
    <div className="verdict">
      <div className={`verdict-head verdict-${result.verdict}`}>
        <div>
          <span className="eyebrow">Verdict</span>
          <strong>{VERDICT_LABEL[result.verdict]}</strong>
        </div>
        <div className="verdict-metrics">
          <span>Risk score <b>{result.risk_score}</b>/100</span>
          <span title="Rule agreement score, not a calibrated probability">
            Rule confidence <b>{Math.round(result.confidence * 100)}%</b>
          </span>
        </div>
      </div>

      {result.mock_intelligence_used && (
        <p className="notice notice-warning">
          This result used <b>mock</b> reputation data from a test fixture. It is not live threat intelligence.
        </p>
      )}
      {result.intelligence_coverage === "partial" && (
        <p className="notice">Some required intelligence was unavailable, so Teger could not fully check this.</p>
      )}

      <section>
        <h3>Recommended action: {humanize(result.recommended_action)}</h3>
        <p>{result.recommended_action_text}</p>
      </section>

      <section>
        <h3>Evidence ({result.evidence.length})</h3>
        {result.evidence.length === 0 ? (
          <p className="muted">No indicators were found.</p>
        ) : (
          <ul className="evidence">
            {result.evidence.map((e) => (
              <li key={e.id}>
                <div className="evidence-top">
                  <span className={`sev sev-${e.severity}`}>{e.severity}</span>
                  <code>{e.id}</code>
                  <span>{humanize(e.category)}</span>
                  {e.tactic && <span className="chip">{humanize(e.tactic)}</span>}
                </div>
                <p>{e.description}</p>
                {e.indicator && <p className="indicator">“{e.indicator}”</p>}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section>
        <h3>AI explanation</h3>
        {ai.status === "completed" ? (
          <div className="ai">
            <p className="muted small">
              Explanation only — written by {ai.usage?.model ?? "the AI provider"} from the evidence above. It cannot
              change the verdict.
            </p>
            <p>{ai.summary}</p>
            <ul>
              {ai.key_points.map((p, i) => (
                <li key={i}>
                  {p.explanation} <span className="muted">({p.evidence_ids.join(", ")})</span>
                </li>
              ))}
            </ul>
            {ai.user_guidance && <p><b>What to do:</b> {ai.user_guidance}</p>}
            {ai.injection_attempt_observed && (
              <p className="notice notice-warning">The content tried to give instructions to an AI assistant.</p>
            )}
          </div>
        ) : (
          <p className="muted">
            {humanize(ai.status)}
            {ai.detail ? ` — ${ai.detail}` : ""}
          </p>
        )}
      </section>

      <details>
        <summary>Detection sources · policy {result.policy_version}</summary>
        <table>
          <thead>
            <tr><th>Detector</th><th>Status</th><th>Mode</th><th>Required</th></tr>
          </thead>
          <tbody>
            {result.detection_sources.map((s) => (
              <tr key={s.name}>
                <td>{s.name} <span className="muted">v{s.version}</span></td>
                <td>{s.status}{s.detail ? ` — ${s.detail}` : ""}</td>
                <td>{s.provider_mode}</td>
                <td>{s.required ? "yes" : "no"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </div>
  );
}
