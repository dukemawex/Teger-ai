"use client";

import { useState } from "react";
import type { ThreatVerdict } from "@/lib/types";

const TITLES = { malicious: "Strong attack indicators", suspicious: "Reasons to be cautious",
  unknown: "More verification needed", no_threat_detected: "No indicators detected" };
const SOURCES: Record<string, string> = { url_heuristics: "URL structure", brand_impersonation: "Brand & sender identity",
  credential_harvesting: "Credential requests", social_engineering: "Manipulation tactics", url_reputation: "Live URL reputation" };
const humanize = (value: string) => SOURCES[value] ?? value.replaceAll("_", " ");
const NOTE = "Hi, I received a request that appears to come from you. Before I take any action, could you confirm whether you sent it and verify the requested details? I am contacting you through our established channel.";

export function InvestigationResult({ result, sample }: { result: ThreatVerdict; sample: string }) {
  const [copyState, setCopyState] = useState("");
  const completed = result.detection_sources.filter(d => d.status === "ok").length;
  function download() {
    const text = ["TEGER AI — INVESTIGATION REPORT", `Reference: ${result.analysis_id}`, `Date: ${result.created_at}`,
      ...(sample ? [`Input: fictional example (${sample})`] : []), `Finding: ${TITLES[result.verdict]}`,
      `Rule risk score: ${result.risk_score}/100 (not a probability)`, `Policy: ${result.policy_version}`,
      `Coverage: ${result.intelligence_coverage}`, ...(result.url ? [`Host: ${result.url.host}`] : []), "",
      "RECOMMENDED ACTION", result.recommended_action_text, "", "EVIDENCE",
      ...result.evidence.map(e => `- ${e.description}${e.indicator ? `\n  Indicator: ${e.indicator}` : ""}`), "", "CHECKS",
      ...result.detection_sources.map(d => `- ${humanize(d.name)}: ${d.status}`), "", "LIMITS",
      "Local rules only. No website was visited. No live reputation or cloud AI was used.",
      "A low score or absence of indicators is not a guarantee of safety. Excerpts are redacted on a best-effort basis.",
    ].join("\n");
    const url = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }));
    const a = document.createElement("a"); a.href = url; a.download = `teger-${result.analysis_id}.txt`;
    document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  async function copyNote() {
    try { await navigator.clipboard.writeText(NOTE); setCopyState("Verification note copied. Send it through a contact channel you already trust."); }
    catch { setCopyState("Copy is unavailable in this browser. Select and copy the note below."); }
  }
  return <div className="investigation-result">
    {sample && <p className="example-disclosure">Fictional example · evaluated by the real detection engine</p>}
    <div className={`result-summary result-${result.verdict}`}>
      <span className="result-label">INVESTIGATION FINDING</span><h2>{TITLES[result.verdict]}</h2>
      <div className="risk-row"><span>Rule risk score <strong>{result.risk_score}<small>/100</small></strong></span>
        <span>{completed} checks completed<br /><small>Score is not a probability.</small></span></div>
      <meter min={0} max={100} value={result.risk_score} aria-label="Rule risk score" />
    </div>
    <div className="next-action"><span className="public-kicker">YOUR NEXT MOVE</span><p>{result.recommended_action_text}</p></div>
    {result.url && <p className="examined-host">Examined host <code>{result.url.host}</code></p>}
    <div className="findings-heading"><h3>What raised a flag</h3><span>{result.evidence.length} findings</span></div>
    {result.evidence.length ? <ol className="finding-list">{result.evidence.map((e, i) =>
      <li key={e.id}><span className="finding-number">{String(i + 1).padStart(2, "0")}</span><div>
        <div className="finding-title"><h4>{humanize(e.category)}</h4><span className={`finding-severity severity-${e.severity}`}>{e.severity}</span></div>
        <p>{e.description}</p>{e.indicator && <blockquote>{e.indicator}</blockquote>}
      </div></li>)}</ol> : <p className="no-findings">The configured rules did not find warning signs in this submission. They cannot establish that the message or destination is safe.</p>}
    <div className="coverage-note"><strong>{result.intelligence_coverage === "partial" ? "Some checks are unavailable" : "Configured checks completed"}</strong>
      <p>Website contents, live reputation, and sender ownership have not been verified. Results reflect the submitted content and local rules.</p></div>
    <details className="check-details"><summary>Inspect detection sources</summary><ul>{result.detection_sources.map(d =>
      <li key={d.name}><span>{humanize(d.name)}</span><span>{d.status === "ok" ? "Completed" : humanize(d.status)}</span></li>)}</ul>
      <p>Policy {result.policy_version} · Reference {result.analysis_id}</p></details>
    <div className="result-actions"><button className="public-button secondary-public" onClick={download}>Download report <span aria-hidden="true">↓</span></button>
      <button className="quiet-button" onClick={copyNote}>Copy verification note</button></div>
    {copyState && <div className="verification-note"><p role="status">{copyState}</p><blockquote>{NOTE}</blockquote></div>}
  </div>;
}
