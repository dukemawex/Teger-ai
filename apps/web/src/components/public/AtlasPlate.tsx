"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { VerdictSeal } from "@/components/VerdictSeal";
import type { CaseVerdict } from "@/lib/cases";

export interface PlateEvidence {
  id: string;
  summary: string;
  method: string;
  stance: string;
  source: string;
}

export interface PlateNode {
  key: string;
  label: string;
  sub: string;
  tone: "risk" | "ok" | "unknown" | "neutral";
  evidence: PlateEvidence[];
  note?: string;
}

export interface PlateCase {
  id: string;
  label: string;
  numeral: string;
  verdict: CaseVerdict;
  headline: string;
  nextAction: string;
  actions: string[];
  nodes: PlateNode[];
}

const POS = [
  { x: 64, y: 196 },
  { x: 214, y: 112 },
  { x: 372, y: 170 },
  { x: 506, y: 82 },
];

const METHOD = { observed: "Observed", derived: "Derived by rule", model_inference: "Model inference" } as Record<string, string>;

/**
 * Campaign-atlas plate. The chart underneath is decorative engraving (not telemetry);
 * the route and every evidence line come from a recorded run of the real investigator on
 * synthetic fixtures (src/demo/recorded.json, checked by a test against the engine).
 */
export function AtlasPlate({ cases }: { cases: PlateCase[] }) {
  const [caseIndex, setCaseIndex] = useState(0);
  const [nodeIndex, setNodeIndex] = useState(2);
  const [drawn, setDrawn] = useState(false);
  const current = cases[caseIndex];
  const node = current.nodes[nodeIndex];

  useEffect(() => {
    setDrawn(false);
    const t = setTimeout(() => setDrawn(true), 30);
    return () => clearTimeout(t);
  }, [caseIndex]);

  const route = `M${POS[0].x} ${POS[0].y} C 120 160, 150 110, ${POS[1].x} ${POS[1].y} S 320 190, ${POS[2].x} ${POS[2].y} S 470 70, ${POS[3].x} ${POS[3].y}`;

  return (
    <figure className="plate" aria-labelledby="plate-title">
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img className="coin" src="/assets/tetradrachm-320.webp" width={112} height={112}
        alt="Silver tetradrachm of Alexander the Great, c. 325–319 BCE (The Met, public domain)" />
      <div className="plate-head">
        <span className="plate-tag">Plate {current.numeral} · synthetic case · recorded run</span>
      </div>
      <h2 id="plate-title" className="plate-title">Evidence route — {current.label}</h2>
      <div className="plate-cases" role="group" aria-label="Choose a demonstration case">
        {cases.map((c, i) => (
          <button key={c.id} type="button" aria-pressed={i === caseIndex}
            onClick={() => { setCaseIndex(i); setNodeIndex(2); }}>{c.numeral}. {c.label}</button>
        ))}
      </div>
      <div className="plate-map">
        <svg viewBox="0 0 570 250" role="group" aria-label={`Evidence route for ${current.label}`}>
          <defs>
            <pattern id="hatch" width="7" height="7" patternUnits="userSpaceOnUse" patternTransform="rotate(28)">
              <line x1="0" y1="0" x2="0" y2="7" stroke="#cbbf9f" strokeWidth="0.8" />
            </pattern>
          </defs>
          {/* decorative engraved chart: graticule, coast and sea hatching — not geographic data */}
          <g aria-hidden="true" opacity="0.9">
            {[60, 140, 220, 300, 380, 460, 540].map((x) => <line key={x} x1={x} y1="0" x2={x - 18} y2="250" stroke="#ddd2b8" strokeWidth="0.7" />)}
            {[50, 125, 200].map((y) => <line key={y} x1="0" y1={y} x2="570" y2={y + 8} stroke="#ddd2b8" strokeWidth="0.7" />)}
            <path d="M0 236 C40 214 70 230 104 206 C138 182 120 150 160 146 C196 142 206 168 238 160 C268 152 262 122 298 118 C332 114 344 140 380 134 C410 129 420 104 452 100 C486 96 500 118 536 108 C552 104 562 96 570 92 L570 250 L0 250Z"
              fill="url(#hatch)" />
            <path d="M0 236 C40 214 70 230 104 206 C138 182 120 150 160 146 C196 142 206 168 238 160 C268 152 262 122 298 118 C332 114 344 140 380 134 C410 129 420 104 452 100 C486 96 500 118 536 108 C552 104 562 96 570 92"
              fill="none" stroke="#a99673" strokeWidth="1.1" />
            <path d="M18 70 C60 44 104 62 132 40 C152 24 190 30 206 14" fill="none" stroke="#a99673" strokeWidth="1" />
            <path d="M400 236 C420 222 446 226 462 212 C480 196 506 206 520 196" fill="none" stroke="#b9a983" strokeWidth="0.9" strokeDasharray="1 3" />
            <g transform="translate(520 196)">
              <circle r="20" fill="none" stroke="#a99673" strokeWidth="0.8" />
              <path d="M0 -26 L4 -4 L0 0 L-4 -4Z M0 26 L4 4 L0 0 L-4 4Z M-26 0 L-4 -4 L0 0 L-4 4Z M26 0 L4 -4 L0 0 L4 4Z" fill="#a99673" />
            </g>
          </g>
          <path className="route-path" d={route} />
          <path className={`route-progress${drawn ? " drawn" : ""}`} d={route} pathLength={1} />
          {current.nodes.map((n, i) => (
            <g key={n.key} className={`route-node ${n.tone}${i === nodeIndex ? " active" : ""}`}
              transform={`translate(${POS[i].x} ${POS[i].y})`} tabIndex={0} role="button"
              aria-pressed={i === nodeIndex} aria-label={`${n.label}: ${n.sub}. Show evidence.`}
              onClick={() => setNodeIndex(i)}
              onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setNodeIndex(i); } }}>
              <circle className="ring" r={i === nodeIndex ? 15 : 12} />
              <circle className="core" r="5.5" />
              <text x={i === 3 ? -12 : 18} y={i === 3 ? -24 : -8} textAnchor={i === 3 ? "end" : "start"}>{n.label}</text>
              <text className="sub" x={i === 3 ? -12 : 18} y={i === 3 ? -10 : 8} textAnchor={i === 3 ? "end" : "start"}>{n.sub}</text>
            </g>
          ))}
        </svg>
        <span className="map-caption" aria-hidden="true">decorative chart · not telemetry</span>
      </div>
      <div className="plate-evidence" aria-live="polite">
        <h3>{node.label}</h3>
        {node.key === "decision" ? (
          <>
            <VerdictSeal verdict={current.verdict} />
            <p className="mt small"><strong>{current.headline}.</strong> {current.nextAction}</p>
            {current.actions.length > 0 && (
              <p className="small muted">Proposed for approval: {current.actions.join(" · ")}</p>
            )}
          </>
        ) : (
          <ul className="plate-list">
            {node.evidence.slice(0, 3).map((e) => (
              <li key={e.id}><span className="evid">{e.id}</span> {e.summary}
                <span className="tiny muted"> — {METHOD[e.method] ?? e.method}; {e.source}</span></li>
            ))}
            {node.evidence.length > 3 && <li className="tiny muted">+ {node.evidence.length - 3} more in the full case</li>}
            {node.note && <li className="muted small">{node.note}</li>}
          </ul>
        )}
      </div>
      <figcaption className="plate-foot">
        <span className="tiny muted">Demo — synthetic evidence from a recorded run. Fictional organizations; reserved domains.</span>
        <Link className="btn btn-primary btn-small" href={`/demo?case=${current.id}`}>Run this case</Link>
      </figcaption>
    </figure>
  );
}
