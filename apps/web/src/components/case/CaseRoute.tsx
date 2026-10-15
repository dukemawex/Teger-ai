"use client";

import { ROUTE_STAGES, type InvestigationCase, type StageKey, type ToolRun } from "@/lib/cases";

type StageState = "pending" | "running" | "done" | "risk" | "ok" | "failed";

export function stageState(c: InvestigationCase, key: StageKey): StageState {
  const stage = ROUTE_STAGES.find((s) => s.key === key)!;
  const runs: ToolRun[] = c.tools.filter((t) => (stage.tools as readonly string[]).includes(t.tool));
  if (key === "decision") {
    if (!c.assessment) return c.status === "running" || c.status === "queued" ? "pending" : "failed";
    return c.assessment.verdict === "no_threat_detected" ? "ok" : c.assessment.verdict === "inconclusive" ? "failed" : "risk";
  }
  if (!runs.length) return "pending";
  if (runs.some((r) => r.state === "running")) return "running";
  const ids = new Set(runs.flatMap((r) => r.evidence_ids));
  const ev = c.evidence.filter((e) => ids.has(e.id));
  if (runs.every((r) => r.state === "failed" || r.state === "unavailable")) return "failed";
  if (ev.some((e) => e.stance === "risk" && (e.severity === "high" || e.severity === "medium"))) return "risk";
  if (ev.some((e) => e.stance === "legitimacy")) return "ok";
  return "done";
}

const STATE_SHORT: Record<StageState, string> = {
  pending: "pending", running: "in progress", done: "checked", risk: "risk found", ok: "consistent", failed: "incomplete",
};

const STATE_TEXT: Record<StageState, string> = {
  pending: "not yet checked", running: "in progress", done: "checked", risk: "risk found",
  ok: "consistent with context", failed: "could not be completed",
};

/**
 * The evidence route: Message → Destination → Identity check → Decision. Legs are drawn
 * when the stage they lead to has completed; the drawing animates once (respecting
 * reduced-motion), so motion marks a change in evidence, not decoration.
 */
export function CaseRoute({ data, selected, onSelect }: {
  data: InvestigationCase;
  selected: StageKey | null;
  onSelect: (key: StageKey | null) => void;
}) {
  const xs = [66, 202, 338, 474];
  const ys = [92, 40, 96, 44];
  return (
    <div className="case-route">
      <svg viewBox="0 0 540 140" role="group" aria-label="Evidence route">
        {ROUTE_STAGES.slice(1).map((stage, i) => {
          const done = !["pending", "running"].includes(stageState(data, stage.key));
          const [x1, y1, x2, y2] = [xs[i], ys[i], xs[i + 1], ys[i + 1]];
          const d = `M${x1 + 30} ${y1 + (y2 > y1 ? 26 : -26)} C ${x1 + 60} ${y1 + (y2 > y1 ? 40 : -40)}, ${x2 - 60} ${y2 + (y2 > y1 ? -40 : 40)}, ${x2 - 30} ${y2 + (y2 > y1 ? -26 : 26)}`;
          return <path key={stage.key} className={`leg${done ? " done draw" : ""}`} d={d} />;
        })}
        {ROUTE_STAGES.map((stage, i) => {
          const state = stageState(data, stage.key);
          const active = selected === stage.key;
          const count = data.evidence.filter((e) =>
            data.tools.some((t) => (stage.tools as readonly string[]).includes(t.tool) && t.evidence_ids.includes(e.id)),
          ).length;
          return (
            <g key={stage.key} className={`stage${active ? " active" : ""}`} tabIndex={0} role="button"
              aria-pressed={active} aria-label={`${stage.label}: ${STATE_TEXT[state]}. ${count} evidence item(s).`}
              onClick={() => onSelect(active ? null : stage.key)}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onSelect(active ? null : stage.key); }
              }}>
              <rect x={xs[i] - 62} y={ys[i] - 25} width="124" height="50" rx="2" />
              <circle className={`marker ${state === "pending" ? "" : state === "running" ? "" : state}`}
                cx={xs[i] - 46} cy={ys[i]} r="6" />
              {state === "running" && (
                <circle cx={xs[i] - 46} cy={ys[i]} r="9" fill="none" stroke="#3f4a5a" strokeWidth="1.5"
                  strokeDasharray="3 3" />
              )}
              <text x={xs[i] - 34} y={ys[i] - 3}>{stage.label}</text>
              <text className="s" x={xs[i] - 34} y={ys[i] + 13}>{STATE_SHORT[state]}</text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
