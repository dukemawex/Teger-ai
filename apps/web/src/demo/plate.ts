import recorded from "./recorded.json";
import type { InvestigationCase } from "@/lib/cases";
import type { PlateCase, PlateEvidence, PlateNode } from "@/components/public/AtlasPlate";

const LABELS: Record<string, string> = {
  "supplier-impersonation": "Impersonation",
  "approved-service": "Approved service",
  inconclusive: "Inconclusive",
  "prompt-injection": "Injection attempt",
};
const NUMERALS = ["I", "II", "III", "IV"];

export const RECORDED_CASES = recorded.cases as unknown as Record<string, InvestigationCase>;

function evidenceFor(c: InvestigationCase, tools: string[]): PlateEvidence[] {
  const ids = new Set(c.tools.filter((t) => tools.includes(t.tool)).flatMap((t) => t.evidence_ids));
  const items = c.evidence.filter((e) => ids.has(e.id));
  // Lead with what changed the picture: risk and legitimacy before neutral observations.
  const rank = (s: string) => (s === "neutral" ? 1 : 0);
  return [...items].sort((a, b) => rank(a.stance) - rank(b.stance))
    .map((e) => ({ id: e.id, summary: e.summary, method: e.method, stance: e.stance, source: e.source }));
}

function tone(ev: PlateEvidence[], failed: boolean): PlateNode["tone"] {
  if (failed) return "unknown";
  if (ev.some((e) => e.stance === "risk")) return "risk";
  if (ev.some((e) => e.stance === "legitimacy")) return "ok";
  return "neutral";
}

export function plateCases(): PlateCase[] {
  return Object.entries(RECORDED_CASES).map(([id, c], i) => {
    const a = c.assessment!;
    const message = evidenceFor(c, ["extract_message", "static_analysis"]);
    const destination = evidenceFor(c, ["resolve_redirects", "inspect_page", "check_reputation"]);
    const identity = evidenceFor(c, ["compare_context"]);
    const destFailed = c.tools.some((t) => t.tool === "resolve_redirects" && t.state !== "completed");
    const verdictTone: PlateNode["tone"] = a.verdict === "no_threat_detected" ? "ok"
      : a.verdict === "inconclusive" ? "unknown" : "risk";
    return {
      id,
      label: LABELS[id] ?? id,
      numeral: NUMERALS[i] ?? String(i + 1),
      verdict: a.verdict,
      headline: a.headline,
      nextAction: a.recommended_next_action,
      actions: c.actions.map((x) => x.title),
      nodes: [
        { key: "message", label: "Message", sub: `${message.length} observations`, tone: tone(message, false), evidence: message },
        { key: "destination", label: "Destination", sub: destFailed ? "not inspectable" : "traced & read",
          tone: tone(destination, destFailed), evidence: destination,
          note: destFailed ? "Teger did not guess what the page contains." : undefined },
        { key: "identity", label: "Identity check", sub: "approved context", tone: tone(identity, false), evidence: identity },
        { key: "decision", label: "Decision", sub: a.verdict.replace(/_/g, " "), tone: verdictTone, evidence: [] },
      ],
    };
  });
}
