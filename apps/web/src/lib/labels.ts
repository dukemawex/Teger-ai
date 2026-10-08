import type { ModuleStatus, Verdict } from "./types";

export const STATUS_LABEL: Record<ModuleStatus, string> = {
  operational: "Operational",
  experimental: "Experimental",
  planned: "Planned",
  unavailable: "Unavailable",
};

export const VERDICT_LABEL: Record<Verdict, string> = {
  malicious: "Malicious",
  suspicious: "Suspicious",
  no_threat_detected: "No threat detected",
  unknown: "Unknown — not fully checked",
};

export function statusLabel(status: string): string {
  return STATUS_LABEL[status as ModuleStatus] ?? "Unavailable";
}

export function humanize(value: string): string {
  return value.replaceAll("_", " ").replace(/^\w/, (c) => c.toUpperCase());
}
