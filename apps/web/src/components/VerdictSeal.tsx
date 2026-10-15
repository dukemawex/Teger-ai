import { VERDICT_LABEL, type CaseVerdict } from "@/lib/cases";

/** Verdict is always conveyed by label + glyph, never by colour alone. */
export function VerdictIcon({ verdict, size = 18 }: { verdict: CaseVerdict | "pending"; size?: number }) {
  const common = { width: size, height: size, viewBox: "0 0 20 20", "aria-hidden": true as const };
  switch (verdict) {
    case "malicious":
      return (
        <svg {...common}><path d="M10 1.5 19 18H1z" fill="none" stroke="currentColor" strokeWidth="1.8" />
          <path d="M10 7v5.2M10 14.2v1.6" stroke="currentColor" strokeWidth="2" /></svg>
      );
    case "suspicious":
      return (
        <svg {...common}><rect x="3" y="3" width="14" height="14" transform="rotate(45 10 10)" fill="none"
          stroke="currentColor" strokeWidth="1.8" /><path d="M10 6.5v4.5M10 12.8v1.6" stroke="currentColor"
          strokeWidth="2" /></svg>
      );
    case "inconclusive":
      return (
        <svg {...common}><circle cx="10" cy="10" r="8" fill="none" stroke="currentColor" strokeWidth="1.8" />
          <path d="M7.6 7.6a2.5 2.5 0 1 1 3.4 2.3c-.7.3-1 .8-1 1.5v.6M10 14.2v1.4" fill="none"
            stroke="currentColor" strokeWidth="1.8" /></svg>
      );
    case "no_threat_detected":
      return (
        <svg {...common}><circle cx="10" cy="10" r="8" fill="none" stroke="currentColor" strokeWidth="1.8" />
          <path d="m6 10.3 2.7 2.6L14.2 7" fill="none" stroke="currentColor" strokeWidth="2" /></svg>
      );
    default:
      return (
        <svg {...common}><circle cx="10" cy="10" r="8" fill="none" stroke="currentColor" strokeWidth="1.8"
          strokeDasharray="2.5 2.5" /></svg>
      );
  }
}

export function VerdictSeal({ verdict, label }: { verdict: CaseVerdict | null; label?: string }) {
  const key = verdict ?? "pending";
  return (
    <span className={`seal seal-${key}`}>
      <VerdictIcon verdict={key} />
      {label ?? (verdict ? VERDICT_LABEL[verdict] : "Assessment pending")}
    </span>
  );
}
