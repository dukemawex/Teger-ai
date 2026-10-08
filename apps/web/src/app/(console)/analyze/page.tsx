import { apiFetch, byokStatus } from "@/lib/api";
import type { WhoAmI } from "@/lib/types";
import { AnalyzeForm } from "./AnalyzeForm";

export default async function AnalyzePage() {
  const [me, byok] = await Promise.all([apiFetch<WhoAmI>("/v1/whoami"), byokStatus()]);
  return (
    <>
      <header className="page-head">
        <span className="eyebrow">THREAT ANALYSIS</span>
        <h1>Inspect a suspicious link or message</h1>
        <p className="muted">
          Teger never opens the link. It checks the URL&apos;s structure, the wording, and the sender, then applies a
          versioned policy.
        </p>
      </header>
      <AnalyzeForm cloudAiAllowed={me.cloud_ai_allowed} byokHint={byok.hint} />
    </>
  );
}
