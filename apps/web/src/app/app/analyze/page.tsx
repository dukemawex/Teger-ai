import { Suspense } from "react";
import { apiFetch, byokStatus } from "@/lib/api";
import type { WhoAmI } from "@/lib/types";
import { InvestigateForm } from "./InvestigateForm";

export default async function AnalyzePage() {
  const [me, byok, ready] = await Promise.all([
    apiFetch<WhoAmI>("/v1/whoami"),
    byokStatus(),
    fetch(`${process.env.TEGER_API_URL ?? "http://127.0.0.1:8100"}/readyz`, { cache: "no-store" })
      .then((r) => r.json()).catch(() => null),
  ]);
  const liveFetch = ready?.components?.fetch_worker === "configured";
  return (
    <div className="page">
      <header className="page-head">
        <span className="eyebrow">Start an investigation</span>
        <h1>Submit a suspicious message or website</h1>
        <p className="muted">Teger opens a case, chooses relevant checks, compares what it finds with your approved
          business context, and proposes a response for a person to approve.</p>
      </header>
      {!me.scopes.includes("cases:write") && (
        <p className="notice notice-warn">This API key lacks the <code>cases:write</code> scope, so it cannot open investigations.</p>
      )}
      <Suspense><InvestigateForm aiPossible={me.cloud_ai_allowed || Boolean(byok.hint)} byokHint={byok.hint} liveFetch={liveFetch} /></Suspense>
    </div>
  );
}
