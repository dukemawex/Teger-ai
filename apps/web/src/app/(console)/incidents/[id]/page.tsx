import Link from "next/link";
import { notFound } from "next/navigation";
import { VerdictView } from "@/components/VerdictView";
import { apiFetch, ApiError } from "@/lib/api";
import type { ThreatVerdict } from "@/lib/types";

export default async function IncidentDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!/^an_[a-f0-9]{32}$/.test(id)) notFound();
  let result: ThreatVerdict;
  try {
    result = await apiFetch<ThreatVerdict>(`/v1/analyses/${id}`);
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) notFound();
    throw err;
  }
  return (
    <>
      <header className="page-head">
        <Link href="/incidents">← Incident history</Link>
        <h1>Analysis {result.analysis_id}</h1>
        <p className="muted">{new Date(result.created_at).toLocaleString()} · {result.content_type}
          {result.url ? ` · ${result.url.unicode_host ?? result.url.host}` : ""}</p>
      </header>
      <section className="panel"><VerdictView result={result} /></section>
    </>
  );
}
