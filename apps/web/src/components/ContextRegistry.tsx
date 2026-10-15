"use client";

import { useEffect, useState } from "react";
import { caseApi } from "@/components/case/useCaseApi";
import type { ContextEntry } from "@/lib/cases";

const KIND_LABEL = { supplier: "Supplier", identity_provider: "Identity provider", service: "Service" };

export function ContextRegistry({ base, editable }: { base: string; editable: boolean }) {
  const api = caseApi(base);
  const [entries, setEntries] = useState<ContextEntry[] | null>(null);
  const [error, setError] = useState("");
  const [tick, setTick] = useState(0);
  useEffect(() => {
    caseApi(base).get<ContextEntry[]>("context").then(setEntries).catch((e) => setError(e.message));
  }, [base, tick]);

  return (
    <>
      {error && <p className="notice notice-danger" role="alert">{error}</p>}
      <section className="panel">
        <div className="panel-title"><h2>Approved records</h2>
          <span className="small muted">An approved domain is context, not immunity: it is still checked.</span></div>
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Organization</th><th>Approved domains &amp; services</th><th>Verified contact</th><th>Approved by</th>{editable && <th />}</tr></thead>
            <tbody>
              {(entries ?? []).map((e) => (
                <tr key={e.id}>
                  <td><strong>{e.name}</strong><div className="tiny muted">{KIND_LABEL[e.kind]} · <span className="mono">{e.id}</span></div></td>
                  <td>
                    {e.domains.map((d) => <div key={d} className="mono small">{d}</div>)}
                    {e.approved_services.map((s) => <div key={s.domain} className="small"><span className="mono">{s.domain}</span> <span className="muted">— {s.purpose}</span></div>)}
                  </td>
                  <td className="small">{e.verified_contact ?? "—"}</td>
                  <td className="small">{e.approved_by}<div className="tiny muted">{e.approved_at.slice(0, 10)} · {e.verification_source}</div></td>
                  {editable && <td><button className="btn btn-small btn-danger" onClick={async () => {
                    if (!window.confirm(`Revoke the approved record for ${e.name}?`)) return;
                    try { await api.del(`context/${e.id}`); setTick((t) => t + 1); } catch (err) { setError((err as Error).message); }
                  }}>Revoke</button></td>}
                </tr>
              ))}
              {entries && !entries.length && <tr><td colSpan={5} className="muted">No approved records yet.</td></tr>}
              {!entries && !error && <tr><td colSpan={5}><span className="spinner" /> Loading…</td></tr>}
            </tbody>
          </table>
        </div>
      </section>
      {editable && <AddEntry base={base} onAdded={() => setTick((t) => t + 1)} />}
    </>
  );
}

function AddEntry({ base, onAdded }: { base: string; onAdded: () => void }) {
  const [kind, setKind] = useState("supplier");
  const [name, setName] = useState("");
  const [domains, setDomains] = useState("");
  const [serviceDomain, setServiceDomain] = useState("");
  const [servicePurpose, setServicePurpose] = useState("");
  const [contact, setContact] = useState("");
  const [source, setSource] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  return (
    <form className="panel panel-pad form mt" onSubmit={async (e) => {
      e.preventDefault();
      setBusy(true); setError("");
      try {
        await caseApi(base).post("context", {
          kind, name, domains: domains.split(/[\s,]+/).filter(Boolean), verified_contact: contact || null,
          verification_source: source,
          approved_services: serviceDomain ? [{ domain: serviceDomain.trim().toLowerCase(), purpose: servicePurpose || "approved service" }] : [],
        });
        setName(""); setDomains(""); setServiceDomain(""); setServicePurpose(""); setContact(""); setSource("");
        onAdded();
      } catch (err) { setError((err as Error).message); } finally { setBusy(false); }
    }}>
      <h2 className="serif">Approve a record</h2>
      <p className="small muted">Add only details you verified independently — never from the message under investigation.
        Your API key is recorded as the approver. Requires the <code>context:write</code> scope.</p>
      <div className="grid-2">
        <div className="form"><label htmlFor="ctx-kind">Type</label>
          <select id="ctx-kind" value={kind} onChange={(e) => setKind(e.target.value)}>
            <option value="supplier">Supplier</option><option value="identity_provider">Identity provider</option><option value="service">Service</option>
          </select></div>
        <div className="form"><label htmlFor="ctx-name">Name</label>
          <input id="ctx-name" type="text" required minLength={2} maxLength={120} value={name} onChange={(e) => setName(e.target.value)} /></div>
        <div className="form"><label htmlFor="ctx-domains">Approved domains</label>
          <input id="ctx-domains" type="text" required value={domains} onChange={(e) => setDomains(e.target.value)} placeholder="supplier.example, billing.supplier.example" /></div>
        <div className="form"><label htmlFor="ctx-contact">Verified contact</label>
          <input id="ctx-contact" type="text" maxLength={200} value={contact} onChange={(e) => setContact(e.target.value)} placeholder="Accounts desk, phone number you hold" /></div>
        <div className="form"><label htmlFor="ctx-svc">Approved third-party service domain (optional)</label>
          <input id="ctx-svc" type="text" value={serviceDomain} onChange={(e) => setServiceDomain(e.target.value)} placeholder="billing.vendor.example" /></div>
        <div className="form"><label htmlFor="ctx-svc-purpose">Service purpose</label>
          <input id="ctx-svc-purpose" type="text" maxLength={120} value={servicePurpose} onChange={(e) => setServicePurpose(e.target.value)} placeholder="invoicing portal" /></div>
      </div>
      <label htmlFor="ctx-source">How was this verified?</label>
      <input id="ctx-source" type="text" required minLength={3} maxLength={200} value={source} onChange={(e) => setSource(e.target.value)} placeholder="Call-back to the number on the signed contract, 2026-10-01" />
      <div className="btn-row"><button className="btn btn-primary" disabled={busy}>{busy ? "Saving…" : "Approve record"}</button></div>
      {error && <p className="notice notice-danger" role="alert">{error}</p>}
    </form>
  );
}
