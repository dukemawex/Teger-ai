import type { Metadata } from "next";
import { InvestigationForm } from "@/components/public/InvestigationForm";

export const metadata: Metadata = { title: "Investigate a message or URL", alternates: { canonical: "/scan" } };

export default function ScanPage() {
  return <section className="investigation-page">
    <header className="investigation-heading"><p className="public-kicker">THE INVESTIGATION DESK</p>
      <h1>Bring the doubt.<br /><em>Follow the evidence.</em></h1>
      <p>Check a suspicious message or URL. Get specific findings and a next step you can act on.</p></header>
    <InvestigationForm />
  </section>;
}
