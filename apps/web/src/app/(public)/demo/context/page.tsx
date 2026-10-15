import type { Metadata } from "next";
import { ContextRegistry } from "@/components/ContextRegistry";
import { DemoBanner } from "@/components/public/DemoBanner";

export const metadata: Metadata = { title: "Demo approved context", robots: { index: false, follow: true } };

export default function DemoContext() {
  return (
    <>
      <DemoBanner />
      <div className="page">
        <header className="page-head">
          <span className="eyebrow">Demo · approved business context</span>
          <h1>Records for Harbor &amp; Quill Ltd (fictional)</h1>
          <p className="muted">Read-only in the demo. In the console, people with the <code>context:write</code> scope add and
            revoke records; the investigator can only read them.</p>
        </header>
        <ContextRegistry base="/api/demo" editable={false} />
      </div>
    </>
  );
}
