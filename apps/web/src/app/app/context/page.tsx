import { ContextRegistry } from "@/components/ContextRegistry";

export default function ContextPage() {
  return (
    <div className="page">
      <header className="page-head">
        <span className="eyebrow">Approved business context</span>
        <h1>Suppliers, services and identity providers</h1>
        <p className="muted">Investigations compare what they observe with these records. Only people can add or revoke
          records; the investigator can read them but never change them.</p>
      </header>
      <ContextRegistry base="/api/live" editable />
    </div>
  );
}
