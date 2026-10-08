import { StatusBadge } from "@/components/StatusBadge";

export default function DevicesPage() {
  return (
    <>
      <header className="page-head">
        <span className="eyebrow">DEVICE INVENTORY</span>
        <h1>Devices</h1>
      </header>
      <section className="panel empty">
        <StatusBadge status="unavailable" />
        <p>
          Device inventory needs the Teger Guard (Windows) or Teger Mobile (Android) agents, which are planned and not
          yet built. No devices are being monitored.
        </p>
      </section>
    </>
  );
}
