import Link from "next/link";
import type { Metadata } from "next";

export const metadata: Metadata = {
  alternates: { canonical: "/" },
  openGraph: { title: "Teger AI — Investigate before you trust", url: "/", type: "website",
    description: "Check suspicious messages and URLs. Understand the evidence. Choose a safer next action." },
};

export default function HomePage() {
  return <>
    <section className="public-hero">
      <div className="hero-copy">
        <p className="public-kicker"><span className="status-dot" /> PUBLIC PHISHING SCANNER</p>
        <h1>Before you trust it.<br /><em>Investigate it.</em></h1>
        <p className="hero-lede">An urgent message. A familiar name. An unfamiliar link.<br className="desktop-break" />
          Find the warning signs before you make your next move.</p>
        <div className="public-actions"><Link className="public-button" href="/scan">Start an investigation <span aria-hidden="true">↗</span></Link>
          <Link className="text-link" href="/method">See how it works <span aria-hidden="true">→</span></Link></div>
        <p className="hero-caption">No account required. Analyze a message or URL.</p>
      </div>
      <div className="hero-emblem" aria-hidden="true">
        <div className="emblem-frame"><svg viewBox="0 0 400 400" fill="none">
          <circle cx="200" cy="200" r="170" stroke="currentColor" strokeWidth=".7" />
          <circle cx="200" cy="200" r="145" stroke="currentColor" strokeWidth=".7" strokeDasharray="2 10" />
          <path d="M200 20v360M20 200h360M80 80l240 240M320 80 80 320" stroke="currentColor" strokeWidth=".5" />
          <path d="m200 65 105 60v115L200 335 95 240V125L200 65Z" fill="#1c2321" stroke="currentColor" strokeWidth="2" />
          <path d="m200 88 85 49v94l-85 78-85-78v-94l85-49Z" stroke="currentColor" strokeWidth=".5" />
          <path d="M142 152h116v20h-46v93h-24v-93h-46v-20Z" fill="currentColor" />
          <path d="M95 125 305 240M305 125 95 240" stroke="currentColor" strokeWidth=".5" />
          <circle cx="200" cy="30" r="4" fill="currentColor" /><circle cx="370" cy="200" r="4" fill="currentColor" />
        </svg></div>
        <span className="emblem-label">OBSERVE / QUESTION / VERIFY</span>
      </div>
    </section>
    <div className="capability-strip"><span>MESSAGE & URL ANALYSIS</span><span>EXPLAINABLE FINDINGS</span><span>YOU CONTROL THE RESPONSE</span></div>
    <section className="public-section" aria-labelledby="evidence-heading">
      <div className="section-heading"><p className="public-kicker">01 / THE INVESTIGATION</p><h2 id="evidence-heading">A verdict is only useful<br /><em>when you can see why.</em></h2>
        <p>Teger checks the content you provide, connects the warning signs, and shows what still needs verification.</p></div>
      <div className="method-grid">
        <article><span className="step-number">01</span><h3>Inspect the request</h3><p>Look for pressure, requests for credentials, changed payment details, and instructions designed to bypass your judgment.</p></article>
        <article><span className="step-number">02</span><h3>Examine the identity</h3><p>Check URL structure, familiar brand names on unfamiliar domains, and sender details that do not match the claimed identity.</p></article>
        <article><span className="step-number">03</span><h3>Choose the next move</h3><p>Read the evidence and recommended action. Save a report or prepare a verification note for a contact you already trust.</p></article>
      </div>
    </section>
    <section className="public-principle"><p className="public-kicker">02 / BUILT FOR SCRUTINY</p>
      <h2>Clear evidence.<br /><em>Honest uncertainty.</em></h2>
      <div><p>The public scanner runs Teger's local detection rules on our server. It analyzes the text and URL you submit; it does not open the destination website.</p>
        <p>Live reputation checks and cloud AI are not used in this scanner. When a required check is unavailable, the result says so. A low score is never a guarantee of safety.</p>
        <Link className="text-link" href="/method">Read the method and limits →</Link></div>
    </section>
    <section className="public-cta"><div><p className="public-kicker">A MOMENT OF DOUBT IS WORTH EXPLORING.</p><h2>What landed in your inbox?</h2></div>
      <Link className="public-button" href="/scan">Check it with Teger <span aria-hidden="true">↗</span></Link></section>
  </>;
}
