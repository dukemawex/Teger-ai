import Link from "next/link";

export function TegerMark() {
  return <svg width="32" height="36" viewBox="0 0 32 36" fill="none" aria-hidden="true">
    <path d="M16 2 29 8v12L16 34 3 20V8L16 2Z" stroke="currentColor" strokeWidth="1.5" />
    <path d="M9 12h14M16 12v13M8 7l16 20M24 7 8 27" stroke="currentColor" strokeWidth="1.2" />
  </svg>;
}

export function PublicShell({ children }: { children: React.ReactNode }) {
  return <div className="public-site">
    <a className="skip-link" href="#main">Skip to content</a>
    <header className="public-header">
      <Link className="public-brand" href="/" aria-label="Teger AI home"><TegerMark />TEGER<span>AI</span></Link>
      <nav aria-label="Public navigation">
        <Link href="/scan">Investigate</Link><Link href="/method">Our method</Link>
        <Link href="/connect" className="console-link">Security console <span aria-hidden="true">↗</span></Link>
      </nav>
    </header>
    <main id="main">{children}</main>
    <footer className="public-footer">
      <div><Link className="public-brand" href="/"><TegerMark />TEGER<span>AI</span></Link>
        <p>A DUKERS LTD product.<br />Built by <a href="https://duker.me/about/">Emmanuel Effiom Duke</a>.</p></div>
      <div className="footer-links"><Link href="/privacy">Privacy</Link><Link href="/method">Capabilities & limits</Link>
        <a href="https://github.com/dukemawex/Teger-ai">Source on GitHub ↗</a><a href="mailto:hello@tegerai.tech">Contact</a></div>
      <p className="footer-note">Evidence informs the decision.<br />You remain in control.</p>
    </footer>
  </div>;
}
