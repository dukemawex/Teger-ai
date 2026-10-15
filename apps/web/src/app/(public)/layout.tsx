import Link from "next/link";
import { Wordmark } from "@/components/Mark";

export default function PublicLayout({ children }: { children: React.ReactNode }) {
  return (
    <>
      <a className="skip" href="#main">Skip to content</a>
      <header className="public-top">
        <div className="inner">
          <Wordmark />
          <span className="status-pill">Private beta · interactive demo</span>
          <nav className="public-nav" aria-label="Site">
            <Link href="/demo">Demo</Link>
            <Link href="/#how">How it works</Link>
            <Link href="/#status">Status &amp; privacy</Link>
            <Link href="/connect">Console sign-in</Link>
          </nav>
        </div>
      </header>
      <main id="main">{children}</main>
      <footer className="public-footer">
        <div className="inner">
          <div>
            <strong>Teger AI — operated by DUKERS LTD.</strong>
            <div>Founded by Emmanuel Effiom Duke.</div>
          </div>
          <div>
            <Link href="/demo">Interactive demo</Link> · <Link href="/#status">Status &amp; privacy</Link> ·{" "}
            <a href="https://github.com/dukemawex/Teger-ai">Source on GitHub</a>
          </div>
          <div className="tiny">
            Tetradrachm photograph: The Metropolitan Museum of Art, object 326395, Open Access (public domain).
            Artwork, mark and charts are original. Demo organizations and domains are fictional.
          </div>
        </div>
      </footer>
    </>
  );
}
