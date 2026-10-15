import type { Metadata, Viewport } from "next";
import "./globals.css";

const SITE = process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.tegerai.tech";
const DESCRIPTION =
  "Teger investigates suspicious emails and websites against the context of your business — approved suppliers, " +
  "services and identity providers — explains the evidence, and helps your team respond. Private beta.";

export const metadata: Metadata = {
  metadataBase: new URL(SITE),
  title: { default: "Teger AI — Inspect the message. Trace the site. Decide with evidence.", template: "%s · Teger AI" },
  description: DESCRIPTION,
  applicationName: "Teger AI",
  alternates: { canonical: "/" },
  openGraph: {
    type: "website", siteName: "Teger AI", url: "/", title: "Teger AI — Decide with evidence",
    description: DESCRIPTION, images: [{ url: "/og.png", width: 1200, height: 630, alt: "Teger AI evidence route" }],
  },
  twitter: { card: "summary_large_image", title: "Teger AI — Decide with evidence", description: DESCRIPTION, images: ["/og.png"] },
  robots: { index: true, follow: true },
};

// Rendered per request so Next.js can attach the CSP nonce from src/middleware.ts to its scripts.
export const dynamic = "force-dynamic";

export const viewport: Viewport = { themeColor: "#171a18", width: "device-width", initialScale: 1 };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en-GB">
      <body>{children}</body>
    </html>
  );
}
