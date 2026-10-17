import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  metadataBase: new URL("https://www.tegerai.tech"),
  title: { default: "Teger AI — Investigate before you trust", template: "%s | Teger AI" },
  description: "Check suspicious messages and URLs with Teger AI. Inspect phishing indicators, understand the evidence, and choose a safer next action.",
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
