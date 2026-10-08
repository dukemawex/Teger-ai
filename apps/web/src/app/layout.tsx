import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Teger AI Security Console",
  description: "Explainable phishing and social-engineering defense.",
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
