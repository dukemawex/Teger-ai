import type { Metadata } from "next";
import { Suspense } from "react";
import { DemoHub } from "@/components/public/DemoHub";
import { DemoBanner } from "@/components/public/DemoBanner";

export const metadata: Metadata = {
  title: "Interactive demo",
  description: "Run a Teger investigation on synthetic phishing cases: supplier impersonation, an approved third-party service, an inconclusive link and a prompt-injection attempt.",
  alternates: { canonical: "/demo" },
};

export default function DemoPage() {
  return (
    <>
      <DemoBanner />
      <Suspense><DemoHub /></Suspense>
    </>
  );
}
