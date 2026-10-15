import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { CaseWorkspace } from "@/components/case/CaseWorkspace";
import { DemoBanner } from "@/components/public/DemoBanner";

export const metadata: Metadata = { title: "Demo case", robots: { index: false, follow: false } };

export default async function DemoCasePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!/^case_[a-f0-9]{16}$/.test(id)) notFound();
  return (
    <>
      <DemoBanner />
      <CaseWorkspace base="/api/demo" caseId={id} mode="demo" homeHref="/demo" casePrefix="/demo/cases" />
    </>
  );
}
