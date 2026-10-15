import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { CaseReport } from "@/components/case/CaseReport";
import { DemoBanner } from "@/components/public/DemoBanner";

export const metadata: Metadata = { title: "Demo report", robots: { index: false, follow: false } };

export default async function DemoReport({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!/^case_[a-f0-9]{16}$/.test(id)) notFound();
  return <><DemoBanner /><CaseReport base="/api/demo" caseId={id} backHref={`/demo/cases/${id}`} mode="demo" /></>;
}
