import { notFound } from "next/navigation";
import { CaseReport } from "@/components/case/CaseReport";

export default async function LiveReport({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!/^case_[a-f0-9]{16}$/.test(id)) notFound();
  return <CaseReport base="/api/live" caseId={id} backHref={`/app/cases/${id}`} mode="live" />;
}
