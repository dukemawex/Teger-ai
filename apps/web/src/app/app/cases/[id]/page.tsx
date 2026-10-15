import { notFound } from "next/navigation";
import { CaseWorkspace } from "@/components/case/CaseWorkspace";

export default async function LiveCasePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!/^case_[a-f0-9]{16}$/.test(id)) notFound();
  return <CaseWorkspace base="/api/live" caseId={id} mode="live" homeHref="/app/analyze"
    casePrefix="/app/cases" />;
}
