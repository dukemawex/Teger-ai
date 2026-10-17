import type { Metadata } from "next";
import { PublicShell } from "@/components/public/PublicShell";
import "./public.css";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { robots: { index: true, follow: true } };

export default function PublicLayout({ children }: { children: React.ReactNode }) {
  return <PublicShell>{children}</PublicShell>;
}
