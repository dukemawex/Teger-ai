"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const LINKS: [string, string][] = [
  ["/app", "Overview"],
  ["/app/analyze", "Start an investigation"],
  ["/app/context", "Approved context"],
  ["/app/activity", "Activity & audit"],
  ["/app/analyses", "Quick analyses"],
  ["/app/settings", "Settings"],
];

export function Nav() {
  const pathname = usePathname();
  return (
    <nav aria-label="Workspace">
      {LINKS.map(([href, label]) => {
        const current = href === "/app" ? pathname === "/app" : pathname.startsWith(href) ||
          (href === "/app/analyze" && pathname.startsWith("/app/cases"));
        return (
          <Link key={href} href={href} aria-current={current ? "page" : undefined}>{label}</Link>
        );
      })}
    </nav>
  );
}
