import Link from "next/link";

const LINKS: [string, string][] = [
  ["/", "Overview"],
  ["/analyze", "Threat analysis"],
  ["/incidents", "Incident history"],
  ["/events", "Security events"],
  ["/protection", "Protection status"],
  ["/devices", "Devices"],
  ["/policies", "Policies"],
  ["/settings", "Settings"],
];

export function Nav() {
  return (
    <nav className="nav" aria-label="Main">
      {LINKS.map(([href, label]) => (
        <Link key={href} href={href}>
          {label}
        </Link>
      ))}
    </nav>
  );
}
