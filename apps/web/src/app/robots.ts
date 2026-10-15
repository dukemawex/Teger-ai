import type { MetadataRoute } from "next";

const SITE = process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.tegerai.tech";

// Robots rules are a crawling hint, not access control: /app and /api require a session.
export default function robots(): MetadataRoute.Robots {
  return {
    rules: [{ userAgent: "*", allow: ["/", "/demo"], disallow: ["/app", "/api/", "/connect", "/demo/cases/"] }],
    sitemap: `${SITE}/sitemap.xml`,
  };
}
