import type { MetadataRoute } from "next";

export default function robots(): MetadataRoute.Robots {
  return { rules: { userAgent: "*", allow: ["/", "/scan", "/method", "/privacy"],
    disallow: ["/api/", "/overview", "/connect", "/analyze", "/incidents", "/events", "/devices", "/policies", "/protection", "/settings"] },
    sitemap: "https://www.tegerai.tech/sitemap.xml" };
}
