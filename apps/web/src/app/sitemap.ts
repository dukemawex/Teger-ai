import type { MetadataRoute } from "next";

export default function sitemap(): MetadataRoute.Sitemap {
  return ["", "/scan", "/method", "/privacy"].map(path => ({ url: `https://www.tegerai.tech${path}` }));
}
