// Exact matches prevent public /scan or /api/scan prefixes from opening private routes.
const PUBLIC_PATHS = new Set(["/", "/scan", "/method", "/privacy", "/connect", "/api/session", "/api/scan",
  "/robots.txt", "/sitemap.xml", "/icon.svg"]);

export function isPublicPath(pathname: string): boolean {
  return PUBLIC_PATHS.has(pathname);
}
