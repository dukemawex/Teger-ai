import { describe, expect, it } from "vitest";
import { isPublicPath } from "./public-paths";

describe("public routing boundary", () => {
  it("opens the scanner and discovery pages", () => {
    for (const path of ["/", "/scan", "/api/scan", "/method", "/privacy", "/robots.txt", "/sitemap.xml"])
      expect(isPublicPath(path)).toBe(true);
  });
  it("keeps console routes, credential settings and prefix lookalikes private", () => {
    for (const path of ["/overview", "/analyze", "/api/analyses", "/api/byok", "/settings", "/incidents",
      "/scan/private", "/api/scan/history", "/api/session/anything"])
      expect(isPublicPath(path)).toBe(false);
  });
});
