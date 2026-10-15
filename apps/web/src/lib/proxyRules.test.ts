import { describe, expect, it } from "vitest";
import { allowedPath } from "./proxyRules";

describe("proxy allow-list", () => {
  it("allows the case workflow", () => {
    expect(allowedPath("POST", "cases")).toBe(true);
    expect(allowedPath("GET", "cases/case_0123456789abcdef/events")).toBe(true);
    expect(allowedPath("POST", "actions/act_0123456789abcdef/execute")).toBe(true);
    expect(allowedPath("DELETE", "context/ctx_northwind")).toBe(true);
  });
  it("rejects anything else, including traversal and other API routes", () => {
    expect(allowedPath("GET", "cases/../analyses")).toBe(false);
    expect(allowedPath("GET", "whoami")).toBe(false);
    expect(allowedPath("POST", "actions/act_0123456789abcdef/approve/extra")).toBe(false);
    expect(allowedPath("DELETE", "cases/case_0123456789abcdef")).toBe(false);
    expect(allowedPath("GET", "cases/case_XYZ")).toBe(false);
  });
});
