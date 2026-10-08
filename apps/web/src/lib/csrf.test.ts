import { describe, expect, it } from "vitest";
import { isSameOrigin } from "./csrf";

const h = (init: Record<string, string>) => new Headers(init);

describe("isSameOrigin", () => {
  it("accepts matching origin and host", () => {
    expect(isSameOrigin(h({ origin: "http://localhost:3100", host: "localhost:3100" }))).toBe(true);
  });
  it("rejects cross-site and missing origins", () => {
    expect(isSameOrigin(h({ origin: "https://evil.example", host: "localhost:3100" }))).toBe(false);
    expect(isSameOrigin(h({ host: "localhost:3100" }))).toBe(false);
    expect(isSameOrigin(h({ origin: "null", host: "localhost:3100" }))).toBe(false);
  });
});
