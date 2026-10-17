import { describe, expect, it } from "vitest";
import { MAX_SCAN_BYTES, readScanInput } from "./public-scan";

const request = (body: unknown) => new Request("https://www.tegerai.tech/api/scan", {
  method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
});

describe("public submission boundary", () => {
  it("keeps only supported subject fields", async () => {
    expect(JSON.parse(await readScanInput(request({ content: " hello ", explain: true, cloud_ai_consent: true,
      tenant_id: "private", apiKey: "secret" })))).toEqual({ content: "hello", content_type: "other" });
  });
  it("rejects empty, invalid and oversized fields", async () => {
    for (const body of [{}, null, [], { content: 123 }, { content: " " }, { url: "x".repeat(2049) },
      { content: "a".repeat(20001) }, { content: "hi", content_type: "unsupported" }])
      await expect(readScanInput(request(body))).rejects.toThrow();
  });
  it("measures bytes without relying on Content-Length", async () => {
    await expect(readScanInput(request({ content: "界".repeat(MAX_SCAN_BYTES / 3) }))).rejects.toMatchObject({ status: 413 });
  });
  it("rejects malformed JSON", async () => {
    await expect(readScanInput(new Request("https://example.com", { method: "POST",
      headers: { "Content-Type": "application/json" }, body: "{" }))).rejects.toThrow();
  });
});
