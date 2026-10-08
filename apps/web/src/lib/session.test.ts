import { describe, expect, it } from "vitest";
import { API_KEY_PATTERN, openSession, sealSession, SESSION_TTL_SECONDS } from "./session";

const KEY = "tgr_abcdefghijkl_" + "A".repeat(43);

describe("session cookie", () => {
  it("round-trips the API key", () => {
    expect(openSession(sealSession(KEY))).toBe(KEY);
  });

  it("does not contain the key in plaintext", () => {
    const sealed = sealSession(KEY);
    expect(sealed).not.toContain("tgr_");
    expect(Buffer.from(sealed, "base64url").toString("utf8")).not.toContain("abcdefghijkl");
  });

  it("rejects tampered values", () => {
    const sealed = Buffer.from(sealSession(KEY), "base64url");
    sealed[sealed.length - 1] ^= 1;
    expect(openSession(sealed.toString("base64url"))).toBeNull();
  });

  it("rejects expired sessions", () => {
    const now = Date.now();
    const sealed = sealSession(KEY, now);
    expect(openSession(sealed, now + (SESSION_TTL_SECONDS + 1) * 1000)).toBeNull();
  });

  it("rejects garbage", () => {
    for (const value of [undefined, "", "abc", "x".repeat(200)]) expect(openSession(value)).toBeNull();
  });

  it("validates API key shape", () => {
    expect(API_KEY_PATTERN.test(KEY)).toBe(true);
    expect(API_KEY_PATTERN.test("sk-ant-123")).toBe(false);
    expect(API_KEY_PATTERN.test(KEY + "\n")).toBe(false);
  });
});
