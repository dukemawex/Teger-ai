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

describe("BYOK key handling", async () => {
  const { BYOK_KEY_PATTERN, keyHint } = await import("./session");
  const ANTHROPIC = "sk-ant-api03-" + "z".repeat(40) + "WXYZ";

  it("accepts Anthropic keys and rejects others", () => {
    expect(BYOK_KEY_PATTERN.test(ANTHROPIC)).toBe(true);
    for (const bad of ["", "sk-proj-" + "a".repeat(40), "sk-ant-short", ANTHROPIC + "\n", ANTHROPIC + " x"]) {
      expect(BYOK_KEY_PATTERN.test(bad)).toBe(false);
    }
  });

  it("only reveals the last four characters", () => {
    expect(keyHint(ANTHROPIC)).toBe("sk-ant-…WXYZ");
  });

  it("seals the key so the cookie does not contain it", () => {
    const sealed = sealSession(ANTHROPIC);
    expect(sealed).not.toContain("sk-ant");
    expect(openSession(sealed)).toBe(ANTHROPIC);
  });
});
