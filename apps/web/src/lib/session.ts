import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

export const SESSION_COOKIE = "teger_session";
export const SESSION_TTL_SECONDS = 8 * 60 * 60;

let devSecret: string | undefined;

function secretKey(): Buffer {
  let secret = process.env.TEGER_DASHBOARD_SECRET ?? "";
  if (secret.length < 32) {
    if (process.env.NODE_ENV === "production") {
      throw new Error("TEGER_DASHBOARD_SECRET must be at least 32 characters in production.");
    }
    // Development only: a per-process secret, so sessions end when the server restarts.
    devSecret ??= randomBytes(32).toString("hex");
    secret = devSecret;
  }
  return createHash("sha256").update(secret).digest();
}

interface SessionPayload {
  k: string; // tenant API key
  exp: number; // unix seconds
}

/** Encrypts the API key with AES-256-GCM so the cookie value is opaque and tamper-evident. */
export function sealSession(apiKey: string, now = Date.now()): string {
  const payload: SessionPayload = { k: apiKey, exp: Math.floor(now / 1000) + SESSION_TTL_SECONDS };
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", secretKey(), iv);
  const body = Buffer.concat([cipher.update(JSON.stringify(payload), "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]).toString("base64url");
}

export function openSession(value: string | undefined, now = Date.now()): string | null {
  if (!value) return null;
  try {
    const raw = Buffer.from(value, "base64url");
    if (raw.length < 29) return null;
    const decipher = createDecipheriv("aes-256-gcm", secretKey(), raw.subarray(0, 12));
    decipher.setAuthTag(raw.subarray(12, 28));
    const text = Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString("utf8");
    const payload = JSON.parse(text) as SessionPayload;
    if (typeof payload.k !== "string" || typeof payload.exp !== "number") return null;
    if (payload.exp * 1000 <= now) return null;
    return payload.k;
  } catch {
    return null;
  }
}

export const API_KEY_PATTERN = /^tgr_[a-z0-9]{12}_[A-Za-z0-9_-]{32,128}$/;

/** Cookie holding the user's own Anthropic key (BYOK), sealed the same way as the session. */
export const AI_KEY_COOKIE = "teger_ai_key";
export const BYOK_KEY_PATTERN = /^sk-ant-[A-Za-z0-9_-]{20,250}$/;

export function keyHint(key: string): string {
  return `sk-ant-…${key.slice(-4)}`;
}
