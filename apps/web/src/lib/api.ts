import "server-only";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { openSession, SESSION_COOKIE } from "./session";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export function apiBase(): string {
  const base = (process.env.TEGER_API_URL ?? "http://127.0.0.1:8100").replace(/\/$/, "");
  if (!/^https?:\/\//.test(base)) throw new Error("TEGER_API_URL must be an http(s) URL.");
  return base;
}

export async function currentApiKey(): Promise<string | null> {
  const store = await cookies();
  return openSession(store.get(SESSION_COOKIE)?.value);
}

/** Server-side call to the Teger API with the session's key. Redirects to /connect when unauthenticated. */
export async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const key = await currentApiKey();
  if (!key) redirect("/connect");
  const response = await fetch(`${apiBase()}${path}`, {
    ...init,
    cache: "no-store",
    headers: { ...(init.headers ?? {}), Authorization: `Bearer ${key}`, Accept: "application/json" },
  });
  if (response.status === 401) redirect("/connect?expired=1");
  if (!response.ok) {
    let detail = `Request failed (${response.status})`;
    try {
      const body = await response.json();
      if (typeof body?.detail === "string") detail = body.detail;
    } catch {
      // keep generic message
    }
    throw new ApiError(response.status, detail);
  }
  return (await response.json()) as T;
}

export async function publicFetch<T>(path: string): Promise<T | null> {
  try {
    const response = await fetch(`${apiBase()}${path}`, { cache: "no-store" });
    return response.ok ? ((await response.json()) as T) : null;
  } catch {
    return null;
  }
}
