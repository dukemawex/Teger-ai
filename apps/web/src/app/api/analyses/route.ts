import { NextResponse } from "next/server";
import { apiBase, currentApiKey, currentByokKey } from "@/lib/api";
import { isSameOrigin } from "@/lib/csrf";

const MAX_BODY = 64 * 1024;

export async function POST(request: Request) {
  if (!isSameOrigin(request.headers)) {
    return NextResponse.json({ detail: "Cross-origin request rejected." }, { status: 403 });
  }
  const key = await currentApiKey();
  if (!key) return NextResponse.json({ detail: "Not connected." }, { status: 401 });

  const raw = await request.text();
  if (raw.length > MAX_BODY) return NextResponse.json({ detail: "Request too large." }, { status: 413 });

  const headers: Record<string, string> = { Authorization: `Bearer ${key}`, "Content-Type": "application/json" };
  let wantsExplanation = false;
  try {
    const parsed = JSON.parse(raw);
    wantsExplanation = parsed?.explain === true && parsed?.cloud_ai_consent === true;
  } catch {
    // The API returns the validation error.
  }
  const byok = wantsExplanation ? await currentByokKey() : null;
  if (byok) headers["X-Anthropic-Api-Key"] = byok; // sent only with consented explanation requests

  let upstream: Response;
  try {
    upstream = await fetch(`${apiBase()}/v1/analyses`, {
      method: "POST",
      headers,
      body: raw,
      cache: "no-store",
    });
  } catch {
    return NextResponse.json({ detail: "The Teger API is not reachable." }, { status: 502 });
  }
  const body = await upstream.text();
  return new NextResponse(body, {
    status: upstream.status,
    headers: { "Content-Type": upstream.headers.get("content-type") ?? "application/json" },
  });
}
