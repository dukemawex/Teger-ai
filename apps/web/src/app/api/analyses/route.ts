import { NextResponse } from "next/server";
import { apiBase, currentApiKey } from "@/lib/api";
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

  let upstream: Response;
  try {
    upstream = await fetch(`${apiBase()}/v1/analyses`, {
      method: "POST",
      headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
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
