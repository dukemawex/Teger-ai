import "server-only";
import { NextResponse } from "next/server";
import { apiBase } from "./api";
import { isSameOrigin } from "./csrf";

export { allowedPath } from "./proxyRules";

const MAX_BODY = 64 * 1024;

export async function forward(
  request: Request,
  upstreamPath: string,
  headers: Record<string, string>,
): Promise<NextResponse> {
  if (request.method !== "GET" && !isSameOrigin(request.headers)) {
    return NextResponse.json({ detail: "Cross-origin request rejected." }, { status: 403 });
  }
  let body: string | undefined;
  if (request.method === "POST") {
    body = await request.text();
    if (body.length > MAX_BODY) return NextResponse.json({ detail: "Request too large." }, { status: 413 });
    headers["Content-Type"] = "application/json";
  }
  const search = new URL(request.url).search;
  let upstream: Response;
  try {
    upstream = await fetch(`${apiBase()}${upstreamPath}${search.length < 64 ? search : ""}`, {
      method: request.method,
      headers: { Accept: "application/json", ...headers },
      body,
      cache: "no-store",
    });
  } catch {
    return NextResponse.json(
      { detail: "The Teger investigation API is not reachable. Start it with `make api` or check TEGER_API_URL." },
      { status: 502 },
    );
  }
  const text = await upstream.text();
  return new NextResponse(text, {
    status: upstream.status,
    headers: {
      "Content-Type": upstream.headers.get("content-type") ?? "application/json",
      "Cache-Control": "no-store",
    },
  });
}
