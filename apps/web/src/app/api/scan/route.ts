import { NextResponse } from "next/server";
import { isSameOrigin } from "@/lib/csrf";
import { readScanInput, ScanInputError } from "@/lib/public-scan";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function error(detail: string, status: number, retry?: string | null) {
  return NextResponse.json({ detail }, { status, headers: {
    "Cache-Control": "no-store", ...(retry && /^\d{1,4}$/.test(retry) ? { "Retry-After": retry } : {}),
  } });
}

export async function POST(request: Request) {
  if (!isSameOrigin(request.headers)) return error("Cross-origin request rejected.", 403);
  let body: string;
  try { body = await readScanInput(request); }
  catch (e) {
    return e instanceof ScanInputError ? error(e.message, e.status) : error("Could not read the submission.", 400);
  }
  // This URL is operator configuration; it can never be supplied by the visitor.
  const base = (process.env.TEGER_API_URL ?? "http://127.0.0.1:8100").replace(/\/$/, "");
  try {
    const response = await fetch(`${base}/v1/public/analyses`, {
      method: "POST", body, headers: { "Content-Type": "application/json" }, cache: "no-store",
      signal: AbortSignal.timeout(15000), redirect: "error",
    });
    if (response.status === 429)
      return error("The public scanner is busy. Please try again in a minute.", 429, response.headers.get("retry-after"));
    if (response.status === 422) return error("Check your input. Use a valid HTTP(S) URL and keep messages under 20,000 characters.", 422);
    if (!response.ok) return error("The scanner is temporarily unavailable. No verdict was produced. Please try again later.", 503);
    const result = await response.json();
    return NextResponse.json(result, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return error("The scanner could not be reached. No verdict was produced. Please try again later.", 503);
  }
}
