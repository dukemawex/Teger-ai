import { NextResponse } from "next/server";
import { apiBase } from "@/lib/api";
import { isSameOrigin } from "@/lib/csrf";
import { AI_KEY_COOKIE, API_KEY_PATTERN, SESSION_COOKIE, SESSION_TTL_SECONDS, sealSession } from "@/lib/session";

const cookieOptions = {
  httpOnly: true,
  sameSite: "strict" as const,
  secure: process.env.NODE_ENV === "production",
  path: "/",
};

export async function POST(request: Request) {
  if (!isSameOrigin(request.headers)) {
    return NextResponse.json({ detail: "Cross-origin request rejected." }, { status: 403 });
  }
  let apiKey = "";
  try {
    const body = await request.json();
    apiKey = typeof body?.apiKey === "string" ? body.apiKey.trim() : "";
  } catch {
    // fall through to validation error
  }
  if (!API_KEY_PATTERN.test(apiKey)) {
    return NextResponse.json({ detail: "That does not look like a Teger API key." }, { status: 400 });
  }

  let response: Response;
  try {
    response = await fetch(`${apiBase()}/v1/whoami`, {
      headers: { Authorization: `Bearer ${apiKey}` },
      cache: "no-store",
    });
  } catch {
    return NextResponse.json({ detail: "The Teger API is not reachable." }, { status: 502 });
  }
  if (response.status === 401) {
    return NextResponse.json({ detail: "The API key was not accepted." }, { status: 401 });
  }
  if (!response.ok) {
    return NextResponse.json({ detail: "The Teger API returned an error." }, { status: 502 });
  }

  const result = NextResponse.json({ connected: true });
  result.cookies.set(SESSION_COOKIE, sealSession(apiKey), { ...cookieOptions, maxAge: SESSION_TTL_SECONDS });
  return result;
}

export async function DELETE(request: Request) {
  if (!isSameOrigin(request.headers)) {
    return NextResponse.json({ detail: "Cross-origin request rejected." }, { status: 403 });
  }
  const result = NextResponse.json({ connected: false });
  result.cookies.set(SESSION_COOKIE, "", { ...cookieOptions, maxAge: 0 });
  result.cookies.set(AI_KEY_COOKIE, "", { ...cookieOptions, maxAge: 0 });
  return result;
}
