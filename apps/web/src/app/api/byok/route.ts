import { NextResponse } from "next/server";
import { currentApiKey } from "@/lib/api";
import { isSameOrigin } from "@/lib/csrf";
import { AI_KEY_COOKIE, BYOK_KEY_PATTERN, keyHint, SESSION_TTL_SECONDS, sealSession } from "@/lib/session";

const cookieOptions = {
  httpOnly: true,
  sameSite: "strict" as const,
  secure: process.env.NODE_ENV === "production",
  path: "/",
};

async function guard(request: Request): Promise<NextResponse | null> {
  if (!isSameOrigin(request.headers)) {
    return NextResponse.json({ detail: "Cross-origin request rejected." }, { status: 403 });
  }
  if (!(await currentApiKey())) return NextResponse.json({ detail: "Not connected." }, { status: 401 });
  return null;
}

/** Saves the user's own Anthropic key in an encrypted HttpOnly cookie. Teger never stores it server-side. */
export async function POST(request: Request) {
  const denied = await guard(request);
  if (denied) return denied;
  let key = "";
  try {
    const body = await request.json();
    key = typeof body?.anthropicKey === "string" ? body.anthropicKey.trim() : "";
  } catch {
    // validation below
  }
  if (!BYOK_KEY_PATTERN.test(key)) {
    return NextResponse.json({ detail: "That does not look like an Anthropic API key (sk-ant-…)." }, { status: 400 });
  }
  const result = NextResponse.json({ configured: true, hint: keyHint(key) });
  result.cookies.set(AI_KEY_COOKIE, sealSession(key), { ...cookieOptions, maxAge: SESSION_TTL_SECONDS });
  return result;
}

export async function DELETE(request: Request) {
  const denied = await guard(request);
  if (denied) return denied;
  const result = NextResponse.json({ configured: false });
  result.cookies.set(AI_KEY_COOKIE, "", { ...cookieOptions, maxAge: 0 });
  return result;
}
