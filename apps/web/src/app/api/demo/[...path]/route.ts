import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { randomBytes } from "node:crypto";
import { allowedPath, forward } from "@/lib/proxy";

const DEMO_COOKIE = "teger_demo";
const SESSION = /^[a-f0-9]{32}$/;

async function handle(request: Request, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  const joined = path.join("/");
  if (!allowedPath(request.method, joined) || joined.startsWith("context/") || (request.method === "POST" && joined === "context")) {
    return NextResponse.json({ detail: "Not found." }, { status: 404 });
  }
  const store = await cookies();
  let session = store.get(DEMO_COOKIE)?.value ?? "";
  const fresh = !SESSION.test(session);
  if (fresh) session = randomBytes(16).toString("hex");
  const response = await forward(request, `/v1/demo/${joined}`, { "X-Teger-Demo-Session": session });
  if (fresh) {
    // Demo state is per visitor; the id only namespaces synthetic fixture data.
    response.cookies.set(DEMO_COOKIE, session, {
      httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", path: "/", maxAge: 60 * 60 * 24,
    });
  }
  return response;
}

export { handle as GET, handle as POST };
