import { NextResponse } from "next/server";
import { currentApiKey, currentByokKey } from "@/lib/api";
import { allowedPath, forward } from "@/lib/proxy";

async function handle(request: Request, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  const joined = path.join("/");
  if (!allowedPath(request.method, joined) || joined === "catalog" || joined.startsWith("session/")) {
    return NextResponse.json({ detail: "Not found." }, { status: 404 });
  }
  const key = await currentApiKey();
  if (!key) return NextResponse.json({ detail: "Not connected." }, { status: 401 });
  const headers: Record<string, string> = { Authorization: `Bearer ${key}` };
  if (request.method === "POST" && joined === "cases") {
    // The user's own Anthropic key is attached only to consented, model-assisted investigations.
    const clone = request.clone();
    try {
      const parsed = await clone.json();
      if (parsed?.ai_planning === true && parsed?.cloud_ai_consent === true) {
        const byok = await currentByokKey();
        if (byok) headers["X-Anthropic-Api-Key"] = byok;
      }
    } catch {
      // The API returns the validation error.
    }
  }
  return forward(request, `/v1/${joined}`, headers);
}

export { handle as GET, handle as POST, handle as DELETE };
