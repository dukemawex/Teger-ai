import { afterEach, describe, expect, it, vi } from "vitest";
import { POST } from "./route";

function request(origin = "https://www.tegerai.tech", body = { content: "hello" }) {
  return new Request("https://www.tegerai.tech/api/scan", { method: "POST", body: JSON.stringify(body),
    headers: { "Content-Type": "application/json", origin, host: "www.tegerai.tech" } });
}
afterEach(() => vi.unstubAllGlobals());

describe("anonymous scanner gateway", () => {
  it("blocks cross-origin requests before reaching the engine", async () => {
    const fetcher = vi.fn(); vi.stubGlobal("fetch", fetcher);
    expect((await POST(request("https://attacker.example"))).status).toBe(403);
    expect(fetcher).not.toHaveBeenCalled();
  });
  it("relays genuine results without credentials or caching", async () => {
    const fetcher = vi.fn().mockResolvedValue(Response.json({ verdict: "suspicious" }));
    vi.stubGlobal("fetch", fetcher);
    const response = await POST(request());
    expect(await response.json()).toEqual({ verdict: "suspicious" });
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(fetcher.mock.calls[0][1].headers).toEqual({ "Content-Type": "application/json" });
    expect(fetcher.mock.calls[0][1].redirect).toBe("error");
  });
  it("preserves rate limiting and returns no verdict on outages", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("", { status: 429, headers: { "Retry-After": "30" } })));
    const limited = await POST(request());
    expect(limited.status).toBe(429);
    expect(limited.headers.get("retry-after")).toBe("30");
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("sensitive upstream details")));
    const unavailable = await POST(request());
    expect(unavailable.status).toBe(503);
    expect(await unavailable.text()).not.toContain("sensitive");
  });
});
