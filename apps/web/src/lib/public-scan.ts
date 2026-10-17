export const MAX_SCAN_BYTES = 64 * 1024;

export class ScanInputError extends Error {
  constructor(message: string, public status = 400) { super(message); }
}

/** Bound streamed input before JSON parsing, including requests without Content-Length. */
export async function readScanInput(request: Request): Promise<string> {
  if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json"))
    throw new ScanInputError("Send a JSON request.", 415);
  const reader = request.body?.getReader();
  if (!reader) throw new ScanInputError("Enter a message or URL.");
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_SCAN_BYTES) {
        await reader.cancel();
        throw new ScanInputError("This submission is too large. Shorten it and try again.", 413);
      }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  let body: Record<string, unknown>;
  try { body = JSON.parse(new TextDecoder().decode(bytes)); }
  catch { throw new ScanInputError("The submission could not be read."); }
  if (!body || typeof body !== "object" || Array.isArray(body))
    throw new ScanInputError("Enter a message or URL.");
  const limits: Record<string, number> = { url: 2048, content: 20000, sender: 320, subject: 998 };
  const cleaned: Record<string, string> = {};
  for (const [field, limit] of Object.entries(limits)) {
    if (body[field] == null) continue;
    if (typeof body[field] !== "string" || (body[field] as string).length > limit)
      throw new ScanInputError(`Check the ${field} field (maximum ${limit} characters).`);
    cleaned[field] = (body[field] as string).trim();
  }
  if (!cleaned.url && !cleaned.content) throw new ScanInputError("Enter a message or URL to investigate.");
  const type = body.content_type ?? "other";
  if (typeof type !== "string" || !["email", "chat", "sms", "web", "other"].includes(type))
    throw new ScanInputError("Choose a supported content type.");
  // An allowlist ensures the public gateway never relays credentials, AI requests or tenant fields.
  return JSON.stringify({ ...cleaned, content_type: type });
}
