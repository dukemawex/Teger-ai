const TEGER_API_BASE = "https://your-render-backend.onrender.com";
// Set this to your deployed Render backend URL before loading the extension.

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type !== "ANALYZE_MESSAGE") {
    return;
  }

  fetch(`${TEGER_API_BASE}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      content: message.payload?.content || "",
      context: message.payload?.context || "",
    }),
  })
    .then(async (res) => {
      if (!res.ok) {
        const text = await res.text();
        throw new Error(text || "Backend request failed");
      }
      return res.json();
    })
    .then((data) => sendResponse({ ok: true, data }))
    .catch((error) => sendResponse({ ok: false, error: error.message }));

  return true;
});
