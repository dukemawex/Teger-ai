const DEFAULT_API_BASE = "https://teger-ai-backend.onrender.com";

async function getApiBase() {
  const { apiBase } = await chrome.storage.local.get("apiBase");
  return (apiBase || DEFAULT_API_BASE).replace(/\/$/, "");
}

async function getInstallationToken() {
  const stored = await chrome.storage.local.get(["installationToken", "installationId"]);
  if (stored.installationToken) {
    return stored.installationToken;
  }

  const apiBase = await getApiBase();
  const response = await fetch(`${apiBase}/installations`, { method: "POST" });
  if (!response.ok) {
    throw new Error("Unable to register this Teger installation.");
  }

  const data = await response.json();
  if (!data?.token) {
    throw new Error("Teger installation registration returned an invalid response.");
  }

  await chrome.storage.local.set({
    installationToken: data.token,
    installationId: data.installation_id,
  });
  return data.token;
}

async function analyzeMessage(payload) {
  const apiBase = await getApiBase();
  const token = await getInstallationToken();

  const response = await fetch(`${apiBase}/analyze`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      content: payload?.content || "",
      context: payload?.context || "",
    }),
  });

  if (response.status === 401) {
    await chrome.storage.local.remove(["installationToken", "installationId"]);
    throw new Error("Teger session expired. Please scan again.");
  }

  if (!response.ok) {
    let message = "Analysis failed.";
    try {
      const body = await response.json();
      message = body?.detail || message;
    } catch (_) {
      // Preserve the generic message when the backend does not return JSON.
    }
    throw new Error(message);
  }

  return response.json();
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type !== "ANALYZE_MESSAGE") {
    return;
  }

  analyzeMessage(message.payload)
    .then((data) => sendResponse({ ok: true, data }))
    .catch((error) => sendResponse({ ok: false, error: error.message }));

  return true;
});
