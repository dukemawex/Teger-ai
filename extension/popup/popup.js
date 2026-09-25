const statusEl = document.getElementById("status");
const scanBtn = document.getElementById("scan-btn");
const resultsEl = document.getElementById("results");
const threatLevelEl = document.getElementById("threat-level");
const confidenceEl = document.getElementById("confidence");
const tacticsEl = document.getElementById("tactics");
const cuesEl = document.getElementById("cues");
const reasoningEl = document.getElementById("reasoning");
const recommendedActionEl = document.getElementById("recommended-action");
const accurateBtn = document.getElementById("accurate-btn");
const falsePositiveBtn = document.getElementById("false-positive-btn");
const feedbackStatusEl = document.getElementById("feedback-status");

let currentHistoryId = null;

async function loadCapturedMessage() {
  const data = await chrome.storage.local.get("pendingScan");
  if (data.pendingScan?.content) {
    statusEl.textContent = `Captured ${data.pendingScan.platform || "message"} content. Ready to analyze.`;
    scanBtn.disabled = false;
    return data.pendingScan;
  }

  statusEl.textContent = "No message captured. Use the in-page Teger scan button first.";
  scanBtn.disabled = true;
  return null;
}

function titleCase(value) {
  return String(value || "")
    .replaceAll("_", " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function renderResult(result) {
  const threat = result.threat_level || "unknown";
  threatLevelEl.textContent = titleCase(threat);
  threatLevelEl.dataset.level = threat;
  confidenceEl.textContent = String(result.confidence ?? "-");

  tacticsEl.replaceChildren();
  (result.tactics || []).forEach((tactic) => {
    const chip = document.createElement("span");
    chip.className = "chip";
    chip.textContent = titleCase(tactic);
    tacticsEl.appendChild(chip);
  });
  if (!tacticsEl.children.length) {
    tacticsEl.textContent = "No known manipulation tactic detected.";
  }

  cuesEl.replaceChildren();
  (result.cues || []).forEach((cue) => {
    const item = document.createElement("li");
    item.textContent = cue;
    cuesEl.appendChild(item);
  });
  if (!cuesEl.children.length) {
    const item = document.createElement("li");
    item.textContent = "No concrete suspicious cue returned.";
    cuesEl.appendChild(item);
  }

  reasoningEl.textContent = result.reasoning || "-";
  recommendedActionEl.textContent = result.recommended_action || "-";
  feedbackStatusEl.textContent = "";
  resultsEl.hidden = false;
}

async function saveHistory(payload, result) {
  const stored = await chrome.storage.local.get("scanHistory");
  const history = Array.isArray(stored.scanHistory) ? stored.scanHistory : [];
  const id = crypto.randomUUID();

  history.unshift({
    id,
    createdAt: new Date().toISOString(),
    platform: payload.platform || "Unknown",
    sender: payload.sender || "Unknown sender",
    threatLevel: result.threat_level,
    confidence: result.confidence,
    tactics: result.tactics || [],
    feedback: null,
  });

  await chrome.storage.local.set({ scanHistory: history.slice(0, 25) });
  currentHistoryId = id;
}

async function recordFeedback(value) {
  if (!currentHistoryId) return;
  const stored = await chrome.storage.local.get("scanHistory");
  const history = Array.isArray(stored.scanHistory) ? stored.scanHistory : [];
  const next = history.map((entry) =>
    entry.id === currentHistoryId ? { ...entry, feedback: value } : entry
  );
  await chrome.storage.local.set({ scanHistory: next });
  feedbackStatusEl.textContent = "Feedback saved locally for this MVP.";
}

accurateBtn.addEventListener("click", () => recordFeedback("accurate"));
falsePositiveBtn.addEventListener("click", () => recordFeedback("false_positive"));

scanBtn.addEventListener("click", async () => {
  const payload = await loadCapturedMessage();
  if (!payload) return;

  scanBtn.disabled = true;
  resultsEl.hidden = true;
  statusEl.textContent = "Analyzing untrusted message content...";

  chrome.runtime.sendMessage(
    {
      type: "ANALYZE_MESSAGE",
      payload: {
        content: payload.content,
        context: payload.context,
      },
    },
    async (response) => {
      if (chrome.runtime.lastError) {
        statusEl.textContent = chrome.runtime.lastError.message;
        scanBtn.disabled = false;
        return;
      }

      if (!response?.ok) {
        statusEl.textContent = response?.error || "Analysis failed.";
        scanBtn.disabled = false;
        return;
      }

      statusEl.textContent = "Analysis complete.";
      renderResult(response.data || {});
      await saveHistory(payload, response.data || {});
      scanBtn.disabled = false;
    }
  );
});

loadCapturedMessage();
