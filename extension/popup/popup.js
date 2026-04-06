const statusEl = document.getElementById('status');
const scanBtn = document.getElementById('scan-btn');
const resultsEl = document.getElementById('results');
const threatLevelEl = document.getElementById('threat-level');
const confidenceEl = document.getElementById('confidence');
const tacticsEl = document.getElementById('tactics');
const reasoningEl = document.getElementById('reasoning');
const recommendedActionEl = document.getElementById('recommended-action');

async function loadCapturedMessage() {
  const data = await chrome.storage.local.get('pendingScan');
  if (data.pendingScan?.content) {
    statusEl.textContent = `Captured ${data.pendingScan.platform || 'message'} content. Ready to analyze.`;
    scanBtn.disabled = false;
    return data.pendingScan;
  }

  statusEl.textContent = 'No message captured. Use the in-page scan button first.';
  scanBtn.disabled = true;
  return null;
}

function renderResult(result) {
  threatLevelEl.textContent = result.threat_level || '-';
  confidenceEl.textContent = String(result.confidence ?? '-');
  tacticsEl.textContent = Array.isArray(result.tactics) ? result.tactics.join(', ') : '-';
  reasoningEl.textContent = result.reasoning || '-';
  recommendedActionEl.textContent = result.recommended_action || '-';
  resultsEl.hidden = false;
}

scanBtn.addEventListener('click', async () => {
  const payload = await loadCapturedMessage();
  if (!payload) {
    return;
  }

  scanBtn.disabled = true;
  statusEl.textContent = 'Analyzing message...';

  chrome.runtime.sendMessage(
    {
      type: 'ANALYZE_MESSAGE',
      payload: {
        content: payload.content,
        context: payload.context,
      },
    },
    (response) => {
      if (chrome.runtime.lastError) {
        statusEl.textContent = chrome.runtime.lastError.message;
        scanBtn.disabled = false;
        return;
      }

      if (!response?.ok) {
        statusEl.textContent = response?.error || 'Analysis failed.';
        scanBtn.disabled = false;
        return;
      }

      statusEl.textContent = 'Analysis complete.';
      renderResult(response.data || {});
      scanBtn.disabled = false;
    }
  );
});

loadCapturedMessage();
