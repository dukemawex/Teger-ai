function extractMessageText(container) {
  const clone = container.cloneNode(true);
  clone.querySelectorAll(".teger-scan-btn").forEach((button) => button.remove());
  return (clone.innerText || "").trim();
}

function findSender(container, platform) {
  if (platform === "Gmail") {
    const messageRoot = container.closest(".adn, .gs") || document;
    return (
      messageRoot.querySelector(".gD")?.getAttribute("email") ||
      messageRoot.querySelector(".gD")?.innerText ||
      "Unknown Sender"
    );
  }

  const messageRoot = container.closest(".c-message_kit__message") || document;
  return (
    messageRoot.querySelector(".c-message__sender_button")?.innerText ||
    messageRoot.querySelector(".c-message_kit__sender")?.innerText ||
    "Unknown Sender"
  );
}

function injectTegerButton() {
  const containers = document.querySelectorAll(".ii.gt, .c-message__body");

  containers.forEach((container) => {
    if (container.querySelector(".teger-scan-btn")) {
      return;
    }

    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "teger-scan-btn";
    btn.textContent = "🛡️ Scan with Teger AI";
    btn.setAttribute("aria-label", "Analyze this message with Teger AI");
    btn.style.margin = "8px 0";
    btn.style.padding = "6px 10px";
    btn.style.borderRadius = "6px";
    btn.style.border = "1px solid #2563eb";
    btn.style.background = "#eff6ff";
    btn.style.color = "#0f172a";
    btn.style.fontWeight = "600";
    btn.style.cursor = "pointer";

    btn.onclick = () => {
      const platform = window.location.host.includes("slack") ? "Slack" : "Gmail";
      const text = extractMessageText(container);
      const sender = findSender(container, platform);

      if (!text) {
        alert("Teger AI: No message text was found to analyze.");
        return;
      }

      chrome.storage.local.set(
        {
          pendingScan: {
            content: text,
            context: `${platform} | Sender: ${sender}`,
            sender,
            platform,
          },
        },
        () => {
          alert("Teger AI: Message captured. Open the extension popup to analyze.");
        }
      );
    };

    container.prepend(btn);
  });
}

const observer = new MutationObserver(injectTegerButton);
observer.observe(document.body, { childList: true, subtree: true });
injectTegerButton();
