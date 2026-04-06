function injectTegerButton() {
  const containers = document.querySelectorAll('.ii.gt, .c-message__body');

  containers.forEach((container) => {
    if (container.querySelector('.teger-scan-btn')) {
      return;
    }

    const btn = document.createElement('button');
    btn.className = 'teger-scan-btn';
    btn.textContent = '🛡️ Scan with Teger AI';
    btn.style.margin = '8px 0';
    btn.style.padding = '6px 10px';
    btn.style.borderRadius = '6px';
    btn.style.border = '1px solid #2563eb';
    btn.style.background = '#eff6ff';
    btn.style.cursor = 'pointer';

    btn.onclick = () => {
      const text = container.innerText || '';
      const sender = document.querySelector('.gD')?.innerText || 'Unknown Sender';
      const platform = window.location.host.includes('slack') ? 'Slack' : 'Gmail';

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
          alert('Teger AI: Message captured. Open the extension popup to analyze.');
        }
      );
    };

    container.prepend(btn);
  });
}

const observer = new MutationObserver(injectTegerButton);
observer.observe(document.body, { childList: true, subtree: true });
injectTegerButton();
