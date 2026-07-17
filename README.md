> 🏆 **Supported by the [OpenAI Cybersecurity Grant](https://openai.com/security)** — awarded to projects advancing AI-powered cyber defense.

# Teger AI 🛡️
> A browser & email plugin that highlights social-engineering cues, explains its reasoning,
> and builds an open dataset of phishing patterns.
> Supported by the OpenAI Cybersecurity Grant

## How It Works
Teger AI is Powered by OpenAI to perform forensic linguistic analysis on messages,
detecting psychological manipulation tactics like artificial urgency, authority spoofing,
and emotional anchoring — the techniques behind modern social engineering attacks.

## Architecture
See [docs/architecture.md](docs/architecture.md)

## Quick Start

### Prerequisites
- Python 3.10+
- Node.js 18+
- An OpenAI API key → https://platform.openai.com/api-keys
- A Render account (free tier works) → https://render.com
- Chrome browser

### 1. Clone
git clone https://github.com/dukemawex/Teger-ai.git
cd Teger-ai

### 2. Backend (Local Dev)
cd backend
cp .env.example .env
# Add your OPENAI_API_KEY to .env
pip install -r requirements.txt
uvicorn app:app --reload
# API runs at http://localhost:8000

### 3. Backend (Render Production)
- Push repo to GitHub
- Go to https://render.com → New Web Service → connect this repo
- Set root directory to /backend
- Render auto-detects render.yaml
- Add OPENAI_API_KEY and ALLOWED_ORIGINS in Render's Environment tab
- Deploy — your backend URL will be https://teger-ai-backend.onrender.com

### 4. Dashboard
cd dashboard
cp .env.example .env
# Set REACT_APP_API_URL to your Render backend URL
npm install
npm start
# Dashboard runs at http://localhost:3000

### 5. Chrome Extension
- Open chrome://extensions in Chrome
- Enable Developer Mode (top right toggle)
- Click "Load Unpacked" → select the /extension folder
- Open extension/background.js and set TEGER_API_BASE to your Render backend URL

### Chrome Web Store Submission
cd extension
zip -r ../teger-ai-extension.zip .
# Upload zip at https://chrome.google.com/webstore/devconsole

## Open Phishing-Pattern Dataset

Teger AI ships an **open, extensible dataset of phishing patterns** in [`/dataset`](dataset/README.md):
the social-engineering tactics behind modern attacks, each with concrete linguistic cues and a
plain-language explanation of *why* it is manipulation. Detector and dataset share one taxonomy
([`dataset/taxonomy.py`](dataset/taxonomy.py)), so a detected tactic maps directly to a documented
pattern — this is what lets the plugin **explain its reasoning** instead of just flagging.

```bash
python dataset/schema.py   # validate the dataset
python dataset/stats.py    # coverage by tactic / severity / source
```

Patterns are sanitized or synthetic (safe to publish). Contributions welcome —
see [CONTRIBUTING.md](CONTRIBUTING.md#contributing-phishing-patterns).

## API Reference
See [docs/api-reference.md](docs/api-reference.md)

## Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md)

## Security
See [SECURITY.md](SECURITY.md) — please report vulnerabilities responsibly

## License
MIT — See [LICENSE](LICENSE)
