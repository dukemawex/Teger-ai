> 🏆 **Supported by the OpenAI Cybersecurity Grant** — awarded to projects advancing AI-powered cyber defense.

# Teger AI 🛡️

**MVP v0.2 — Private Beta**

Teger AI is an explainable social-engineering defense layer for suspicious email and chat messages. It detects manipulation tactics, surfaces the concrete cues behind the warning, and gives the user a safe next action.

## What the MVP does

- Scans user-selected Gmail and Slack messages
- Detects social-engineering tactics using a shared threat taxonomy
- Extracts deterministic risk signals before AI analysis
- Treats message content as untrusted attacker-controlled data
- Returns risk level, confidence, tactics, cues, reasoning, and recommended action
- Uses signed anonymous installation tokens instead of exposing provider credentials
- Applies per-installation and per-IP scan rate limits
- Stores local scan history as metadata only; raw message text is not added to browser history
- Includes a security-console dashboard for manual analysis and local feedback

## Architecture

See docs/architecture.md.

## Quick Start

### Prerequisites

- Python 3.10+
- Node.js 18+
- An OpenAI API key
- Chrome

### 1. Clone

    git clone https://github.com/dukemawex/Teger-ai.git
    cd Teger-ai

### 2. Backend

    cd backend
    cp .env.example .env
    pip install -r requirements.txt

Set at minimum:

    OPENAI_API_KEY=...
    APP_SECRET=use-a-long-random-secret
    ALLOWED_ORIGINS=http://localhost:3000

Then run:

    uvicorn app:app --reload

The API starts at http://localhost:8000.

### 3. Dashboard

    cd dashboard
    cp .env.example .env
    npm install
    npm start

Set REACT_APP_API_URL to the backend URL.

### 4. Chrome Extension

- Open chrome://extensions
- Enable Developer Mode
- Choose **Load unpacked**
- Select the extension directory
- Open Gmail or Slack and use **Scan with Teger AI**

The extension defaults to https://teger-ai-backend.onrender.com. For local development, set an apiBase value in extension local storage to http://localhost:8000.

## API protection

The browser extension never contains the OpenAI API key. It first obtains a signed anonymous installation token from POST /installations, then sends that token as a Bearer token to POST /analyze.

The backend also limits requests by both installation and source IP.

## Open phishing-pattern dataset

Teger ships an open, extensible dataset of social-engineering patterns in the dataset directory. Detector and dataset share one taxonomy, so a detected tactic maps directly to a documented pattern.

    python dataset/schema.py
    python dataset/stats.py

Patterns are sanitized or synthetic. Contributions must not include victim data, credentials, or live malicious links.

## Tests

    pip install -r backend/requirements.txt -r backend/requirements-dev.txt
    python -m pytest -q backend/
    python -m pytest -q dataset/

GitHub Actions runs backend linting, backend regression tests, dashboard build checks, secret scanning, and dataset validation.

## Privacy

See PRIVACY.md. Teger analyzes only content the user explicitly submits. The MVP does not persist raw message text in its local scan history.

## API Reference

See docs/api-reference.md.

## Security

See SECURITY.md and docs/threat-model.md.

## License

MIT — See LICENSE.
