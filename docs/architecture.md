# Architecture

Teger AI MVP v0.2 has four product layers.

## 1. Chrome Extension

- Injects an explicit **Scan with Teger AI** action into supported Gmail and Slack message surfaces.
- Captures only the message selected by the user.
- Removes Teger UI text before extraction.
- Stores an anonymous signed installation token in Chrome local storage.
- Sends selected content to the backend over HTTPS.
- Stores recent scan metadata and user feedback locally without persisting raw message text in scan history.

## 2. Backend API

FastAPI exposes GET /health, POST /installations, and POST /analyze.

Security controls include:

- environment-only provider secrets
- HMAC-signed anonymous installation tokens
- request-size validation
- per-installation and per-IP rate limiting
- restricted CORS configuration
- generic upstream error handling
- no OpenAI key in browser code

## 3. Detection Pipeline

    Selected message
          |
          v
    Deterministic signal extraction
          |
          +-- urgency
          +-- credential request
          +-- financial request
          +-- authority claim
          +-- secrecy/process bypass
          +-- URL shape
          |
          v
    AI forensic analysis
          |
          v
    Validated AnalysisResult
          |
          +-- threat level
          +-- confidence
          +-- tactics
          +-- cues
          +-- deterministic signals
          +-- reasoning
          +-- recommended action

The message is marked as **untrusted attacker-controlled data** at the model boundary. Instructions inside the message are never treated as instructions for Teger.

## 4. Security Console

The React dashboard supports authenticated manual analysis and renders risk level, confidence, tactics, suspicious cues, reasoning, recommended action, local scan metrics, and local feedback.

Raw message content is intentionally excluded from browser history entries.

## Data Flow

1. A user explicitly selects a suspicious message.
2. The client creates or reuses a signed anonymous installation identity.
3. The client submits the selected message to POST /analyze.
4. The backend extracts deterministic signals.
5. The AI detector analyzes the message as untrusted data.
6. Pydantic validates the returned structure and taxonomy.
7. The extension or dashboard renders the explanation and recommended action.
8. Only scan metadata and optional feedback are retained locally by the MVP client.
