# Architecture

Teger AI has three layers:

1. **Chrome Extension (`/extension`)**
   - Captures suspicious message context from Gmail and Slack.
   - Sends message content to backend for analysis.

2. **Backend API (`/backend`)**
   - FastAPI service exposing `/health` and `/analyze`.
   - Uses OpenAI GPT-4o to detect social engineering and phishing signals.

3. **Dashboard (`/dashboard`)**
   - React interface for SOC-style manual analysis.
   - Calls backend API via `REACT_APP_API_URL`.

## Data Flow

1. User captures a message in Gmail/Slack with the extension.
2. Extension posts message data to backend `/analyze`.
3. Backend returns structured JSON with threat assessment.
4. Extension and dashboard render results for user action.
