# API Reference

## GET /health

Returns service status and MVP version.

Response:

    {
      "status": "ok",
      "version": "0.2.0"
    }

## POST /installations

Creates an anonymous installation identity and signed token for the browser extension or dashboard.

Response:

    {
      "installation_id": "91f98f0b-2b64-4b9f-9f08-cb9aafe1a340",
      "token": "91f98f0b-2b64-4b9f-9f08-cb9aafe1a340.<signature>"
    }

The token must be sent to protected endpoints with an Authorization: Bearer header.

## POST /analyze

Analyzes one explicitly submitted message for social-engineering and phishing indicators.

Request:

    {
      "content": "Please buy gift cards right now and send me the codes.",
      "context": "Gmail | Sender: ceo@company.com"
    }

Limits:

- content: 1–20,000 characters
- context: up to 1,000 characters
- authenticated using a signed installation token
- rate-limited by installation and source IP

Response:

    {
      "threat_level": "high",
      "confidence": 94,
      "tactics": ["authority_spoofing", "artificial_urgency"],
      "cues": ["buy gift cards right now", "send me the codes"],
      "signals": ["financial_request", "urgent_language"],
      "reasoning": "The message combines urgency with an unusual financial request.",
      "recommended_action": "Verify the request through a known trusted channel."
    }

## Error behavior

The API returns validation and authentication errors without exposing provider credentials, prompts, or message content. Upstream provider failures are returned as a generic 502 response.
