# API Reference

## `GET /health`
Returns service health.

### Response
```json
{ "status": "ok" }
```

## `POST /analyze`
Analyzes message content for social engineering and phishing indicators.

### Request Body
```json
{
  "content": "Please buy gift cards right now and send me the codes.",
  "context": "Gmail | Sender: ceo@company.com"
}
```

### Response
```json
{
  "threat_level": "high",
  "confidence": 92,
  "tactics": ["authority spoofing", "artificial urgency"],
  "reasoning": "The sender pressures immediate action and bypasses normal process.",
  "recommended_action": "Verify through a second channel before responding."
}
```
