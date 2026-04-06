# Threat Model

## Protected Assets
- User credentials
- Financial approval workflows
- Internal communication trust channels

## Primary Threats
- Social engineering and phishing
- Authority spoofing
- Artificial urgency and pressure tactics
- Credential harvesting attempts

## Trust Boundaries
- Browser extension context
- Backend API boundary
- OpenAI API boundary

## Security Controls
- Secrets managed via environment variables only
- CORS restricted through `ALLOWED_ORIGINS`
- No hardcoded API keys in source code
- CI secret scanning via TruffleHog
