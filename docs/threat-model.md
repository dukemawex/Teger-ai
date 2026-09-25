# Threat Model

## Protected Assets

- user credentials and secrets
- financial approval workflows
- internal communication trust channels
- provider API credentials
- selected private message content
- integrity of Teger risk assessments

## Primary Threats

- social engineering and phishing
- authority spoofing and business email compromise
- artificial urgency and coercion
- credential harvesting
- payment redirection
- prompt injection embedded inside attacker-controlled messages
- unauthorized use of the public analysis API
- excessive API usage that consumes provider quota
- accidental storage or disclosure of private communications

## Trust Boundaries

- Gmail or Slack page DOM
- Chrome extension content script
- Chrome extension service worker
- backend API
- AI provider boundary
- browser local storage
- dashboard browser context

## MVP Security Controls

- provider secrets are loaded from backend environment variables only
- OpenAI credentials are never embedded in extension or dashboard code
- clients receive HMAC-signed anonymous installation tokens
- analyze requests require a valid Bearer token
- scan requests are rate-limited by both installation and source IP
- installation creation is independently rate-limited
- message and context length are bounded by Pydantic validation
- CORS origins are configured through ALLOWED_ORIGINS
- attacker-controlled message text is explicitly marked as untrusted data in the model prompt
- instructions inside analyzed messages are never intended to control the detector
- deterministic signals are treated as hints rather than proof
- model output is validated against a typed AnalysisResult schema
- tactics not present in the shared taxonomy are removed
- upstream errors are converted to generic client errors
- local history excludes raw message bodies
- CI performs linting, regression tests, dataset validation, dashboard builds, and secret scanning

## Current MVP Limitations

- in-memory rate limiting is process-local and should be replaced with a shared store such as Redis before multi-instance deployment
- Gmail and Slack DOM selectors may change and require regression testing
- sender identity displayed in the page is context, not cryptographic proof of identity
- AI confidence is a model output and must not be treated as a calibrated probability without evaluation
- the MVP does not yet perform attachment detonation, mailbox authentication checks, or full URL reputation lookups
