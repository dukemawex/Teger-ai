# Contributing to Teger AI

## Fork and Local Setup
1. Fork this repository and clone your fork.
2. Backend setup:
   - `cd backend`
   - `cp .env.example .env`
   - Add `OPENAI_API_KEY` and set `ALLOWED_ORIGINS`.
   - `pip install -r requirements.txt`
3. Dashboard setup:
   - `cd dashboard`
   - `cp .env.example .env`
   - Set `REACT_APP_API_URL` to your backend URL.
   - `npm install`
4. Load the extension from `/extension` in `chrome://extensions`.

## Branch Naming
- `feat/<short-description>`
- `fix/<short-description>`
- `docs/<short-description>`

## Pull Request Checklist
- [ ] No hardcoded API keys or secrets
- [ ] Relevant tests/build checks pass
- [ ] Documentation updated for behavior/config changes

## AI Provider Policy
All AI inference in Teger AI must go through OpenAI only.
Do not add other AI providers.
