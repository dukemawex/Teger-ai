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

## Contributing Phishing Patterns

The open dataset lives in [`/dataset`](dataset/README.md). To add a pattern:

1. **Pick the tactic.** Use an existing slug in [`dataset/taxonomy.py`](dataset/taxonomy.py).
   If none fits, add a new slug + one-line description there first (keep it general).
2. **Add the example.** Append one JSON object per line to a file in `dataset/patterns/*.jsonl`.
   Required fields: `id` (next free `TP-XXXX`), `tactic`, `title`, `example_text`,
   `linguistic_cues` (non-empty), `severity`, `source_type`, `explanation` (the reasoning).
3. **Keep it safe and legal.** Examples must be **sanitized or synthetic**. Do not submit
   real victims' messages, real credentials, live malicious URLs, or personal data.
   Defang links (e.g. `hxxp://`) or use `example.com`-style placeholders.
4. **Validate.** Run `python dataset/schema.py` — it must print `OK`. Then `python -m pytest dataset/`.
5. Open a PR with `feat/dataset-<tactic>` and a note on the tactic and source.

The dataset is defensive and educational. Contributions that could serve as an attack
toolkit (working phishing kits, live infrastructure) will be rejected.
