import os
import json

from openai import OpenAI

# Shared taxonomy: detection and the open dataset speak the same vocabulary, so a
# detected tactic maps directly to a documented pattern.
try:
    # when run from repo root
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dataset"))
    from taxonomy import TACTICS, SEVERITY
except Exception:  # pragma: no cover - fallback if path differs
    TACTICS, SEVERITY = {}, ("low", "medium", "high", "critical")

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

_TAXONOMY_BLOCK = "\n".join(f"- {slug}: {desc}" for slug, desc in TACTICS.items())


def _system_prompt() -> str:
    return (
        "You are a forensic linguist and cybersecurity analyst. Detect social "
        "engineering, phishing, and psychological manipulation by analyzing the gap "
        "between claimed identity and actual intent.\n\n"
        "Classify tactics ONLY using this fixed taxonomy (use the exact slugs):\n"
        f"{_TAXONOMY_BLOCK}\n\n"
        "Return a JSON object with:\n"
        "  threat_level: one of low/medium/high/critical\n"
        "  confidence: integer 0-100\n"
        "  tactics: list of taxonomy slugs that apply\n"
        "  cues: list of the concrete linguistic signals you observed (quote them)\n"
        "  reasoning: a plain-language explanation a non-expert can follow\n"
        "  recommended_action: what the user should do\n"
        "Every tactic you list MUST be justified by at least one cue."
    )


def analyze_message(content: str, context: str = "") -> dict:
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": _system_prompt()},
            {"role": "user", "content": f"Platform context: {context}\n\nMessage to analyze:\n{content}"},
        ],
        response_format={"type": "json_object"},
        temperature=0.2,
    )
    result = json.loads(response.choices[0].message.content)
    # Keep only taxonomy-valid tactics so detector output stays aligned with the dataset.
    if TACTICS and isinstance(result.get("tactics"), list):
        result["tactics"] = [t for t in result["tactics"] if t in TACTICS]
    return result
