import os
import json
from openai import OpenAI

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def analyze_message(content: str, context: str = "") -> dict:
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a forensic linguist and cybersecurity analyst. "
                    "Detect social engineering, phishing, and psychological manipulation. "
                    "Analyze linguistic dissonance — the gap between claimed identity and actual intent. "
                    "Return a JSON object with: threat_level (low/medium/high/critical), "
                    "confidence (0-100), tactics (list), reasoning (string), recommended_action (string)."
                ),
            },
            {
                "role": "user",
                "content": f"Platform context: {context}\n\nMessage to analyze:\n{content}",
            },
        ],
        response_format={"type": "json_object"},
        temperature=0.2,
    )
    return json.loads(response.choices[0].message.content)
