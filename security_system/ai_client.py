"""
AI CLIENT — Google Gemini (Free)
─────────────────────────────────
All three AI agents (Attacker, Analyzer, Reporter) import
call_ai() from here. This is the only file that talks to Gemini.

Get your FREE API key at: https://aistudio.google.com
No credit card. 1,500 requests/day free.
"""

import google.generativeai as genai
from security_system.config import GEMINI_API_KEY, GEMINI_MODEL

# Configure Gemini once at import time
genai.configure(api_key=GEMINI_API_KEY)
_model = genai.GenerativeModel(GEMINI_MODEL)


def call_ai(prompt: str, max_tokens: int = 2048) -> str:
    """
    Send a prompt to Gemini and return the text response.

    Args:
        prompt:     The full prompt string to send
        max_tokens: Max output length (default 2048)

    Returns:
        The model's response as a plain string
    """
    response = _model.generate_content(
        prompt,
        generation_config=genai.types.GenerationConfig(
            max_output_tokens=max_tokens,
            temperature=0.2,    # Low temperature = more consistent JSON output
        ),
    )
    return response.text.strip()