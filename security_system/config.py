import os
from dotenv import load_dotenv

# Load .env from the project root (two levels up from this file)
_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(_root, ".env"))

GEMINI_API_KEY       = os.getenv("GEMINI_API_KEY", "")
VULNERABLE_APP_PORT  = int(os.getenv("VULNERABLE_APP_PORT", "9999"))
SECURITY_API_PORT    = int(os.getenv("SECURITY_API_PORT", "8000"))

# Free Gemini model — fast and completely free
# Get your key at: https://aistudio.google.com
GEMINI_MODEL = "gemini-1.5-flash"

# How many payloads the attacker sends per parameter
MAX_PAYLOADS_PER_PARAM = 5

if not GEMINI_API_KEY or GEMINI_API_KEY == "your-gemini-key-here":
    raise ValueError(
        "\n\n❌  GEMINI_API_KEY not set!\n"
        "   1. Go to: https://aistudio.google.com\n"
        "   2. Click 'Get API Key' (completely free, no credit card)\n"
        "   3. Open: security_project/.env\n"
        "   4. Replace 'your-gemini-key-here' with your real key\n"
    )