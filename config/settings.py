"""
config/settings.py
Sab settings yahan se aati hain — .env se load hoti hain
"""
import os
from dotenv import load_dotenv

load_dotenv()

# ── LLM (OpenRouter) ──────────────────────────────────────
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
LLM_MODEL = os.getenv("LLM_MODEL", "openrouter/free")

# ── Backend ───────────────────────────────────────────────
BACKEND_URL  = os.getenv("BACKEND_URL",  "http://localhost:8000")
BACKEND_USER = os.getenv("BACKEND_USER", "john.doe")
BACKEND_PASS = os.getenv("BACKEND_PASS", "secret")

MOCK_MODE = os.getenv("MOCK_MODE", "false").lower() == "true"