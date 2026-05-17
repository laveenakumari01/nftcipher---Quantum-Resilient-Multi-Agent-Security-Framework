"""
config/settings.py
Sab settings yahan se aati hain — .env se load hoti hain
"""
import os
from dotenv import load_dotenv

load_dotenv()

# ── LLM (OpenRouter) ──────────────────────────────────────
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")

# Primary model — OpenRouter pe available free models (2025-2026)
# Agar yeh 404 de toh FALLBACK_MODELS try hote hain (base_agent.py mein)
# openrouter/free = Official OpenRouter free-model auto-router (launched Feb 2026)
# Automatically picks the best available free model for each request
# Docs: https://openrouter.ai/openrouter/free
LLM_MODEL = os.getenv("LLM_MODEL", "openrouter/free")

# ── Backend ───────────────────────────────────────────────
BACKEND_URL  = os.getenv("BACKEND_URL",  "http://localhost:8000")
BACKEND_USER = os.getenv("BACKEND_USER", "john.doe")
BACKEND_PASS = os.getenv("BACKEND_PASS", "secret")

MOCK_MODE = os.getenv("MOCK_MODE", "false").lower() == "true"