"""
config/settings.py
All settings are loaded from here using the .env file

New additions:
  - PQC settings
  - ChromaDB (VectorDB)
  - Redis (Vectorless cache)
  - LangGraph
"""
import os
from dotenv import load_dotenv

load_dotenv()

# ── LLM (OpenRouter) ──────────────────────────────────────
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
LLM_MODEL          = os.getenv("LLM_MODEL", "openrouter/free")

# ── Backend ───────────────────────────────────────────────
BACKEND_URL  = os.getenv("BACKEND_URL",  "http://localhost:8000")
BACKEND_USER = os.getenv("BACKEND_USER", "john.doe")
BACKEND_PASS = os.getenv("BACKEND_PASS", "secret")
MOCK_MODE    = os.getenv("MOCK_MODE", "false").lower() == "true"

# ── PQC Settings ──────────────────────────────────────────
# Real PQC mode automatically turns ON if liboqs-python is installed
# Set FORCE_FALLBACK_PQC = true if you do not want to install liboqs
FORCE_FALLBACK_PQC   = os.getenv("FORCE_FALLBACK_PQC", "false").lower() == "true"
PQC_KEY_ROTATION_SEC = int(os.getenv("PQC_KEY_ROTATION_SEC", "1800"))  # 30 minutes

# ── ChromaDB (Vector Database — for RAG) ─────────────────
# Local mode: data is stored on the same machine
# Production mode: set CHROMA_HOST and CHROMA_PORT for a remote server
CHROMA_MODE      = os.getenv("CHROMA_MODE", "local")       # "local" or "remote"
CHROMA_HOST      = os.getenv("CHROMA_HOST", "localhost")
CHROMA_PORT      = int(os.getenv("CHROMA_PORT", "8001"))
CHROMA_DB_PATH   = os.getenv("CHROMA_DB_PATH", "./chroma_db")  # path for local mode
EMBEDDING_MODEL  = os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")  # sentence-transformers

# ── Redis (Vectorless fast cache) ─────────────────────────
REDIS_HOST     = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT     = int(os.getenv("REDIS_PORT", "6379"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")
REDIS_DB       = int(os.getenv("REDIS_DB", "0"))
# If Redis is not available, an in-memory fallback will be used
REDIS_ENABLED  = os.getenv("REDIS_ENABLED", "true").lower() == "true"

# ── LangGraph ─────────────────────────────────────────────
# LangGraph uses SQLite by default for state persistence
LANGGRAPH_CHECKPOINTER = os.getenv("LANGGRAPH_CHECKPOINTER", "sqlite")
LANGGRAPH_DB_PATH      = os.getenv("LANGGRAPH_DB_PATH", "./langgraph_state.db")

# ── Computer Vision ───────────────────────────────────────
# YOLO model sizes:
# n = nano (fast)
# s = small
# m = medium
# l = large
# x = xlarge (more accurate)
YOLO_MODEL_SIZE  = os.getenv("YOLO_MODEL_SIZE", "n")
CV_CONFIDENCE    = float(os.getenv("CV_CONFIDENCE", "0.5"))
# If OpenCV is not installed, the Vision Agent works in simulated mode
VISION_MODE      = os.getenv("VISION_MODE", "auto")  # "auto", "real", "simulated"

# ── Verification Engine thresholds ────────────────────────
# These values decide what action should be taken based on the agent result
VERIFY_AUTO_BLOCK_SCORE = float(os.getenv("VERIFY_AUTO_BLOCK_SCORE", "0.80"))
VERIFY_ALERT_SCORE      = float(os.getenv("VERIFY_ALERT_SCORE",      "0.50"))
VERIFY_WATCHLIST_SCORE  = float(os.getenv("VERIFY_WATCHLIST_SCORE",  "0.25"))