"""
Central Logger - Replaces print statements
Saves logs to file + shows on terminal
Future: Backend/Frontend integration ready — logs can be sent via API
"""
import logging
import os
from datetime import datetime

# Create logs folder
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

# Log file name — with current date
LOG_FILE = os.path.join(LOG_DIR, f"nftcipher_{datetime.now().strftime('%Y%m%d')}.log")

# Logger setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),   # save into file
        logging.StreamHandler()                             # also show on terminal
    ]
)

logger = logging.getLogger("NftCipher")

# ── SSE Hook — optional, set by backend.py ────────────────
_sse_push_fn = None

def set_sse_hook(fn):
    """Backend.py yeh call karta hai taake logger SSE mein push kar sake."""
    global _sse_push_fn
    _sse_push_fn = fn

def _push(event_type: str, message: str):
    if _sse_push_fn:
        try:
            _sse_push_fn(event_type, {"message": message, "raw": message})
        except Exception:
            pass


def log_info(message: str):
    """Normal information log"""
    logger.info(message)
    _push("INFO", message)


def log_threat(message: str):
    """Threat detected log"""
    logger.warning(f"🚨 THREAT | {message}")
    _push("THREAT", f"🚨 {message}")


def log_blocked(message: str):
    """Agent blocked log"""
    logger.error(f"🚫 BLOCKED | {message}")
    _push("BLOCKED", f"🚫 {message}")


def log_allowed(message: str):
    """Request allowed log"""
    logger.info(f"✅ ALLOWED | {message}")
    _push("ALLOWED", f"✅ {message}")


def log_denied(message: str):
    """Request denied log"""
    logger.warning(f"❌ DENIED | {message}")
    _push("DENIED", f"❌ {message}")


def log_attack(message: str):
    """Attack simulation log"""
    logger.warning(f"💀 ATTACK | {message}")
    _push("ATTACK", f"💀 {message}")


def log_error(message: str):
    """Error log"""
    logger.error(f"❌ ERROR | {message}")
    _push("ERROR", f"❌ {message}")