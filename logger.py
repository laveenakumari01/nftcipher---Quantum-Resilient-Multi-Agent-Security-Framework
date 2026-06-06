"""
logger.py

Enhanced Structured Logger with Integrity Hashing.

Before: basic logging to file + terminal.
Now:
  - Every log entry has a SHA3-256 integrity hash
  - Structured JSON log format for machine parsing
  - Severity levels: INFO, THREAT, BLOCKED, ALLOWED, DENIED, ATTACK, ERROR
  - SSE hook for real-time frontend streaming (unchanged interface)
  - Tamper detection — audit function verifies log integrity
"""

import logging
import os
import time
import json
import hashlib
from datetime import datetime

# ── Log Directory Setup ───────────────────────────────────
LOG_DIR  = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

LOG_FILE        = os.path.join(LOG_DIR, f"nftcipher_{datetime.now().strftime('%Y%m%d')}.log")
LOG_FILE_JSON   = os.path.join(LOG_DIR, f"nftcipher_{datetime.now().strftime('%Y%m%d')}.jsonl")

# Log signing key — generated once at startup
# Every entry hash includes this key so external tampering is detectable
_LOG_KEY = hashlib.sha256(f"nftcipher-log-{datetime.now().date()}".encode()).hexdigest()[:16]

# In-memory log buffer for integrity audit
_log_buffer: list = []
_MAX_BUFFER  = 500


# ── Standard Text Logger ──────────────────────────────────
logging.basicConfig(
    level   = logging.INFO,
    format  = "%(asctime)s | %(levelname)s | %(message)s",
    handlers = [
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(),
    ]
)
logger = logging.getLogger("NftCipher")


# ── SSE Hook — set by backend.py ──────────────────────────
_sse_push_fn = None

def set_sse_hook(fn):
    """Backend calls this so logger can push to SSE stream."""
    global _sse_push_fn
    _sse_push_fn = fn

def _push(event_type: str, message: str):
    if _sse_push_fn:
        try:
            _sse_push_fn(event_type, {"message": message, "raw": message})
        except Exception:
            pass


# ── Structured Entry Writer ───────────────────────────────

def _write_entry(level: str, message: str, icon: str = ""):
    """
    Write a structured log entry with integrity hash.
    Saves to both plain text log and JSON lines log.
    """
    timestamp  = time.time()
    entry_hash = hashlib.sha3_256(
        f"{_LOG_KEY}|{level}|{message}|{timestamp}".encode()
    ).hexdigest()[:32]

    entry = {
        "timestamp":   timestamp,
        "datetime":    datetime.utcfromtimestamp(timestamp).isoformat(),
        "level":       level,
        "message":     message,
        "hash":        entry_hash,
    }

    # Save to in-memory buffer for audit
    _log_buffer.append(entry)
    if len(_log_buffer) > _MAX_BUFFER:
        _log_buffer.pop(0)

    # Append to JSON lines file for machine parsing
    try:
        with open(LOG_FILE_JSON, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass

    return entry_hash


# ── Public Log Functions ──────────────────────────────────
# Same interface as before — no breaking changes

def log_info(message: str):
    """Normal information log."""
    _write_entry("INFO", message)
    logger.info(message)
    _push("INFO", message)


def log_threat(message: str):
    """Threat detected log."""
    _write_entry("THREAT", message)
    logger.warning(f"🚨 THREAT | {message}")
    _push("THREAT", f"🚨 {message}")


def log_blocked(message: str):
    """Agent or action blocked log."""
    _write_entry("BLOCKED", message)
    logger.error(f"🚫 BLOCKED | {message}")
    _push("BLOCKED", f"🚫 {message}")


def log_allowed(message: str):
    """Request allowed log."""
    _write_entry("ALLOWED", message)
    logger.info(f"✅ ALLOWED | {message}")
    _push("ALLOWED", f"✅ {message}")


def log_denied(message: str):
    """Request denied log."""
    _write_entry("DENIED", message)
    logger.warning(f"❌ DENIED | {message}")
    _push("DENIED", f"❌ {message}")


def log_attack(message: str):
    """Attack simulation log."""
    _write_entry("ATTACK", message)
    logger.warning(f"💀 ATTACK | {message}")
    _push("ATTACK", f"💀 {message}")


def log_error(message: str):
    """Error log."""
    _write_entry("ERROR", message)
    logger.error(f"❌ ERROR | {message}")
    _push("ERROR", f"❌ {message}")


# ── Audit Function ────────────────────────────────────────

def audit_log_integrity(entries: list = None) -> dict:
    """
    Verify integrity of log entries.
    Recomputes hash for each entry and checks for tampering.

    entries: list of log dicts (from _log_buffer or JSON file)
             if None — uses in-memory buffer
    """
    entries  = entries or list(_log_buffer)
    ok       = 0
    tampered = []

    for entry in entries:
        expected = hashlib.sha3_256(
            f"{_LOG_KEY}|{entry['level']}|{entry['message']}|{entry['timestamp']}".encode()
        ).hexdigest()[:32]

        if entry.get("hash") == expected:
            ok += 1
        else:
            tampered.append({
                "timestamp": entry.get("timestamp"),
                "level":     entry.get("level"),
                "message":   entry.get("message", "")[:50],
                "status":    "TAMPERED",
            })

    return {
        "total":            len(entries),
        "ok":               ok,
        "tampered":         len(tampered),
        "tampered_entries": tampered,
        "integrity":        "PASS" if not tampered else "FAIL",
        "audit_time":       time.time(),
    }


def get_recent_logs(limit: int = 50, level: str = None) -> list:
    """
    Get recent log entries from in-memory buffer.
    Optionally filter by level: INFO, THREAT, BLOCKED, etc.
    """
    entries = list(_log_buffer)[-limit:]
    if level:
        entries = [e for e in entries if e.get("level") == level.upper()]
    return entries


def get_log_stats() -> dict:
    """Log statistics for dashboard."""
    by_level = {}
    for entry in _log_buffer:
        lvl = entry.get("level", "UNKNOWN")
        by_level[lvl] = by_level.get(lvl, 0) + 1

    return {
        "total_in_buffer": len(_log_buffer),
        "by_level":        by_level,
        "log_file":        LOG_FILE,
        "json_log_file":   LOG_FILE_JSON,
        "integrity_key":   _LOG_KEY[:8] + "...",
        "features": {
            "integrity_hashing": True,
            "structured_json":   True,
            "sse_streaming":     _sse_push_fn is not None,
        },
    }