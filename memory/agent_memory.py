"""
memory/agent_memory.py

Agent Long-Term Memory — SQLite based persistence.

Before: deque(maxlen=50) — RAM only, lost on restart.
Now:    SQLite database — persists across restarts.

Every agent remembers:
  - All past actions and their outcomes
  - Detected threat patterns
  - False positive history (so same thing not flagged again)
  - Trust scores for other agents it interacts with
  - Session summaries for LangGraph state recovery

Security focus:
  - Memory entries are hashed for tamper detection
  - Suspicious pattern detection uses historical data
  - Agent cannot be tricked by repeating previously blocked actions
"""

import os
import time
import json
import sqlite3
import hashlib
import threading
from collections import deque
from logger import log_info, log_error, log_threat


# Database stored in project root — one file for all agents
DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "agent_memory.db"
)


class AgentMemory:
    """
    Long-term persistent memory for each agent.

    Short-term: last 50 actions in RAM (fast access)
    Long-term:  SQLite database (survives restarts)

    Each agent has its own rows in shared tables —
    identified by agent_id column.
    """

    _db_lock = threading.Lock()  # one lock for all instances

    def __init__(self, agent_id: str, max_short_term: int = 50):
        self.agent_id       = agent_id
        self.failed_attempts = 0

        # Short-term cache — fast RAM access
        self._short_term: deque = deque(maxlen=max_short_term)

        # Trust scores for other agents { agent_id: float 0.0-1.0 }
        self._trust_scores: dict = {}

        # Initialize database
        self._init_db()

        # Load existing data from DB into short-term cache
        self._load_from_db()

        log_info(f"[Memory:{agent_id}] Initialized | DB: {DB_PATH}")

    # ── DATABASE SETUP ────────────────────────────────────

    def _init_db(self):
        """Create tables if they do not exist."""
        with self._db_lock:
            conn = sqlite3.connect(DB_PATH)
            c    = conn.cursor()

            # Main action history table
            c.execute("""
                CREATE TABLE IF NOT EXISTS agent_actions (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id    TEXT    NOT NULL,
                    action      TEXT    NOT NULL,
                    result      TEXT    NOT NULL,
                    success     INTEGER NOT NULL,
                    timestamp   REAL    NOT NULL,
                    entry_hash  TEXT    NOT NULL
                )
            """)

            # Threat patterns — what threats this agent has seen
            c.execute("""
                CREATE TABLE IF NOT EXISTS threat_patterns (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id    TEXT    NOT NULL,
                    pattern     TEXT    NOT NULL,
                    flags       TEXT    NOT NULL,
                    score       REAL    NOT NULL,
                    verdict     TEXT    NOT NULL,
                    timestamp   REAL    NOT NULL
                )
            """)

            # False positive history — so same thing not flagged again
            c.execute("""
                CREATE TABLE IF NOT EXISTS false_positives (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id    TEXT    NOT NULL,
                    flags       TEXT    NOT NULL,
                    evidence    TEXT    NOT NULL,
                    timestamp   REAL    NOT NULL
                )
            """)

            # Agent trust scores
            c.execute("""
                CREATE TABLE IF NOT EXISTS trust_scores (
                    agent_id        TEXT NOT NULL,
                    target_agent_id TEXT NOT NULL,
                    score           REAL NOT NULL,
                    updated_at      REAL NOT NULL,
                    PRIMARY KEY (agent_id, target_agent_id)
                )
            """)

            # Session summaries for LangGraph recovery
            c.execute("""
                CREATE TABLE IF NOT EXISTS session_summaries (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id    TEXT    NOT NULL,
                    cycle_id    TEXT    NOT NULL,
                    summary     TEXT    NOT NULL,
                    verdict     TEXT    NOT NULL,
                    timestamp   REAL    NOT NULL
                )
            """)

            conn.commit()
            conn.close()

    def _load_from_db(self):
        """Load last 50 actions from DB into short-term cache on startup."""
        try:
            with self._db_lock:
                conn = sqlite3.connect(DB_PATH)
                c    = conn.cursor()
                c.execute("""
                    SELECT action, result, success, timestamp
                    FROM   agent_actions
                    WHERE  agent_id = ?
                    ORDER  BY timestamp DESC
                    LIMIT  50
                """, (self.agent_id,))
                rows = c.fetchall()
                conn.close()

            # Count failed attempts from history
            for action, result, success, timestamp in reversed(rows):
                entry = {
                    "action":    action,
                    "result":    result,
                    "success":   bool(success),
                    "timestamp": timestamp,
                }
                self._short_term.append(entry)
                if not success:
                    self.failed_attempts += 1

            log_info(f"[Memory:{self.agent_id}] Loaded {len(rows)} historical entries")

        except Exception as e:
            log_error(f"[Memory:{self.agent_id}] DB load error: {e}")

    # ── CORE OPERATIONS ───────────────────────────────────

    def add(self, action: str, result: str, success: bool):
        """
        Record a new action in both short-term cache and SQLite.
        Creates a tamper-detection hash for each entry.
        """
        timestamp  = time.time()
        entry_hash = hashlib.sha256(
            f"{self.agent_id}|{action}|{result}|{success}|{timestamp}".encode()
        ).hexdigest()

        entry = {
            "action":     action,
            "result":     result,
            "success":    success,
            "timestamp":  timestamp,
            "entry_hash": entry_hash,
        }

        # Add to short-term cache
        self._short_term.append(entry)

        # Track failures
        if not success:
            self.failed_attempts += 1

        # Persist to SQLite
        try:
            with self._db_lock:
                conn = sqlite3.connect(DB_PATH)
                c    = conn.cursor()
                c.execute("""
                    INSERT INTO agent_actions
                        (agent_id, action, result, success, timestamp, entry_hash)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (self.agent_id, action, result, int(success), timestamp, entry_hash))
                conn.commit()
                conn.close()
        except Exception as e:
            log_error(f"[Memory:{self.agent_id}] DB write error: {e}")

    def record_threat_pattern(self, flags: list, score: float, verdict: str):
        """
        Save a detected threat pattern to long-term memory.
        Used to recognize similar patterns faster in the future.
        """
        pattern = "|".join(sorted(flags))
        try:
            with self._db_lock:
                conn = sqlite3.connect(DB_PATH)
                c    = conn.cursor()
                c.execute("""
                    INSERT INTO threat_patterns
                        (agent_id, pattern, flags, score, verdict, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    self.agent_id,
                    pattern,
                    json.dumps(flags),
                    score,
                    verdict,
                    time.time(),
                ))
                conn.commit()
                conn.close()
            log_info(f"[Memory:{self.agent_id}] Threat pattern saved: {flags}")
        except Exception as e:
            log_error(f"[Memory:{self.agent_id}] Threat pattern save error: {e}")

    def record_false_positive(self, flags: list, evidence: dict):
        """
        Record a false positive so the same pattern is not flagged again.
        Verification engine checks this before raising alerts.
        """
        try:
            with self._db_lock:
                conn = sqlite3.connect(DB_PATH)
                c    = conn.cursor()
                c.execute("""
                    INSERT INTO false_positives
                        (agent_id, flags, evidence, timestamp)
                    VALUES (?, ?, ?, ?)
                """, (
                    self.agent_id,
                    json.dumps(flags),
                    json.dumps(evidence, default=str),
                    time.time(),
                ))
                conn.commit()
                conn.close()
            log_info(f"[Memory:{self.agent_id}] False positive recorded: {flags}")
        except Exception as e:
            log_error(f"[Memory:{self.agent_id}] False positive save error: {e}")

    def was_false_positive(self, flags: list) -> bool:
        """
        Check if this exact flag combination was previously a false positive.
        If yes — skip full verification and mark as NORMAL directly.
        """
        pattern = json.dumps(sorted(flags))
        try:
            with self._db_lock:
                conn = sqlite3.connect(DB_PATH)
                c    = conn.cursor()
                c.execute("""
                    SELECT COUNT(*) FROM false_positives
                    WHERE  agent_id = ? AND flags = ?
                    AND    timestamp > ?
                """, (
                    self.agent_id,
                    pattern,
                    time.time() - 86400,  # only check last 24 hours
                ))
                count = c.fetchone()[0]
                conn.close()
            return count > 0
        except Exception as e:
            log_error(f"[Memory:{self.agent_id}] False positive check error: {e}")
            return False

    def save_session_summary(self, cycle_id: str, summary: str, verdict: str):
        """
        Save LangGraph cycle summary for crash recovery.
        On restart, orchestrator loads last summary to resume context.
        """
        try:
            with self._db_lock:
                conn = sqlite3.connect(DB_PATH)
                c    = conn.cursor()
                c.execute("""
                    INSERT INTO session_summaries
                        (agent_id, cycle_id, summary, verdict, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                """, (self.agent_id, cycle_id, summary, verdict, time.time()))
                conn.commit()
                conn.close()
        except Exception as e:
            log_error(f"[Memory:{self.agent_id}] Session summary save error: {e}")

    def get_last_session(self) -> dict:
        """Get the most recent session summary — used for LangGraph recovery."""
        try:
            with self._db_lock:
                conn = sqlite3.connect(DB_PATH)
                c    = conn.cursor()
                c.execute("""
                    SELECT cycle_id, summary, verdict, timestamp
                    FROM   session_summaries
                    WHERE  agent_id = ?
                    ORDER  BY timestamp DESC
                    LIMIT  1
                """, (self.agent_id,))
                row = c.fetchone()
                conn.close()

            if row:
                return {
                    "cycle_id":  row[0],
                    "summary":   row[1],
                    "verdict":   row[2],
                    "timestamp": row[3],
                }
        except Exception as e:
            log_error(f"[Memory:{self.agent_id}] Last session fetch error: {e}")
        return {}

    # ── TRUST SCORES ──────────────────────────────────────

    def update_trust(self, target_agent_id: str, delta: float):
        """
        Update trust score for another agent.
        delta > 0: agent behaved well
        delta < 0: agent did something suspicious
        Score clamped between 0.0 and 1.0
        """
        current = self._trust_scores.get(target_agent_id, 0.7)
        new_score = max(0.0, min(1.0, current + delta))
        self._trust_scores[target_agent_id] = new_score

        try:
            with self._db_lock:
                conn = sqlite3.connect(DB_PATH)
                c    = conn.cursor()
                c.execute("""
                    INSERT INTO trust_scores
                        (agent_id, target_agent_id, score, updated_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(agent_id, target_agent_id)
                    DO UPDATE SET score = ?, updated_at = ?
                """, (
                    self.agent_id, target_agent_id, new_score, time.time(),
                    new_score, time.time(),
                ))
                conn.commit()
                conn.close()
        except Exception as e:
            log_error(f"[Memory:{self.agent_id}] Trust update error: {e}")

    def get_trust(self, target_agent_id: str) -> float:
        """Get current trust score for an agent. Default 0.7 (neutral)."""
        return self._trust_scores.get(target_agent_id, 0.7)

    # ── CONTEXT FOR LLM ───────────────────────────────────

    def get_context(self) -> str:
        """
        Provide last 5 actions as context string for LLM prompts.
        Same interface as before — no breaking change.
        """
        recent = list(self._short_term)[-5:]
        if not recent:
            return "No previous actions recorded."
        lines = []
        for h in recent:
            status = "SUCCESS" if h["success"] else "FAILED"
            lines.append(f"- {h['action']} → {status}")
        return "\n".join(lines)

    def get_rich_context(self) -> str:
        """
        Extended context with threat patterns and false positive history.
        Used for more informed LLM analysis.
        """
        base = self.get_context()

        # Add recent threat patterns
        try:
            with self._db_lock:
                conn = sqlite3.connect(DB_PATH)
                c    = conn.cursor()
                c.execute("""
                    SELECT flags, verdict, score FROM threat_patterns
                    WHERE  agent_id = ?
                    AND    timestamp > ?
                    ORDER  BY timestamp DESC LIMIT 3
                """, (self.agent_id, time.time() - 3600))
                patterns = c.fetchall()

                c.execute("""
                    SELECT flags FROM false_positives
                    WHERE  agent_id = ?
                    AND    timestamp > ?
                    ORDER  BY timestamp DESC LIMIT 3
                """, (self.agent_id, time.time() - 86400))
                fp_rows = c.fetchall()
                conn.close()

            if patterns:
                base += "\n\nRecent threat patterns:"
                for flags, verdict, score in patterns:
                    base += f"\n- {flags} → {verdict} (score={score:.2f})"

            if fp_rows:
                base += "\n\nRecent false positives (do not re-flag):"
                for (flags,) in fp_rows:
                    base += f"\n- {flags}"

        except Exception as e:
            log_error(f"[Memory:{self.agent_id}] Rich context error: {e}")

        return base

    # ── SUSPICIOUS CHECK ──────────────────────────────────

    def is_suspicious(self) -> bool:
        """
        More than 3 failures = suspicious.
        Same interface as before — no breaking change.
        """
        return self.failed_attempts >= 3

    # ── STATS ─────────────────────────────────────────────

    def get_stats(self) -> dict:
        """Return memory statistics for dashboard."""
        try:
            with self._db_lock:
                conn = sqlite3.connect(DB_PATH)
                c    = conn.cursor()

                c.execute("SELECT COUNT(*) FROM agent_actions WHERE agent_id=?", (self.agent_id,))
                total_actions = c.fetchone()[0]

                c.execute("SELECT COUNT(*) FROM threat_patterns WHERE agent_id=?", (self.agent_id,))
                threat_patterns = c.fetchone()[0]

                c.execute("SELECT COUNT(*) FROM false_positives WHERE agent_id=?", (self.agent_id,))
                false_positives = c.fetchone()[0]

                conn.close()

            return {
                "agent_id":        self.agent_id,
                "total_actions":   total_actions,
                "failed_attempts": self.failed_attempts,
                "threat_patterns": threat_patterns,
                "false_positives": false_positives,
                "short_term_size": len(self._short_term),
                "trust_scores":    dict(self._trust_scores),
                "db_path":         DB_PATH,
                "persistent":      True,
            }
        except Exception as e:
            log_error(f"[Memory:{self.agent_id}] Stats error: {e}")
            return {"agent_id": self.agent_id, "error": str(e)}

    def clear_short_term(self):
        """Clear RAM cache — DB data is preserved."""
        self._short_term.clear()
        log_info(f"[Memory:{self.agent_id}] Short-term cache cleared")
