"""
threat_intelligence.py

Threat Intelligence Tracker
============================

"""

import time
import json
import threading
from logger import log_info, log_error, log_threat


# ── KNOWN THREAT TYPES ────────────────────────────────────────────────────────

KNOWN_THREAT_TYPES = {
    "BRUTE_FORCE",
    "DATA_EXFILTRATION",
    "API_FLOODING",
    "PRIVILEGE_ESCALATION",
    "NORMAL",
}

# Session timeout: 

SESSION_TIMEOUT_SEC = 300   # 5 minutes


# ── CONNECTION HELPER ─────────────────────────────────────────────────────────

def _get_conn():
    try:
        from database import Database
        pool = Database.get_pool()
        if pool:
            return pool.getconn()
        return None
    except Exception as e:
        log_error(f"[ThreatIntel] DB connection error: {e}")
        return None


def _release_conn(conn):
    try:
        from database import Database
        pool = Database.get_pool()
        if pool and conn:
            pool.putconn(conn)
    except Exception:
        pass


# ── SCHEMA SETUP ──────────────────────────────────────────────────────────────

def init_threat_intelligence_tables():
    """
    Create threat_intelligence and threat_occurrences tables.
    Call this from backend.py init_db() — after existing tables.
    """
    conn = _get_conn()
    if not conn:
        log_error("[ThreatIntel] Cannot create tables — no DB connection")
        return

    try:
        cur = conn.cursor()

        # ── TABLE 1: threat_intelligence ──────────────────
        # Har unique threat TYPE ka master record
        cur.execute("""
            CREATE TABLE IF NOT EXISTS threat_intelligence (
                id              SERIAL PRIMARY KEY,
                threat_type     VARCHAR(100) UNIQUE NOT NULL,  -- e.g. BRUTE_FORCE, AGENT_MIMICRY
                is_known_type   BOOLEAN DEFAULT TRUE,           -- FALSE = naya, model ne nahi dekha
                first_seen      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                total_count     INTEGER DEFAULT 1,              -- kitni baar detect hua total
                active_sessions INTEGER DEFAULT 0,             -- abhi kitne sessions chal rahe
                total_sessions  INTEGER DEFAULT 1,             -- total sessions ever
                raw_signature   JSONB DEFAULT '{}',            -- flags, score etc. first detection ka
                last_agent_id   VARCHAR(100),                  -- last mein kis agent pe detect hua
                notes           TEXT DEFAULT ''                -- human/LLM notes
            )
        """)

        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_ti_threat_type
            ON threat_intelligence(threat_type)
        """)

        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_ti_is_known
            ON threat_intelligence(is_known_type)
        """)

        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_ti_total_count
            ON threat_intelligence(total_count DESC)
        """)

        # ── TABLE 2: threat_occurrences ───────────────────
        # Har individual attack session ka record
        # "Yeh BRUTE_FORCE 10 baar aaya phir ruk gaya" — ek row
        cur.execute("""
            CREATE TABLE IF NOT EXISTS threat_occurrences (
                id              SERIAL PRIMARY KEY,
                session_id      VARCHAR(150) UNIQUE NOT NULL,  -- e.g. "occ-BRUTE_FORCE-1717000000"
                threat_type     VARCHAR(100) NOT NULL,
                agent_id        VARCHAR(100) NOT NULL,          -- target agent
                start_time      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                end_time        TIMESTAMP,                      -- NULL = still ACTIVE
                hit_count       INTEGER DEFAULT 1,             -- kitni baar is session mein aya
                peak_score      REAL DEFAULT 0.0,              -- highest consensus score in session
                status          VARCHAR(20) DEFAULT 'ACTIVE',  -- ACTIVE / STOPPED
                flags_observed  JSONB DEFAULT '[]',            -- all unique flags seen
                metadata        JSONB DEFAULT '{}'             -- extra info
            )
        """)

        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_occ_threat_type
            ON threat_occurrences(threat_type)
        """)

        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_occ_status
            ON threat_occurrences(status)
        """)

        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_occ_agent_id
            ON threat_occurrences(agent_id)
        """)

        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_occ_start_time
            ON threat_occurrences(start_time DESC)
        """)

        conn.commit()
        cur.close()
        log_info("[ThreatIntel] Tables ready — threat_intelligence + threat_occurrences")

    except Exception as e:
        conn.rollback()
        log_error(f"[ThreatIntel] Table init error: {e}")
    finally:
        _release_conn(conn)


# ── CORE TRACKER CLASS ────────────────────────────────────────────────────────

class ThreatIntelligenceTracker:
    """
    Singleton tracker — call record_threat() every time Sentinel
    confirms a threat. Everything else is automatic.

    Usage in sentinel_agent.py:
        from threat_intelligence import threat_tracker
        threat_tracker.record_threat(
            threat_type      = "BRUTE_FORCE",
            agent_id         = agent_id,
            flags            = flags,
            consensus_score  = verified.consensus_score,
        )
    """

    def __init__(self):
        # In-memory active session cache
        # Key: (threat_type, agent_id) → {session_id, last_hit, hit_count}
        self._active_sessions: dict = {}
        self._lock = threading.Lock()
        log_info("[ThreatIntel] Tracker initialized")

    # ── PUBLIC API ────────────────────────────────────────

    def record_threat(
        self,
        threat_type    : str,
        agent_id       : str,
        flags          : list,
        consensus_score: float,
        metadata       : dict = None,
    ):
        """
        Main entry point. Call this every time a CONFIRMED threat is detected.

        Does 3 things automatically:
          1. Upserts threat_intelligence table (new type? INSERT. Known? UPDATE count.)
          2. Manages threat_occurrences session (continue existing or start new)
          3. Feeds updated data into PgRagStore for RAG retrieval
        """
        metadata = metadata or {}
        threat_type = threat_type.upper().strip()

        try:
            is_known = threat_type in KNOWN_THREAT_TYPES

            # Step 1: Update threat_intelligence master record
            self._upsert_threat_intelligence(
                threat_type     = threat_type,
                is_known        = is_known,
                agent_id        = agent_id,
                flags           = flags,
                consensus_score = consensus_score,
            )

            # Step 2: Manage occurrence session
            session_id = self._manage_occurrence_session(
                threat_type     = threat_type,
                agent_id        = agent_id,
                flags           = flags,
                consensus_score = consensus_score,
                metadata        = metadata,
            )

            # Step 3: Feed into PgRagStore (background — non-blocking)
            threading.Thread(
                target  = self._feed_to_rag,
                args    = (threat_type, agent_id, flags, consensus_score, is_known),
                daemon  = True,
            ).start()

            log_info(
                f"[ThreatIntel] Recorded | type={threat_type} | "
                f"known={is_known} | agent={agent_id} | session={session_id}"
            )

        except Exception as e:
            log_error(f"[ThreatIntel] record_threat error: {e}")

    def check_and_close_stale_sessions(self):
        """
        Close sessions that have been inactive for SESSION_TIMEOUT_SEC.
        Call this from Sentinel's run_cycle() every loop.
        """
        now = time.time()
        stale_keys = []

        with self._lock:
            for key, session in self._active_sessions.items():
                if now - session["last_hit"] > SESSION_TIMEOUT_SEC:
                    stale_keys.append(key)

        for key in stale_keys:
            with self._lock:
                session = self._active_sessions.pop(key, None)
            if session:
                self._close_session(session["session_id"])
                log_info(
                    f"[ThreatIntel] Session STOPPED (timeout) | "
                    f"session={session['session_id']} | hits={session['hit_count']}"
                )

    # ── THREAT INTELLIGENCE UPSERT ────────────────────────

    def _upsert_threat_intelligence(
        self,
        threat_type : str,
        is_known    : bool,
        agent_id    : str,
        flags       : list,
        consensus_score: float,
    ):
        """
        Insert new threat type OR update existing one.

        New type  → INSERT with is_known_type=FALSE, log as discovery
        Known type → UPDATE total_count, last_seen, last_agent_id
        """
        conn = _get_conn()
        if not conn:
            return

        try:
            cur = conn.cursor()

            cur.execute("""
                INSERT INTO threat_intelligence
                    (threat_type, is_known_type, first_seen, last_seen,
                     total_count, active_sessions, total_sessions,
                     raw_signature, last_agent_id)
                VALUES (%s, %s, NOW(), NOW(), 1, 1, 1, %s, %s)
                ON CONFLICT (threat_type) DO UPDATE SET
                    last_seen      = NOW(),
                    total_count    = threat_intelligence.total_count + 1,
                    last_agent_id  = EXCLUDED.last_agent_id,
                    raw_signature  = EXCLUDED.raw_signature
            """, (
                threat_type,
                is_known,
                json.dumps({
                    "flags"          : flags,
                    "consensus_score": consensus_score,
                    "agent_id"       : agent_id,
                }),
                agent_id,
            ))

            # If this is a NEW unknown type, log it prominently
            cur.execute(
                "SELECT total_count FROM threat_intelligence WHERE threat_type = %s",
                (threat_type,)
            )
            row = cur.fetchone()
            if row and row[0] == 1 and not is_known:
                log_threat(
                    f"[ThreatIntel] NEW UNKNOWN THREAT TYPE DISCOVERED: {threat_type} | "
                    f"agent={agent_id} | flags={flags}"
                )

            conn.commit()
            cur.close()

        except Exception as e:
            conn.rollback()
            log_error(f"[ThreatIntel] upsert_threat_intelligence error: {e}")
        finally:
            _release_conn(conn)

    # ── SESSION MANAGEMENT ────────────────────────────────

    def _manage_occurrence_session(
        self,
        threat_type    : str,
        agent_id       : str,
        flags          : list,
        consensus_score: float,
        metadata       : dict,
    ) -> str:
        """
        Continue existing active session or start a new one.

        Logic:
          - Same (threat_type, agent_id) hit within SESSION_TIMEOUT_SEC → continue
          - Gap > SESSION_TIMEOUT_SEC → close old, start new
          - First time ever → start new

        Returns the session_id that was used.
        """
        now = time.time()
        key = (threat_type, agent_id)

        with self._lock:
            existing = self._active_sessions.get(key)

        if existing and (now - existing["last_hit"]) <= SESSION_TIMEOUT_SEC:
            # Continue existing session
            existing["hit_count"] += 1
            existing["last_hit"]   = now
            if consensus_score > existing["peak_score"]:
                existing["peak_score"] = consensus_score

            self._update_occurrence_hit(
                session_id      = existing["session_id"],
                hit_count       = existing["hit_count"],
                peak_score      = existing["peak_score"],
                flags           = flags,
            )
            return existing["session_id"]

        else:
            # Close old session if it existed
            if existing:
                self._close_session(existing["session_id"])
                log_info(
                    f"[ThreatIntel] Session STOPPED (new wave) | "
                    f"session={existing['session_id']} | hits={existing['hit_count']}"
                )

            # Start new session
            session_id = f"occ-{threat_type}-{int(now)}-{agent_id[:8]}"
            new_session = {
                "session_id": session_id,
                "last_hit"  : now,
                "hit_count" : 1,
                "peak_score": consensus_score,
            }

            with self._lock:
                self._active_sessions[key] = new_session

            self._insert_occurrence(
                session_id      = session_id,
                threat_type     = threat_type,
                agent_id        = agent_id,
                flags           = flags,
                consensus_score = consensus_score,
                metadata        = metadata,
            )
            return session_id

    def _insert_occurrence(
        self,
        session_id     : str,
        threat_type    : str,
        agent_id       : str,
        flags          : list,
        consensus_score: float,
        metadata       : dict,
    ):
        """Insert a new occurrence session row."""
        conn = _get_conn()
        if not conn:
            return

        try:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO threat_occurrences
                    (session_id, threat_type, agent_id, start_time,
                     hit_count, peak_score, status, flags_observed, metadata)
                VALUES (%s, %s, %s, NOW(), 1, %s, 'ACTIVE', %s, %s)
                ON CONFLICT (session_id) DO NOTHING
            """, (
                session_id,
                threat_type,
                agent_id,
                consensus_score,
                json.dumps(list(set(flags))),
                json.dumps(metadata),
            ))

            # Also increment active_sessions count in threat_intelligence
            cur.execute("""
                UPDATE threat_intelligence
                SET active_sessions = active_sessions + 1,
                    total_sessions  = total_sessions  + 1
                WHERE threat_type = %s
            """, (threat_type,))

            conn.commit()
            cur.close()

        except Exception as e:
            conn.rollback()
            log_error(f"[ThreatIntel] insert_occurrence error: {e}")
        finally:
            _release_conn(conn)

    def _update_occurrence_hit(
        self,
        session_id : str,
        hit_count  : int,
        peak_score : float,
        flags      : list,
    ):
        """Increment hit_count on an existing ACTIVE session."""
        conn = _get_conn()
        if not conn:
            return

        try:
            cur = conn.cursor()
            cur.execute("""
                UPDATE threat_occurrences SET
                    hit_count      = %s,
                    peak_score     = GREATEST(peak_score, %s),
                    flags_observed = flags_observed || %s::jsonb
                WHERE session_id = %s AND status = 'ACTIVE'
            """, (
                hit_count,
                peak_score,
                json.dumps(list(set(flags))),
                session_id,
            ))
            conn.commit()
            cur.close()

        except Exception as e:
            conn.rollback()
            log_error(f"[ThreatIntel] update_occurrence_hit error: {e}")
        finally:
            _release_conn(conn)

    def _close_session(self, session_id: str):
        """Mark a session as STOPPED and set end_time."""
        conn = _get_conn()
        if not conn:
            return

        try:
            cur = conn.cursor()

            # Get hit_count before closing for the log
            cur.execute(
                "SELECT threat_type, hit_count FROM threat_occurrences WHERE session_id = %s",
                (session_id,)
            )
            row = cur.fetchone()

            cur.execute("""
                UPDATE threat_occurrences SET
                    status   = 'STOPPED',
                    end_time = NOW()
                WHERE session_id = %s AND status = 'ACTIVE'
            """, (session_id,))

            # Decrement active_sessions in threat_intelligence
            if row:
                cur.execute("""
                    UPDATE threat_intelligence
                    SET active_sessions = GREATEST(active_sessions - 1, 0)
                    WHERE threat_type = %s
                """, (row[0],))

                log_info(
                    f"[ThreatIntel] Session closed | session={session_id} | "
                    f"type={row[0]} | total_hits={row[1]}"
                )

            conn.commit()
            cur.close()

        except Exception as e:
            conn.rollback()
            log_error(f"[ThreatIntel] close_session error: {e}")
        finally:
            _release_conn(conn)

    # ── RAG FEED ──────────────────────────────────────────

    def _feed_to_rag(
        self,
        threat_type    : str,
        agent_id       : str,
        flags          : list,
        consensus_score: float,
        is_known       : bool,
    ):
        """
        Store threat data into PgRagStore so LLM gets historical context.
        Runs in background thread — never blocks Sentinel.
        """
        try:
            from rag.pg_rag_store import pg_rag_store

            # Get current stats from threat_intelligence for richer content
            conn = _get_conn()
            total_count = 1
            total_sessions = 1
            if conn:
                try:
                    cur = conn.cursor()
                    cur.execute(
                        "SELECT total_count, total_sessions FROM threat_intelligence WHERE threat_type = %s",
                        (threat_type,)
                    )
                    row = cur.fetchone()
                    if row:
                        total_count    = row[0]
                        total_sessions = row[1]
                    cur.close()
                except Exception:
                    pass
                finally:
                    _release_conn(conn)

            # Build descriptive content string for LLM retrieval
            known_label = "known attack pattern" if is_known else "NEWLY DISCOVERED threat type"
            content = (
                f"Threat type: {threat_type} ({known_label}). "
                f"Detected on agent: {agent_id}. "
                f"Total detections so far: {total_count}. "
                f"Total attack sessions: {total_sessions}. "
                f"Observed flags: {', '.join(flags) if flags else 'none'}. "
                f"Confidence score: {round(consensus_score, 2)}. "
                f"{'This is a new unknown threat type that the ML model has not seen before — requires investigation.' if not is_known else ''}"
            )

            doc_id = f"ti-{threat_type}-{agent_id}"

            pg_rag_store.store(
                doc_id        = doc_id,
                threat_type   = threat_type,
                content       = content,
                metadata      = {
                    "agent_id"       : agent_id,
                    "flags"          : flags,
                    "consensus_score": consensus_score,
                    "total_count"    : total_count,
                    "is_known_type"  : is_known,
                    "source"         : "threat_intelligence_tracker",
                },
                is_known_type = is_known,
            )

        except Exception as e:
            log_error(f"[ThreatIntel] _feed_to_rag error: {e}")

    # ── QUERY HELPERS (for API endpoints / dashboard) ─────

    def get_all_threat_types(self) -> list[dict]:
        """Return all known + unknown threat types with stats."""
        conn = _get_conn()
        if not conn:
            return []
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT threat_type, is_known_type, first_seen, last_seen,
                       total_count, active_sessions, total_sessions, last_agent_id
                FROM threat_intelligence
                ORDER BY total_count DESC
            """)
            rows = cur.fetchall()
            cur.close()
            return [
                {
                    "threat_type"    : r[0],
                    "is_known_type"  : r[1],
                    "first_seen"     : str(r[2]),
                    "last_seen"      : str(r[3]),
                    "total_count"    : r[4],
                    "active_sessions": r[5],
                    "total_sessions" : r[6],
                    "last_agent_id"  : r[7],
                }
                for r in rows
            ]
        except Exception as e:
            log_error(f"[ThreatIntel] get_all_threat_types error: {e}")
            return []
        finally:
            _release_conn(conn)

    def get_occurrences(
        self,
        threat_type: str = None,
        status     : str = None,
        limit      : int = 50,
    ) -> list[dict]:
        """
        Return occurrence sessions, optionally filtered by type or status.

        Examples:
            get_occurrences(status='STOPPED')       → all finished sessions
            get_occurrences(threat_type='BRUTE_FORCE') → all brute force sessions
        """
        conn = _get_conn()
        if not conn:
            return []
        try:
            cur = conn.cursor()
            conditions = []
            params     = []

            if threat_type:
                conditions.append("threat_type = %s")
                params.append(threat_type.upper())
            if status:
                conditions.append("status = %s")
                params.append(status.upper())

            where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
            params.append(limit)

            cur.execute(f"""
                SELECT session_id, threat_type, agent_id, start_time, end_time,
                       hit_count, peak_score, status, flags_observed
                FROM threat_occurrences
                {where}
                ORDER BY start_time DESC
                LIMIT %s
            """, params)

            rows = cur.fetchall()
            cur.close()
            return [
                {
                    "session_id"    : r[0],
                    "threat_type"   : r[1],
                    "agent_id"      : r[2],
                    "start_time"    : str(r[3]),
                    "end_time"      : str(r[4]) if r[4] else None,
                    "hit_count"     : r[5],
                    "peak_score"    : r[6],
                    "status"        : r[7],
                    "flags_observed": r[8],
                }
                for r in rows
            ]
        except Exception as e:
            log_error(f"[ThreatIntel] get_occurrences error: {e}")
            return []
        finally:
            _release_conn(conn)

    def get_unknown_threats(self) -> list[dict]:
        """Return only newly discovered threat types (is_known_type=FALSE)."""
        conn = _get_conn()
        if not conn:
            return []
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT threat_type, first_seen, last_seen, total_count,
                       total_sessions, last_agent_id, raw_signature
                FROM threat_intelligence
                WHERE is_known_type = FALSE
                ORDER BY total_count DESC
            """)
            rows = cur.fetchall()
            cur.close()
            return [
                {
                    "threat_type"  : r[0],
                    "first_seen"   : str(r[1]),
                    "last_seen"    : str(r[2]),
                    "total_count"  : r[3],
                    "total_sessions": r[4],
                    "last_agent_id": r[5],
                    "raw_signature": r[6],
                }
                for r in rows
            ]
        except Exception as e:
            log_error(f"[ThreatIntel] get_unknown_threats error: {e}")
            return []
        finally:
            _release_conn(conn)


# ── SINGLETON ─────────────────────────────────────────────────────────────────

threat_tracker = ThreatIntelligenceTracker()