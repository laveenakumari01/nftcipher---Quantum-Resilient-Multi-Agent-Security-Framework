"""
rag/pg_rag_store.py

PostgreSQL-backed RAG Store with Cursor-based Paging
=====================================================

Replaces ChromaDB for threat intelligence retrieval.
Uses PostgreSQL full-text search (tsvector/tsquery) instead of
vector embeddings — faster, no extra dependencies, more precise
for structured security data.

How it works:
  1. store()  — saves a threat document as a searchable row
  2. search() — full-text query, returns top_k results (one page)
  3. search_paged() — same but cursor-based, safe for large datasets
  4. LLM gets the returned rows as context for grounded suggestions

Why PostgreSQL over ChromaDB for threat data:
  - Threat types are structured labels (BRUTE_FORCE, API_FLOODING etc.)
  - SQL COUNT / GROUP BY directly answers "how many times did X happen"
  - No sentence-transformers model needed (removes ~500MB from Docker image)
  - Full-text search (GIN index) is fast and production-proven
  - Already in the stack — zero new services

"""

import json
import time
from logger import log_info, log_error


# ── CONNECTION HELPER ──────────────────────────────────────────────────────────

def _get_conn():
    """
    Get a PostgreSQL connection using the same pool as backend.py.
    Imported lazily so this module can be imported even before DB is ready.
    """
    try:
        from database import Database
        pool = Database.get_pool()
        if pool:
            return pool.getconn()
        return None
    except Exception as e:
        log_error(f"[PgRagStore] Connection error: {e}")
        return None


def _release_conn(conn):
    """Return connection back to the pool."""
    try:
        from database import Database
        pool = Database.get_pool()
        if pool and conn:
            pool.putconn(conn)
    except Exception:
        pass


# ── SCHEMA SETUP ──────────────────────────────────────────────────────────────

def init_pg_rag_tables():
    """
    Create the two tables used by this RAG store.
    Call once at startup from backend.py init_db().

    threat_rag_documents  — one row per stored threat document
    threat_rag_stats      — aggregated stats per threat_type (for fast paging)
    """
    conn = _get_conn()
    if not conn:
        log_error("[PgRagStore] Cannot init tables — no DB connection")
        return

    try:
        cur = conn.cursor()

        # Main document store
        cur.execute("""
            CREATE TABLE IF NOT EXISTS threat_rag_documents (
                id              SERIAL PRIMARY KEY,
                doc_id          TEXT UNIQUE NOT NULL,       -- unique key e.g. "threat-BRUTE_FORCE-1717000000"
                threat_type     TEXT NOT NULL,              -- e.g. BRUTE_FORCE, API_FLOODING
                content         TEXT NOT NULL,              -- human-readable description fed to LLM
                metadata        JSONB DEFAULT '{}',         -- flags, agent_id, score, etc.
                hit_count       INTEGER DEFAULT 1,          -- how many times this pattern was seen
                first_seen      REAL NOT NULL,              -- unix timestamp
                last_seen       REAL NOT NULL,              -- unix timestamp
                is_known_type   BOOLEAN DEFAULT TRUE,       -- FALSE = newly discovered threat type
                search_vector   TSVECTOR,                   -- auto-updated full-text index
                created_at      REAL NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())
            )
        """)

        # GIN index on search_vector for fast full-text search
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_rag_search_vector
            ON threat_rag_documents USING GIN(search_vector)
        """)

        # Index on threat_type for fast filtering
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_rag_threat_type
            ON threat_rag_documents(threat_type)
        """)

        # Index on last_seen for cursor-based paging
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_rag_last_seen
            ON threat_rag_documents(last_seen DESC)
        """)

        # Trigger: auto-update search_vector whenever content changes
        cur.execute("""
            CREATE OR REPLACE FUNCTION update_rag_search_vector()
            RETURNS TRIGGER AS $$
            BEGIN
                NEW.search_vector :=
                    setweight(to_tsvector('english', COALESCE(NEW.threat_type, '')), 'A') ||
                    setweight(to_tsvector('english', COALESCE(NEW.content, '')),     'B');
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
        """)

        cur.execute("""
            DROP TRIGGER IF EXISTS trg_rag_search_vector ON threat_rag_documents
        """)

        cur.execute("""
            CREATE TRIGGER trg_rag_search_vector
            BEFORE INSERT OR UPDATE ON threat_rag_documents
            FOR EACH ROW EXECUTE FUNCTION update_rag_search_vector()
        """)

        conn.commit()
        cur.close()
        log_info("[PgRagStore] Tables and indexes ready")

    except Exception as e:
        conn.rollback()
        log_error(f"[PgRagStore] Table init error: {e}")
    finally:
        _release_conn(conn)


# ── CORE CLASS ────────────────────────────────────────────────────────────────

class PgRagStore:
    """
    PostgreSQL-backed RAG store for threat intelligence.

    Drop-in replacement for VectorStore (ChromaDB) in suggestion_engine.py
    and sentinel_agent.py.

    Public interface (same shape as VectorStore so no other file breaks):
        store(doc_id, threat_type, content, metadata, is_known_type)
        search(query, top_k, threat_type_filter)
        search_paged(query, page_size, cursor)   ← new: safe for large datasets
        get_threat_summary(threat_type)
        get_status()
    """

    def __init__(self):
        log_info("[PgRagStore] Initialized — PostgreSQL full-text RAG active")

    # ── WRITE ─────────────────────────────────────────────────────────────────

    def store(
        self,
        doc_id       : str,
        threat_type  : str,
        content      : str,
        metadata     : dict = None,
        is_known_type: bool = True,
    ) -> bool:
        """
        Save or update a threat document.

        If doc_id already exists:
          - hit_count is incremented
          - last_seen is updated
          - content and metadata are refreshed

        If doc_id is new:
          - a fresh row is inserted

        Args:
            doc_id        : unique identifier e.g. "threat-BRUTE_FORCE-agent01"
            threat_type   : label e.g. "BRUTE_FORCE" or "UNKNOWN_AGENT_MIMICRY"
            content       : text description that LLM will read as context
            metadata      : dict with flags, agent_id, score, etc.
            is_known_type : False for newly discovered threat patterns

        Returns:
            True on success, False on error
        """
        metadata = metadata or {}
        now      = time.time()

        conn = _get_conn()
        if not conn:
            return False

        try:
            cur = conn.cursor()

            # Upsert: insert or update on conflict
            cur.execute("""
                INSERT INTO threat_rag_documents
                    (doc_id, threat_type, content, metadata, hit_count,
                     first_seen, last_seen, is_known_type)
                VALUES (%s, %s, %s, %s, 1, %s, %s, %s)
                ON CONFLICT (doc_id) DO UPDATE SET
                    content       = EXCLUDED.content,
                    metadata      = EXCLUDED.metadata,
                    hit_count     = threat_rag_documents.hit_count + 1,
                    last_seen     = EXCLUDED.last_seen,
                    is_known_type = EXCLUDED.is_known_type
            """, (
                doc_id,
                threat_type.upper(),
                content,
                json.dumps(metadata),
                now,
                now,
                is_known_type,
            ))

            conn.commit()
            cur.close()
            log_info(
                f"[PgRagStore] Stored | doc_id={doc_id} | "
                f"type={threat_type} | known={is_known_type}"
            )
            return True

        except Exception as e:
            conn.rollback()
            log_error(f"[PgRagStore] store error: {e}")
            return False
        finally:
            _release_conn(conn)

    # ── SEARCH — single page ──────────────────────────────────────────────────

    def search(
        self,
        query              : str,
        top_k              : int  = 5,
        threat_type_filter : str  = None,
    ) -> list[dict]:
        """
        Full-text search returning the top_k most relevant documents.

        Uses PostgreSQL ts_rank for relevance scoring.
        Optionally filter by threat_type for targeted lookups.

        Returns list of dicts:
            {doc_id, threat_type, content, metadata, hit_count,
             first_seen, last_seen, is_known_type, relevance_score}
        """
        conn = _get_conn()
        if not conn:
            return []

        try:
            cur = conn.cursor()

            # Build base query — full-text rank + recency boost
            if threat_type_filter:
                cur.execute("""
                    SELECT
                        doc_id, threat_type, content, metadata,
                        hit_count, first_seen, last_seen, is_known_type,
                        ts_rank(search_vector, plainto_tsquery('english', %s)) AS relevance
                    FROM threat_rag_documents
                    WHERE threat_type = %s
                      AND search_vector @@ plainto_tsquery('english', %s)
                    ORDER BY relevance DESC, last_seen DESC
                    LIMIT %s
                """, (query, threat_type_filter.upper(), query, top_k))
            else:
                cur.execute("""
                    SELECT
                        doc_id, threat_type, content, metadata,
                        hit_count, first_seen, last_seen, is_known_type,
                        ts_rank(search_vector, plainto_tsquery('english', %s)) AS relevance
                    FROM threat_rag_documents
                    WHERE search_vector @@ plainto_tsquery('english', %s)
                    ORDER BY relevance DESC, last_seen DESC
                    LIMIT %s
                """, (query, query, top_k))

            rows    = cur.fetchall()
            cur.close()
            return self._rows_to_dicts(rows)

        except Exception as e:
            log_error(f"[PgRagStore] search error: {e}")
            return []
        finally:
            _release_conn(conn)

    # ── SEARCH — cursor-based paging ──────────────────────────────────────────

    def search_paged(
        self,
        query      : str,
        page_size  : int   = 5,
        cursor     : float = None,
    ) -> dict:
        """
        Cursor-based paging search — safe for large threat datasets.

        Instead of OFFSET (which gets slow on big tables), uses last_seen
        timestamp as a cursor. Each call returns the next page.

        How to use:
            # First page
            result = store.search_paged("brute force login", page_size=5)
            docs   = result["docs"]
            next_c = result["next_cursor"]   # None if no more pages

            # Second page
            result = store.search_paged("brute force login", page_size=5, cursor=next_c)

        Args:
            query      : search string
            page_size  : how many docs per page (keep <=10 for LLM context)
            cursor     : last_seen value from previous page's next_cursor

        Returns:
            {
                "docs"       : list of document dicts,
                "next_cursor": float timestamp or None (no more pages),
                "has_more"   : bool,
                "page_size"  : int,
            }
        """
        conn = _get_conn()
        if not conn:
            return {"docs": [], "next_cursor": None, "has_more": False, "page_size": page_size}

        try:
            cur = conn.cursor()

            # Fetch page_size + 1 to detect if there is a next page
            fetch_count = page_size + 1

            if cursor is None:
                # First page — no cursor constraint
                cur.execute("""
                    SELECT
                        doc_id, threat_type, content, metadata,
                        hit_count, first_seen, last_seen, is_known_type,
                        ts_rank(search_vector, plainto_tsquery('english', %s)) AS relevance
                    FROM threat_rag_documents
                    WHERE search_vector @@ plainto_tsquery('english', %s)
                    ORDER BY last_seen DESC, relevance DESC
                    LIMIT %s
                """, (query, query, fetch_count))
            else:
                # Subsequent pages — only rows older than cursor
                cur.execute("""
                    SELECT
                        doc_id, threat_type, content, metadata,
                        hit_count, first_seen, last_seen, is_known_type,
                        ts_rank(search_vector, plainto_tsquery('english', %s)) AS relevance
                    FROM threat_rag_documents
                    WHERE search_vector @@ plainto_tsquery('english', %s)
                      AND last_seen < %s
                    ORDER BY last_seen DESC, relevance DESC
                    LIMIT %s
                """, (query, query, cursor, fetch_count))

            rows = cur.fetchall()
            cur.close()

            # Determine if there is a next page
            has_more    = len(rows) > page_size
            page_rows   = rows[:page_size]
            next_cursor = page_rows[-1][6] if has_more and page_rows else None

            return {
                "docs"       : self._rows_to_dicts(page_rows),
                "next_cursor": next_cursor,
                "has_more"   : has_more,
                "page_size"  : page_size,
            }

        except Exception as e:
            log_error(f"[PgRagStore] search_paged error: {e}")
            return {"docs": [], "next_cursor": None, "has_more": False, "page_size": page_size}
        finally:
            _release_conn(conn)

    # ── THREAT SUMMARY ────────────────────────────────────────────────────────

    def get_threat_summary(self, threat_type: str = None) -> list[dict]:
        """
        Aggregated summary — total hits, first/last seen per threat type.

        Used to build the LLM context preamble:
        "BRUTE_FORCE has been seen 47 times, last at 2026-06-05 10:30"

        Args:
            threat_type: if given, returns summary for that type only

        Returns:
            list of {threat_type, total_documents, total_hits,
                     first_seen, last_seen, is_known_type}
        """
        conn = _get_conn()
        if not conn:
            return []

        try:
            cur = conn.cursor()

            if threat_type:
                cur.execute("""
                    SELECT
                        threat_type,
                        COUNT(*)         AS total_documents,
                        SUM(hit_count)   AS total_hits,
                        MIN(first_seen)  AS first_seen,
                        MAX(last_seen)   AS last_seen,
                        bool_and(is_known_type) AS is_known_type
                    FROM threat_rag_documents
                    WHERE threat_type = %s
                    GROUP BY threat_type
                """, (threat_type.upper(),))
            else:
                cur.execute("""
                    SELECT
                        threat_type,
                        COUNT(*)         AS total_documents,
                        SUM(hit_count)   AS total_hits,
                        MIN(first_seen)  AS first_seen,
                        MAX(last_seen)   AS last_seen,
                        bool_and(is_known_type) AS is_known_type
                    FROM threat_rag_documents
                    GROUP BY threat_type
                    ORDER BY total_hits DESC
                """)

            rows = cur.fetchall()
            cur.close()

            return [
                {
                    "threat_type"     : row[0],
                    "total_documents" : row[1],
                    "total_hits"      : row[2],
                    "first_seen"      : row[3],
                    "last_seen"       : row[4],
                    "is_known_type"   : row[5],
                }
                for row in rows
            ]

        except Exception as e:
            log_error(f"[PgRagStore] get_threat_summary error: {e}")
            return []
        finally:
            _release_conn(conn)

    # ── UNKNOWN THREAT TYPES ──────────────────────────────────────────────────

    def get_unknown_threats(self, limit: int = 20) -> list[dict]:
        """
        Return all documents marked as newly discovered (is_known_type=False).

        Used by Sentinel to surface novel attack patterns that need
        human review or model retraining.
        """
        conn = _get_conn()
        if not conn:
            return []

        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT
                    doc_id, threat_type, content, metadata,
                    hit_count, first_seen, last_seen, is_known_type,
                    1.0 AS relevance
                FROM threat_rag_documents
                WHERE is_known_type = FALSE
                ORDER BY hit_count DESC, last_seen DESC
                LIMIT %s
            """, (limit,))
            rows = cur.fetchall()
            cur.close()
            return self._rows_to_dicts(rows)

        except Exception as e:
            log_error(f"[PgRagStore] get_unknown_threats error: {e}")
            return []
        finally:
            _release_conn(conn)

    # ── CONTEXT BUILDER — feeds LLM ───────────────────────────────────────────

    def build_rag_context(
        self,
        query      : str,
        page_size  : int   = 5,
        cursor     : float = None,
    ) -> str:
        """
        Build a ready-to-use context string for the LLM.

        Combines:
          1. Threat summary stats (how often each type was seen)
          2. Top matching documents (actual past incidents)

        The LLM receives this as the "context" section in its prompt so
        its suggestion is grounded in real historical threat data.

        Args:
            query     : threat description to search for
            page_size : max documents to include (keep low to avoid context overflow)
            cursor    : paging cursor from previous call

        Returns:
            Formatted string ready to inject into LLM prompt
        """
        # Get summary stats for the query's matching threat types
        search_result = self.search_paged(query, page_size=page_size, cursor=cursor)
        docs          = search_result["docs"]

        if not docs:
            return "No historical threat data found matching this pattern."

        lines = ["=== HISTORICAL THREAT CONTEXT ===\n"]

        # Section 1: stats per type found in this page
        seen_types = list({d["threat_type"] for d in docs})
        for t in seen_types:
            summaries = self.get_threat_summary(t)
            if summaries:
                s = summaries[0]
                lines.append(
                    f"[{t}] Total occurrences: {s['total_hits']} | "
                    f"Documents: {s['total_documents']} | "
                    f"Known type: {s['is_known_type']}\n"
                )

        lines.append("\n=== MATCHING PAST INCIDENTS ===\n")

        # Section 2: actual documents
        for i, doc in enumerate(docs, 1):
            meta    = doc.get("metadata", {})
            flags   = meta.get("flags", [])
            agent   = meta.get("agent_id", "unknown")
            score   = meta.get("consensus_score", "?")

            lines.append(
                f"[Incident {i}] Type: {doc['threat_type']} | "
                f"Hits: {doc['hit_count']} | "
                f"Agent: {agent} | "
                f"Score: {score} | "
                f"Flags: {', '.join(flags) if flags else 'none'}\n"
                f"  Description: {doc['content'][:300]}\n"
            )

        # Paging note so LLM knows if more context is available
        if search_result["has_more"]:
            lines.append(
                f"\n[Note: more historical incidents available — "
                f"next_cursor={search_result['next_cursor']}]"
            )

        return "".join(lines)

    # ── STATUS ────────────────────────────────────────────────────────────────

    def get_status(self) -> dict:
        """Status dict for the /status API endpoint."""
        conn = _get_conn()
        if not conn:
            return {"mode": "pg_rag", "error": "no_db_connection", "document_count": 0}

        try:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*), SUM(hit_count) FROM threat_rag_documents")
            row = cur.fetchone()
            cur.execute("SELECT COUNT(*) FROM threat_rag_documents WHERE is_known_type = FALSE")
            unknown_count = cur.fetchone()[0]
            cur.close()

            return {
                "mode"           : "pg_rag_paged",
                "chroma_available"     : False,   # keeps shape compatible with VectorStore
                "embeddings_available" : False,
                "document_count" : row[0] or 0,
                "total_hits"     : row[1] or 0,
                "unknown_threats": unknown_count,
                "collections"    : 1,
                "backend"        : "postgresql_fulltext",
            }

        except Exception as e:
            log_error(f"[PgRagStore] get_status error: {e}")
            return {"mode": "pg_rag", "error": str(e), "document_count": 0}
        finally:
            _release_conn(conn)

    # ── INTERNAL HELPERS ──────────────────────────────────────────────────────

    @staticmethod
    def _rows_to_dicts(rows: list) -> list[dict]:
        """Convert raw DB rows to clean dicts."""
        result = []
        for row in rows:
            meta = {}
            try:
                meta = json.loads(row[3]) if isinstance(row[3], str) else (row[3] or {})
            except Exception:
                pass

            result.append({
                "doc_id"       : row[0],
                "threat_type"  : row[1],
                "content"      : row[2],
                "metadata"     : meta,
                "hit_count"    : row[4],
                "first_seen"   : row[5],
                "last_seen"    : row[6],
                "is_known_type": row[7],
                "relevance"    : round(float(row[8]), 4) if row[8] else 0.0,
            })
        return result


# ── SINGLETON ─────────────────────────────────────────────────────────────────

# Import this instance everywhere instead of VectorStore for threat data
pg_rag_store = PgRagStore()