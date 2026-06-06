"""
suggestion_engine.py

Suggestion Engine — Autonomous Security Recommendation System
============================================================

When a threat is CONFIRMED by Sentinel's verification engine, this module
orchestrates a chain of targeted agent-to-agent conversations:

  Sentinel  →  Research Agent  →  Coding Agent  →  Suggestion Engine  →  Dashboard

Each agent contributes its specialized knowledge:
  - Research Agent: CVE lookup, root cause analysis
  - Coding Agent  : patch steps, firewall rules, commands
  - This Engine   : combines everything into one structured recommendation

CHANGE (pg_rag integration):
  Before: LLM had no historical context — every suggestion started from scratch.
  Now:
    - Before calling Research Agent, PgRagStore is queried for past incidents
    - Historical context (how many times threat was seen, what worked before)
      is injected into the LLM prompt
    - After suggestion is COMPLETE, it is stored back into PgRagStore so
      future threats of the same type get even richer context
    - Paging support: if first page of context is not enough, next_cursor
      is passed to get more historical incidents

The final suggestion is:
  1. Saved to SQLite database (persistent, queryable)
  2. Stored in PgRagStore for future RAG retrieval
  3. Exposed via /suggestions API endpoints (consumed by frontend dashboard)
  4. Broadcast on MessageBus so other agents can act on it

Place this file at the ROOT of your project (same level as backend.py).
"""

import json
import time
import threading
import sqlite3
from dataclasses import dataclass, asdict, field
from typing import Optional

from logger import log_info, log_error, log_allowed

# Import the new PostgreSQL RAG store
from rag.pg_rag_store import pg_rag_store


# ── DATA STRUCTURES ───────────────────────────────────────────────────────────

@dataclass
class SuggestionThread:
    """
    Tracks one complete threat-to-suggestion conversation.

    Each field is filled by a different agent in the pipeline.
    The thread_id ties all contributions together.
    """
    thread_id         : str          # unique ID, e.g. "SUGG-1717000000-AGENT-ST-01"
    threat_agent_id   : str          # which agent triggered the alert
    threat_flags      : list         # e.g. ["HIGH_REQUEST_RATE", "DATA_EXFIL"]
    threat_level      : str          # "HIGH" / "MEDIUM" / "LOW"
    consensus_score   : float        # Sentinel's verification confidence 0.0-1.0
    timestamp         : float        # when the threat was confirmed

    # Filled by Research Agent
    research_query    : str  = ""
    research_result   : dict = field(default_factory=dict)
    applicable_cves   : list = field(default_factory=list)
    root_cause        : str  = ""

    # Filled by Coding Agent
    patch_result      : dict = field(default_factory=dict)
    immediate_actions : list = field(default_factory=list)
    longterm_fix      : list = field(default_factory=list)
    patch_commands    : list = field(default_factory=list)

    # RAG context injected before Research step (new)
    rag_context       : str  = ""    # historical context string from PgRagStore
    rag_next_cursor   : float = None  # paging cursor if more context was available

    # Final combined output
    risk_score        : float = 0.0
    risk_impact       : str   = ""
    final_suggestion  : dict  = field(default_factory=dict)
    status            : str   = "PENDING"   # PENDING → RESEARCHING → PATCHING → COMPLETE → FAILED
    completed_at      : float = 0.0


# ── DATABASE ──────────────────────────────────────────────────────────────────

DB_PATH = "suggestions.db"

def _init_suggestions_db():
    """
    Create the suggestions table if it does not exist yet.
    Called once at module import time.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS suggestions (
                thread_id       TEXT PRIMARY KEY,
                agent_id        TEXT NOT NULL,
                threat_level    TEXT NOT NULL,
                threat_flags    TEXT NOT NULL,   -- JSON list
                consensus_score REAL NOT NULL,
                root_cause      TEXT,
                immediate_actions TEXT,           -- JSON list
                longterm_fix    TEXT,             -- JSON list
                applicable_cves TEXT,             -- JSON list
                patch_commands  TEXT,             -- JSON list
                risk_score      REAL,
                risk_impact     TEXT,
                final_suggestion TEXT,            -- full JSON blob
                status          TEXT DEFAULT 'PENDING',
                created_at      REAL NOT NULL,
                completed_at    REAL,
                rag_context_used TEXT             -- was RAG context available (new)
            )
        """)
        # Add rag_context_used column if upgrading from older schema
        try:
            conn.execute("ALTER TABLE suggestions ADD COLUMN rag_context_used TEXT")
        except Exception:
            pass  # column already exists — ignore
        conn.commit()
        conn.close()
        log_info("[SuggestionEngine] Database ready")
    except Exception as e:
        log_error(f"[SuggestionEngine] DB init error: {e}")

_init_suggestions_db()


def _save_suggestion(thread: SuggestionThread):
    """
    Upsert a SuggestionThread into the SQLite database.
    Called after each phase so progress is never lost.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            INSERT OR REPLACE INTO suggestions (
                thread_id, agent_id, threat_level, threat_flags, consensus_score,
                root_cause, immediate_actions, longterm_fix, applicable_cves,
                patch_commands, risk_score, risk_impact, final_suggestion,
                status, created_at, completed_at, rag_context_used
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            thread.thread_id,
            thread.threat_agent_id,
            thread.threat_level,
            json.dumps(thread.threat_flags),
            thread.consensus_score,
            thread.root_cause,
            json.dumps(thread.immediate_actions),
            json.dumps(thread.longterm_fix),
            json.dumps(thread.applicable_cves),
            json.dumps(thread.patch_commands),
            thread.risk_score,
            thread.risk_impact,
            json.dumps(thread.final_suggestion),
            thread.status,
            thread.timestamp,
            thread.completed_at,
            "yes" if thread.rag_context else "no",   # track if RAG context was used
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        log_error(f"[SuggestionEngine] DB save error: {e}")


# ── CORE ENGINE ───────────────────────────────────────────────────────────────

class SuggestionEngine:
    """
    Orchestrates the Research → Coding → Final Suggestion pipeline.

    Usage:
        # At startup, inject references to the agents
        suggestion_engine.set_agents(
            research_agent=research,
            coding_agent=coding,
            sentinel_agent=sentinel,
        )

        # When Sentinel confirms a threat, call:
        suggestion_engine.trigger(threat_payload)
    """

    def __init__(self):
        self._research_agent  = None
        self._coding_agent    = None
        self._sentinel_agent  = None
        self._active_threads  : dict[str, SuggestionThread] = {}
        self._lock            = threading.Lock()

    # ── SETUP ─────────────────────────────────────────────

    def set_agents(self, research_agent, coding_agent, sentinel_agent):
        """
        Inject live agent references.
        Must be called before any threat can be processed.
        """
        self._research_agent = research_agent
        self._coding_agent   = coding_agent
        self._sentinel_agent = sentinel_agent
        log_info("[SuggestionEngine] Agent references registered")

    # ── PUBLIC TRIGGER ────────────────────────────────────

    def trigger(self, threat_payload: dict):
        """
        Entry point: called by Sentinel when a threat is CONFIRMED.

        Runs asynchronously — returns immediately, does NOT block Sentinel.
        The pipeline runs in a background thread so Sentinel stays responsive.

        threat_payload must contain:
            agent_id        : str   — who was flagged
            threat_level    : str   — HIGH / MEDIUM / LOW
            flags           : list  — list of flag strings
            consensus_score : float — Sentinel's confidence score
            threat_type     : str   — optional, used for RAG lookup
        """
        if not self._research_agent or not self._coding_agent:
            log_error("[SuggestionEngine] Cannot trigger — agents not set. Call set_agents() first.")
            return

        thread_id = f"SUGG-{int(time.time())}-{threat_payload.get('agent_id', 'UNKNOWN')}"

        thread = SuggestionThread(
            thread_id       = thread_id,
            threat_agent_id = threat_payload.get("agent_id", "UNKNOWN"),
            threat_flags    = threat_payload.get("flags", []),
            threat_level    = threat_payload.get("threat_level", "MEDIUM"),
            consensus_score = threat_payload.get("consensus_score", 0.5),
            timestamp       = time.time(),
        )

        # Store the threat_type on the thread for RAG lookup (not in dataclass fields
        # to keep backward compat — store in a custom attribute)
        thread._threat_type = threat_payload.get(
            "threat_type",
            thread.threat_flags[0] if thread.threat_flags else "UNKNOWN"
        )

        with self._lock:
            self._active_threads[thread_id] = thread

        log_info(f"[SuggestionEngine] Pipeline started | thread={thread_id}")

        bg = threading.Thread(
            target=self._run_pipeline,
            args=(thread,),
            daemon=True,
            name=f"sugg-{thread_id[-8:]}",
        )
        bg.start()

    # ── PIPELINE ──────────────────────────────────────────

    def _run_pipeline(self, thread: SuggestionThread):
        """
        The full 5-step pipeline running in a background thread.

        Step 0: RAG lookup — fetch historical context from PgRagStore  (NEW)
        Step 1: Ask Research Agent what it knows about these flags/CVEs
        Step 2: Ask Coding Agent to generate patch steps
        Step 2b: Auto-generate firewall rule
        Step 3: Combine everything into a structured final suggestion
        Step 4: Persist to SQLite + store back into PgRagStore          (NEW)
        """
        try:
            # ── STEP 0: RAG CONTEXT RETRIEVAL (NEW) ───────
            self._fetch_rag_context(thread)

            # ── STEP 1: RESEARCH ──────────────────────────
            thread.status = "RESEARCHING"
            _save_suggestion(thread)

            log_info(f"[SuggestionEngine] [{thread.thread_id}] Step 1: Asking Research Agent")
            research_result = self._ask_research(thread)
            thread.research_result  = research_result
            thread.applicable_cves  = research_result.get("relevant_cves", [])
            thread.root_cause       = research_result.get("recommendation", "Unknown root cause")
            _save_suggestion(thread)

            # ── STEP 2: PATCH GENERATION ──────────────────
            thread.status = "PATCHING"
            _save_suggestion(thread)

            log_info(f"[SuggestionEngine] [{thread.thread_id}] Step 2: Asking Coding Agent")
            patch_result = self._ask_coding(thread)
            thread.patch_result      = patch_result
            thread.immediate_actions = patch_result.get("steps", [])
            thread.longterm_fix      = patch_result.get("revert_steps", [])
            thread.patch_commands    = patch_result.get("commands", [])
            _save_suggestion(thread)

            # ── STEP 2b: FIREWALL RULE ────────────────────
            try:
                flags_str = thread.threat_flags[0] if thread.threat_flags else "UNKNOWN"
                threat_ip = getattr(thread, "threat_ip", None) or f"10.0.0.{hash(thread.threat_agent_id) % 254 + 1}"
                fw_rule = self._coding_agent.generate_firewall_rule({
                    "ip"         : threat_ip,
                    "attack_type": flags_str,
                    "agent_id"   : thread.threat_agent_id,
                    "score"      : thread.consensus_score,
                })
                log_info(
                    f"[SuggestionEngine] [{thread.thread_id}] "
                    f"Firewall rule auto-generated | rule_id={fw_rule.get('rule_id', '?')}"
                )
            except Exception as fw_err:
                log_error(f"[SuggestionEngine] Firewall rule generation failed: {fw_err}")

            # ── STEP 3: COMBINE INTO FINAL SUGGESTION ─────
            log_info(f"[SuggestionEngine] [{thread.thread_id}] Step 3: Building final suggestion")
            final = self._build_final_suggestion(thread)
            thread.final_suggestion = final
            thread.risk_score       = self._calculate_risk_score(thread)
            thread.risk_impact      = self._describe_risk_impact(thread)
            thread.status           = "COMPLETE"
            thread.completed_at     = time.time()
            _save_suggestion(thread)

            # ── STEP 4: STORE BACK INTO PG RAG (NEW) ──────
            self._store_to_pg_rag(thread)

            # ── BROADCAST TO DASHBOARD ────────────────────
            if self._sentinel_agent:
                self._sentinel_agent.broadcast("SUGGESTION_READY", {
                    "thread_id"   : thread.thread_id,
                    "agent_id"    : thread.threat_agent_id,
                    "threat_level": thread.threat_level,
                    "risk_score"  : thread.risk_score,
                    "summary"     : final.get("threat_summary", ""),
                    "timestamp"   : thread.completed_at,
                })

            elapsed = thread.completed_at - thread.timestamp
            log_allowed(
                f"[SuggestionEngine] COMPLETE | thread={thread.thread_id} | "
                f"elapsed={elapsed:.1f}s | CVEs={thread.applicable_cves} | "
                f"rag_context={'yes' if thread.rag_context else 'no'}"
            )

        except Exception as e:
            thread.status = "FAILED"
            thread.completed_at = time.time()
            _save_suggestion(thread)
            log_error(f"[SuggestionEngine] Pipeline failed | thread={thread.thread_id} | error={e}")

    # ── RAG STEPS (NEW) ───────────────────────────────────

    def _fetch_rag_context(self, thread: SuggestionThread):
        """
        Step 0: Query PgRagStore for historical context before Research Agent.

        Builds a context string from past incidents of the same threat type.
        This string is later injected into the Research Agent prompt so the
        LLM knows "this has happened before, here is what was found."

        Uses paging: fetches first page (5 docs). If the threat is complex
        (HIGH level), fetches a second page too.
        """
        try:
            threat_type = getattr(thread, "_threat_type", "UNKNOWN")
            flags_text  = " ".join(thread.threat_flags) if thread.threat_flags else threat_type

            # Build search query from flags + threat type
            query = f"{threat_type} {flags_text}".strip()

            # First page
            context_str = pg_rag_store.build_rag_context(
                query     = query,
                page_size = 5,
                cursor    = None,
            )

            # For HIGH threats, fetch a second page for richer context
            if thread.threat_level == "HIGH":
                result_p1 = pg_rag_store.search_paged(query, page_size=5, cursor=None)
                if result_p1["has_more"]:
                    context_p2 = pg_rag_store.build_rag_context(
                        query     = query,
                        page_size = 5,
                        cursor    = result_p1["next_cursor"],
                    )
                    context_str = context_str + "\n\n[PAGE 2]\n" + context_p2
                    thread.rag_next_cursor = result_p1["next_cursor"]

            thread.rag_context = context_str
            log_info(
                f"[SuggestionEngine] [{thread.thread_id}] "
                f"RAG context fetched | chars={len(context_str)} | type={threat_type}"
            )

        except Exception as e:
            # RAG failure must not block the pipeline
            log_error(f"[SuggestionEngine] RAG context fetch failed: {e}")
            thread.rag_context = ""

    def _store_to_pg_rag(self, thread: SuggestionThread):
        """
        Step 4: After suggestion is COMPLETE, store it back into PgRagStore.

        This is how the system learns over time — every completed suggestion
        becomes a future context document for similar threats.

        The stored content is a human-readable summary of:
          - what the threat was
          - what CVEs were found
          - what immediate actions were taken
        """
        try:
            threat_type = getattr(thread, "_threat_type", "UNKNOWN")

            # Build a descriptive content string for future retrieval
            immediate = "; ".join(thread.immediate_actions[:3]) if thread.immediate_actions else "none"
            content = (
                f"Threat: {threat_type} detected on agent {thread.threat_agent_id}. "
                f"Flags: {', '.join(thread.threat_flags)}. "
                f"Severity: {thread.threat_level}. "
                f"Root cause: {thread.root_cause[:200]}. "
                f"CVEs: {', '.join(thread.applicable_cves) if thread.applicable_cves else 'none'}. "
                f"Immediate actions taken: {immediate}. "
                f"Risk score: {thread.risk_score}."
            )

            # Known types are the standard 5 labels; anything else is unknown
            known_types = {
                "BRUTE_FORCE", "DATA_EXFILTRATION", "API_FLOODING",
                "PRIVILEGE_ESCALATION", "NORMAL",
            }
            is_known = threat_type.upper() in known_types

            pg_rag_store.store(
                doc_id        = thread.thread_id,    # suggestion thread_id as doc key
                threat_type   = threat_type,
                content       = content,
                metadata      = {
                    "agent_id"       : thread.threat_agent_id,
                    "flags"          : thread.threat_flags,
                    "consensus_score": thread.consensus_score,
                    "applicable_cves": thread.applicable_cves,
                    "risk_score"     : thread.risk_score,
                    "threat_level"   : thread.threat_level,
                },
                is_known_type = is_known,
            )

            log_info(
                f"[SuggestionEngine] [{thread.thread_id}] "
                f"Stored to PgRagStore | type={threat_type} | known={is_known}"
            )

        except Exception as e:
            # Storing back must not crash the pipeline
            log_error(f"[SuggestionEngine] PgRagStore store-back failed: {e}")

    # ── AGENT QUERIES ─────────────────────────────────────

    def _ask_research(self, thread: SuggestionThread) -> dict:
        """
        Ask Research Agent: "What CVE matches these threat flags?"

        Now injects RAG historical context into the query so the LLM
        knows about past incidents of the same type.
        """
        flags_text = ", ".join(thread.threat_flags) if thread.threat_flags else "suspicious behavior"

        # Build query with RAG context prepended
        rag_prefix = ""
        if thread.rag_context:
            rag_prefix = (
                f"HISTORICAL CONTEXT FROM PAST INCIDENTS:\n"
                f"{thread.rag_context}\n\n"
                f"Based on the above historical data, answer the following:\n"
            )

        query = (
            f"{rag_prefix}"
            f"Threat detected on agent {thread.threat_agent_id}. "
            f"Flags: {flags_text}. "
            f"Threat level: {thread.threat_level}. "
            f"What CVE matches this pattern? What is the root cause?"
        )
        thread.research_query = query

        if hasattr(self._sentinel_agent, "ask_agent"):
            result = self._sentinel_agent.ask_agent(
                target_agent = self._research_agent,
                question     = query,
                context      = {
                    "thread_id"   : thread.thread_id,
                    "flags"       : thread.threat_flags,
                    "threat_level": thread.threat_level,
                    "agent_id"    : thread.threat_agent_id,
                    "rag_context" : thread.rag_context,   # pass context separately too
                },
            )
            if result:
                return result

        log_info("[SuggestionEngine] Falling back to direct search_threats call")
        return self._research_agent.search_threats(query, top_k=3)

    def _ask_coding(self, thread: SuggestionThread) -> dict:
        """
        Ask Coding Agent: "Here is the CVE — give me patch steps."

        Passes the Research Agent's CVE findings as context.
        """
        top_cve            = thread.applicable_cves[0] if thread.applicable_cves else "UNKNOWN-CVE"
        affected_component = thread.threat_agent_id

        if hasattr(self._sentinel_agent, "ask_agent"):
            result = self._sentinel_agent.ask_agent(
                target_agent = self._coding_agent,
                question     = (
                    f"CVE identified: {top_cve}. "
                    f"Affected component: {affected_component}. "
                    f"Root cause: {thread.root_cause}. "
                    f"Generate immediate patch steps and long-term fix."
                ),
                context      = {
                    "thread_id"          : thread.thread_id,
                    "cve_id"             : top_cve,
                    "affected_component" : affected_component,
                    "research_context"   : thread.research_result,
                },
            )
            if result:
                return result

        log_info("[SuggestionEngine] Falling back to direct generate_patch_suggestion call")
        return self._coding_agent.generate_patch_suggestion(top_cve, affected_component)

    # ── FINAL SUGGESTION BUILDER ──────────────────────────

    def _build_final_suggestion(self, thread: SuggestionThread) -> dict:
        """
        Combine Research + Coding outputs into one clean structured suggestion.
        Now includes RAG context info so dashboard shows "based on N past incidents."
        """
        top_cve        = thread.applicable_cves[0] if thread.applicable_cves else "No CVE identified"
        research_level = thread.research_result.get("threat_level", "UNKNOWN")

        # Count how many past incidents were referenced
        rag_incident_count = thread.rag_context.count("[Incident") if thread.rag_context else 0

        return {
            # ── SECTION 1: THREAT SUMMARY ─────────────────
            "threat_summary": {
                "what"           : f"Threat detected on {thread.threat_agent_id}",
                "when"           : time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(thread.timestamp)),
                "severity"       : thread.threat_level,
                "flags"          : thread.threat_flags,
                "confirmed_by"   : "Sentinel Verification Engine",
                "consensus_score": round(thread.consensus_score, 2),
            },

            # ── SECTION 2: ROOT CAUSE (from Research Agent) ─
            "root_cause": {
                "explanation"        : thread.root_cause,
                "applicable_cves"    : thread.applicable_cves,
                "cve_threat_level"   : research_level,
                "research_query"     : thread.research_query,
                "source"             : "Research Agent (CVE Database + RAG)",
                "historical_context" : {                                # NEW
                    "incidents_used" : rag_incident_count,
                    "rag_available"  : bool(thread.rag_context),
                },
            },

            # ── SECTION 3: IMMEDIATE ACTIONS (from Coding Agent) ─
            "immediate_actions": {
                "steps"  : thread.immediate_actions,
                "commands": thread.patch_commands,
                "source" : "Coding Agent (auto-generated, safety-verified)",
            },

            # ── SECTION 4: LONG-TERM FIX ──────────────────
            "longterm_fix": {
                "steps"           : thread.longterm_fix,
                "top_cve_patched" : top_cve,
                "estimated_effort": thread.patch_result.get("estimated_effort", "hours"),
                "source"          : "Coding Agent",
            },

            # ── SECTION 5: RISK SCORE ─────────────────────
            "risk_assessment": {
                "risk_score"      : round(thread.risk_score, 2),
                "risk_impact"     : thread.risk_impact,
                "unmitigated_risk": (
                    "HIGH — continued exploitation likely"
                    if thread.risk_score > 0.7
                    else "MEDIUM — limited exposure if not patched"
                ),
            },

            # ── METADATA ──────────────────────────────────
            "meta": {
                "thread_id"       : thread.thread_id,
                "pipeline_duration": round(time.time() - thread.timestamp, 1),
                "agents_involved" : ["Sentinel", "Research Agent", "Coding Agent", "Suggestion Engine"],
                "generated_at"    : time.time(),
                "rag_context_used": bool(thread.rag_context),           # NEW
                "rag_incidents_referenced": rag_incident_count,         # NEW
            },
        }

    # ── RISK CALCULATION ──────────────────────────────────

    def _calculate_risk_score(self, thread: SuggestionThread) -> float:
        """
        Calculate a 0.0-1.0 risk score.

        Factors:
          - Sentinel's consensus_score      (40% weight)
          - Number of threat flags          (30% weight)
          - CVE severity from Research      (30% weight)
        """
        sentinel_factor = thread.consensus_score * 0.4
        flag_factor     = min(len(thread.threat_flags) / 5.0, 1.0) * 0.3
        severity_map    = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.5, "LOW": 0.2, "UNKNOWN": 0.4}
        cve_level       = thread.research_result.get("threat_level", "UNKNOWN")
        cve_factor      = severity_map.get(cve_level, 0.4) * 0.3
        return round(sentinel_factor + flag_factor + cve_factor, 2)

    def _describe_risk_impact(self, thread: SuggestionThread) -> str:
        """Human-readable description of what happens if this is NOT fixed."""
        score = thread.risk_score
        if score >= 0.8:
            return (
                "CRITICAL: Immediate exploitation likely. "
                "System compromise, data breach, or service outage probable within hours."
            )
        elif score >= 0.6:
            return (
                "HIGH: Significant exposure. "
                "Attacker may escalate privileges or exfiltrate data if not patched."
            )
        elif score >= 0.4:
            return (
                "MEDIUM: Moderate risk. "
                "Limited blast radius, but repeated attempts could succeed."
            )
        else:
            return (
                "LOW: Contained risk. "
                "Monitor and apply patch in next maintenance window."
            )

    # ── QUERY METHODS (for API endpoints) ─────────────────

    def get_all_suggestions(self, limit: int = 50) -> list[dict]:
        """Fetch completed suggestions from DB for dashboard display."""
        try:
            conn = sqlite3.connect(DB_PATH)
            rows = conn.execute("""
                SELECT thread_id, agent_id, threat_level, threat_flags,
                       consensus_score, root_cause, immediate_actions, longterm_fix,
                       applicable_cves, patch_commands, risk_score, risk_impact,
                       final_suggestion, status, created_at, completed_at,
                       rag_context_used
                FROM suggestions
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,)).fetchall()
            conn.close()

            results = []
            for row in rows:
                results.append({
                    "thread_id"         : row[0],
                    "agent_id"          : row[1],
                    "threat_level"      : row[2],
                    "threat_flags"      : json.loads(row[3] or "[]"),
                    "consensus_score"   : row[4],
                    "root_cause"        : row[5],
                    "immediate_actions" : json.loads(row[6] or "[]"),
                    "longterm_fix"      : json.loads(row[7] or "[]"),
                    "applicable_cves"   : json.loads(row[8] or "[]"),
                    "patch_commands"    : json.loads(row[9] or "[]"),
                    "risk_score"        : row[10],
                    "risk_impact"       : row[11],
                    "final_suggestion"  : json.loads(row[12] or "{}"),
                    "status"            : row[13],
                    "created_at"        : row[14],
                    "completed_at"      : row[15],
                    "rag_context_used"  : row[16],   # NEW — frontend can show this
                })
            return results

        except Exception as e:
            log_error(f"[SuggestionEngine] DB query error: {e}")
            return []

    def get_suggestion(self, thread_id: str) -> Optional[dict]:
        """Fetch a single suggestion by its thread_id."""
        all_suggestions = self.get_all_suggestions(limit=1000)
        for s in all_suggestions:
            if s["thread_id"] == thread_id:
                return s
        return None

    def get_active_count(self) -> int:
        """How many suggestions are currently being processed."""
        with self._lock:
            return sum(
                1 for t in self._active_threads.values()
                if t.status in ("PENDING", "RESEARCHING", "PATCHING")
            )

    def get_stats(self) -> dict:
        """Summary stats for the /suggestions/stats endpoint."""
        try:
            conn      = sqlite3.connect(DB_PATH)
            total     = conn.execute("SELECT COUNT(*) FROM suggestions").fetchone()[0]
            complete  = conn.execute("SELECT COUNT(*) FROM suggestions WHERE status='COMPLETE'").fetchone()[0]
            failed    = conn.execute("SELECT COUNT(*) FROM suggestions WHERE status='FAILED'").fetchone()[0]
            avg_score = conn.execute("SELECT AVG(risk_score) FROM suggestions WHERE status='COMPLETE'").fetchone()[0]
            rag_used  = conn.execute("SELECT COUNT(*) FROM suggestions WHERE rag_context_used='yes'").fetchone()[0]
            conn.close()

            # Also get PgRagStore stats
            rag_status = pg_rag_store.get_status()

            return {
                "total_suggestions"      : total,
                "completed"              : complete,
                "failed"                 : failed,
                "active_in_pipeline"     : self.get_active_count(),
                "average_risk_score"     : round(avg_score or 0.0, 2),
                "suggestions_with_rag"   : rag_used,           # NEW
                "rag_document_count"     : rag_status.get("document_count", 0),  # NEW
                "rag_unknown_threats"    : rag_status.get("unknown_threats", 0), # NEW
            }
        except Exception as e:
            log_error(f"[SuggestionEngine] Stats error: {e}")
            return {}


# ── SINGLETON INSTANCE (imported everywhere) ──────────────────────────────────

suggestion_engine = SuggestionEngine()