"""
orchestration/langgraph_orchestrator.py

LangGraph Orchestrator — replaces threading with structured graph-based flow.

Why LangGraph over threading:
  - Shared state across all agents — every agent sees the same picture
  - Conditional edges — Sentinel detects → Verifier runs → Arbiter acts (automatic)
  - Checkpointing — system crash hone pe same state se resume
  - Clear flow control — no race conditions between agents

Graph structure:
  START
    ↓
  [research_node]     — fetch latest threat intel
    ↓
  [sentinel_node]     — monitor + detect threats
    ↓
  [threat_det_node]   — phishing, malware, network check
    ↓
  [vision_node]       — physical security check
    ↓
  [verify_node]       — verify all claims (2-of-3 consensus)
    ↓
  conditional_edge:
    CONFIRMED_THREAT  → [arbiter_node] → [cryptographer_node] → [coding_node]
    FALSE_POSITIVE    → [END]
    NORMAL            → [END]
    ↓
  END
"""

import time
import json
from typing import TypedDict, Annotated, Any
from logger import log_info, log_threat, log_error, log_blocked

# LangGraph imports
# LangGraph imports
try:
    from langgraph.graph import StateGraph, START, END

    try:
        from langgraph.checkpoint.memory import MemorySaver as SqliteSaver
    except ImportError:
        SqliteSaver = None

    _LANGGRAPH_AVAILABLE = True
    log_info("[Orchestrator] LangGraph loaded successfully")
except ImportError:
    _LANGGRAPH_AVAILABLE = False
    log_error("[Orchestrator] LangGraph not found. Install: pip install langgraph")


# ── Shared State Definition ───────────────────────────────
# This is the single shared state that all agents read and write
# Every agent gets this state as input and returns updated state

class SecurityState(TypedDict):
    """
    Shared state passed between all agents in the graph.
    Each node reads what it needs and writes its results back.
    """
    # Current cycle metadata
    cycle_id:          str
    cycle_start:       float
    timestamp:         float

    # Input event (what triggered this cycle)
    trigger_event:     str        # "scheduled", "threat_detected", "manual"
    trigger_agent:     str        # which agent triggered
    trigger_payload:   dict       # raw trigger data

    # Research results
    research_context:  str        # CVE context from Research Agent
    threat_intel:      dict       # full research result

    # Detection results from each agent
    sentinel_result:   dict       # Sentinel's behavioral analysis
    threat_det_result: dict       # ThreatDetection's findings
    vision_result:     dict       # Vision Agent's physical findings

    # Aggregated flags and evidence
    all_flags:         list       # combined flags from all detectors
    all_evidence:      dict       # combined evidence metrics
    ml_risk_score:     float      # highest ML risk score seen

    # Verification result
    verification_done:   bool
    final_verdict:       str      # CONFIRMED_THREAT | FALSE_POSITIVE | UNCERTAIN | NORMAL
    consensus_score:     float
    action_level:        str      # AUTO_BLOCK | ALERT | WATCHLIST | IGNORE
    integrity_hash:      str

    # Actions taken
    arbiter_decision:    dict
    crypto_action:       dict
    coding_action:       dict

    # Cycle summary
    errors:              list
    completed:           bool


def _default_state(trigger: str = "scheduled") -> SecurityState:
    """Create a fresh state for each cycle."""
    import uuid
    return SecurityState(
        cycle_id          = str(uuid.uuid4())[:8],
        cycle_start       = time.time(),
        timestamp         = time.time(),
        trigger_event     = trigger,
        trigger_agent     = "orchestrator",
        trigger_payload   = {},
        research_context  = "",
        threat_intel      = {},
        sentinel_result   = {},
        threat_det_result = {},
        vision_result     = {},
        all_flags         = [],
        all_evidence      = {},
        ml_risk_score     = 0.0,
        verification_done = False,
        final_verdict     = "NORMAL",
        consensus_score   = 0.0,
        action_level      = "IGNORE",
        integrity_hash    = "",
        arbiter_decision  = {},
        crypto_action     = {},
        coding_action     = {},
        errors            = [],
        completed         = False,
    )


# ── Graph Nodes ───────────────────────────────────────────
# Each node is a function that takes state and returns updated state
# Nodes never modify state in place — they return a new dict with changes

def research_node(state: SecurityState, research_agent) -> dict:
    """
    Node 1 — AI Research Agent
    Fetches relevant threat intel based on current flags.
    Runs first so other agents have CVE context available.
    """
    log_info(f"[Graph] research_node | cycle={state['cycle_id']}")
    try:
        # Build search query from any existing flags
        existing_flags = state.get("all_flags", [])
        query = " ".join(f.replace("_", " ").lower() for f in existing_flags) or "latest security threats"

        result = research_agent.search_threats(query, top_k=3)

        context = ""
        if result.get("relevant_cves"):
            context = (
                f"Related CVEs: {result['relevant_cves']} | "
                f"Threat level: {result.get('threat_level', 'UNKNOWN')} | "
                f"Recommendation: {result.get('recommendation', 'N/A')}"
            )

        return {
            "research_context": context,
            "threat_intel":     result,
        }

    except Exception as e:
        log_error(f"[Graph] research_node error: {e}")
        return {"errors": state.get("errors", []) + [f"research_node: {e}"]}


def sentinel_node(state: SecurityState, sentinel_agent) -> dict:
    """
    Node 2 — Sentinel Agent
    Behavioral monitoring — analyzes agent activity for anomalies.
    Uses research context from previous node to ground its analysis.
    """
    log_info(f"[Graph] sentinel_node | cycle={state['cycle_id']}")
    try:
        token   = sentinel_agent._ensure_token()
        payload = state.get("trigger_payload", {})

        # Pull metrics from trigger payload or use defaults for scheduled cycles
        agent_id = payload.get("agent_id", "AGENT-AD-01")
        action   = payload.get("action",   "scheduled_scan")
        metadata = payload.get("metadata", {
            "data_size":      0,
            "request_count":  5,
            "rpm":            5.0,
        })

        # Inject research context into sentinel's analysis
        if state.get("research_context"):
            metadata["research_context"] = state["research_context"]

        result = sentinel_agent.analyze_behavior(token, agent_id, action, metadata)

        # Collect flags and evidence for aggregation
        new_flags    = state.get("all_flags", []) + result.get("flags", [])
        new_evidence = {**state.get("all_evidence", {}), **{
            "request_count":   metadata.get("request_count", 0),
            "rpm":             metadata.get("rpm", 0),
            "failed_attempts": sentinel_agent.memory.failed_attempts,
            "data_mb":         metadata.get("data_size", 0) / 1024,
        }}

        return {
            "sentinel_result": result,
            "all_flags":       list(set(new_flags)),
            "all_evidence":    new_evidence,
            "ml_risk_score":   max(
                state.get("ml_risk_score", 0.0),
                result.get("ml_risk_score", 0.0)
            ),
        }

    except Exception as e:
        log_error(f"[Graph] sentinel_node error: {e}")
        return {"errors": state.get("errors", []) + [f"sentinel_node: {e}"]}


def threat_detection_node(state: SecurityState, threat_det_agent) -> dict:
    """
    Node 3 — Threat Detection Agent
    Runs phishing + malware + network checks in parallel.
    Results feed into the verification node.
    """
    log_info(f"[Graph] threat_detection_node | cycle={state['cycle_id']}")
    try:
        payload    = state.get("trigger_payload", {})
        td_results = {}

        # Network anomaly check — always runs
        traffic_data = {
            "rpm":             state["all_evidence"].get("rpm", 5.0),
            "failed_attempts": state["all_evidence"].get("failed_attempts", 0),
            "unique_ips":      payload.get("unique_ips", 1),
            "data_mb":         state["all_evidence"].get("data_mb", 0),
        }
        network_result     = threat_det_agent.detect_network_anomaly(traffic_data)
        td_results["network"] = network_result

        # Phishing check — only if URL provided in trigger
        if payload.get("url"):
            phishing_result       = threat_det_agent.detect_phishing(payload["url"])
            td_results["phishing"] = phishing_result

        # Malware check — only if content provided
        if payload.get("content"):
            malware_result       = threat_det_agent.analyze_malware(payload["content"])
            td_results["malware"] = malware_result

        # Aggregate flags from threat detection
        new_flags = list(state.get("all_flags", []))
        for engine, result in td_results.items():
            if result.get("verdict") in ("PHISHING", "MALWARE", "ANOMALY"):
                new_flags.append(f"{engine.upper()}_DETECTED")

        return {
            "threat_det_result": td_results,
            "all_flags":         list(set(new_flags)),
            "ml_risk_score":     max(
                state.get("ml_risk_score", 0.0),
                network_result.get("rule_score", 0.0),
            ),
        }

    except Exception as e:
        log_error(f"[Graph] threat_detection_node error: {e}")
        return {"errors": state.get("errors", []) + [f"threat_detection_node: {e}"]}


def vision_node(state: SecurityState, vision_agent) -> dict:
    """
    Node 4 — Vision Agent
    Physical security scan of all monitored locations.
    Physical threats are added to the shared flags list.
    """
    log_info(f"[Graph] vision_node | cycle={state['cycle_id']}")
    try:
        payload     = state.get("trigger_payload", {})
        new_flags   = list(state.get("all_flags", []))
        vision_result = {}

        # If a frame description is provided — analyze it directly
        if payload.get("frame_description"):
            vision_result = vision_agent.analyze_frame_description(
                description = payload["frame_description"],
                location    = payload.get("location", "Unknown"),
            )
            if vision_result.get("threat_detected"):
                new_flags.append("PHYSICAL_ANOMALY")

        # Otherwise run the standard location scan
        else:
            import random
            location = random.choice(vision_agent.MONITORED_LOCATIONS)
            scan     = vision_agent._scan_location(location)
            vision_result = scan
            if scan.get("anomaly_detected"):
                new_flags.append("PHYSICAL_ANOMALY")
                new_flags.append(scan.get("event_type", "UNKNOWN_PHYSICAL"))

        return {
            "vision_result": vision_result,
            "all_flags":     list(set(new_flags)),
        }

    except Exception as e:
        log_error(f"[Graph] vision_node error: {e}")
        return {"errors": state.get("errors", []) + [f"vision_node: {e}"]}


def verify_node(state: SecurityState, sentinel_agent) -> dict:
    """
    Node 5 — Verification Engine
    Aggregates all detection results and runs 4-layer verification.
    This node is the single source of truth for threat verdicts.
    No action is taken without passing through this node first.
    """
    log_info(f"[Graph] verify_node | cycle={state['cycle_id']} | flags={state.get('all_flags', [])}")
    try:
        from verification.result_verifier import ResultVerifier, AgentClaim

        flags    = state.get("all_flags", [])
        evidence = state.get("all_evidence", {})

        # If no flags at all — skip verification, mark as normal
        if not flags:
            log_info(f"[Graph] verify_node: no flags — marking NORMAL")
            return {
                "verification_done": True,
                "final_verdict":     "NORMAL",
                "consensus_score":   0.0,
                "action_level":      "IGNORE",
                "integrity_hash":    "",
            }

        # Build a unified claim from all collected evidence
        claim = AgentClaim(
            agent_id     = "ORCHESTRATOR",
            claim_type   = "THREAT",
            confidence   = state.get("ml_risk_score", 0.5),
            flags        = flags,
            raw_evidence = {
                "request_count":   evidence.get("request_count", 0),
                "rpm":             evidence.get("rpm", 0),
                "failed_attempts": evidence.get("failed_attempts", 0),
                "data_mb":         evidence.get("data_mb", 0),
            },
            llm_reason = f"Orchestrator aggregated flags: {flags}",
        )

        verifier = ResultVerifier()
        verified = verifier.verify(
            claim         = claim,
            agent         = sentinel_agent,
            ml_risk_score = state.get("ml_risk_score", 0.5),
        )

        log_info(
            f"[Graph] verify_node result: {verified.final_verdict} | "
            f"score={verified.consensus_score:.2f} | action={verified.action_level}"
        )

        return {
            "verification_done": True,
            "final_verdict":     verified.final_verdict,
            "consensus_score":   verified.consensus_score,
            "action_level":      verified.action_level,
            "integrity_hash":    verified.integrity_hash,
        }

    except Exception as e:
        log_error(f"[Graph] verify_node error: {e}")
        return {
            "verification_done": True,
            "final_verdict":     "UNCERTAIN",
            "errors": state.get("errors", []) + [f"verify_node: {e}"],
        }


def arbiter_node(state: SecurityState, arbiter_agent) -> dict:
    """
    Node 6 — Arbiter Agent
    Only reached when verification confirms a threat.
    Makes the final allow/deny/escalate decision.
    """
    log_info(f"[Graph] arbiter_node | verdict={state.get('final_verdict')} | action={state.get('action_level')}")
    try:
        token  = arbiter_agent._ensure_token()
        result = arbiter_agent.make_decision(
            token      = token,
            agent_id   = state["trigger_payload"].get("agent_id", "AGENT-AD-01"),
            action     = f"verified_threat:{state['final_verdict']}",
            threat_data = {
                "flags":           state.get("all_flags", []),
                "consensus_score": state.get("consensus_score", 0.0),
                "action_level":    state.get("action_level", "ALERT"),
                "from_graph":      True,
            },
        )

        return {"arbiter_decision": result}

    except Exception as e:
        log_error(f"[Graph] arbiter_node error: {e}")
        return {"errors": state.get("errors", []) + [f"arbiter_node: {e}"]}


def cryptographer_node(state: SecurityState, crypto_agent) -> dict:
    """
    Node 7 — Cryptographer Agent
    Revokes tokens and rotates keys for compromised agents.
    Runs after Arbiter confirms block decision.
    """
    log_info(f"[Graph] cryptographer_node | action={state.get('action_level')}")
    try:
        target_agent = state["trigger_payload"].get("agent_id", "AGENT-AD-01")
        action_level = state.get("action_level", "ALERT")

        if action_level == "AUTO_BLOCK":
            # Revoke all tokens for the blocked agent
            revoked = crypto_agent.revoke_all_tokens(
                agent_id = target_agent,
                reason   = f"Verified threat: score={state.get('consensus_score', 0):.2f}",
            )
            # Issue new keys so system can recover
            crypto_agent.issue_keys(target_agent)

            return {"crypto_action": {
                "action":       "TOKENS_REVOKED_KEYS_ROTATED",
                "agent_id":     target_agent,
                "revoked":      revoked,
                "timestamp":    time.time(),
            }}

        elif action_level == "ALERT":
            # Just rotate keys as a precaution
            crypto_agent.issue_keys(target_agent)
            return {"crypto_action": {
                "action":    "KEYS_ROTATED_PRECAUTION",
                "agent_id":  target_agent,
                "timestamp": time.time(),
            }}

        return {"crypto_action": {"action": "NO_CRYPTO_ACTION_NEEDED"}}

    except Exception as e:
        log_error(f"[Graph] cryptographer_node error: {e}")
        return {"errors": state.get("errors", []) + [f"cryptographer_node: {e}"]}


def coding_node(state: SecurityState, coding_agent) -> dict:
    """
    Node 8 — Coding Agent
    Auto-generates firewall rules and incident response scripts.
    Only runs for AUTO_BLOCK or ALERT level threats.
    """
    log_info(f"[Graph] coding_node | action={state.get('action_level')}")
    try:
        action_level = state.get("action_level", "IGNORE")
        target       = state["trigger_payload"].get("agent_id", "unknown")
        flags        = state.get("all_flags", [])

        if action_level in ("AUTO_BLOCK", "ALERT"):
            # Generate firewall rule
            rule = coding_agent.generate_firewall_rule({
                "ip":          state["trigger_payload"].get("ip", "0.0.0.0"),
                "attack_type": flags[0] if flags else "UNKNOWN",
                "agent_id":    target,
                "score":       state.get("consensus_score", 0.0),
            })

            # Generate incident response script
            script = coding_agent.generate_incident_response({
                "type":     f"GRAPH_{action_level}",
                "agent_id": target,
                "flags":    flags,
                "score":    state.get("consensus_score", 0.0),
            })

            return {"coding_action": {
                "firewall_rule":  rule.get("rule", ""),
                "ir_script_id":  script.get("script_id", ""),
                "generated_at":  time.time(),
            }}

        return {"coding_action": {"action": "NO_CODE_NEEDED"}}

    except Exception as e:
        log_error(f"[Graph] coding_node error: {e}")
        return {"errors": state.get("errors", []) + [f"coding_node: {e}"]}


def complete_node(state: SecurityState) -> dict:
    """
    Final node — marks cycle as complete and logs summary.
    Always reached regardless of threat verdict.
    """
    duration = time.time() - state.get("cycle_start", time.time())
    log_info(
        f"[Graph] Cycle complete | id={state.get('cycle_id')} | "
        f"verdict={state.get('final_verdict')} | "
        f"score={state.get('consensus_score', 0):.2f} | "
        f"duration={duration:.2f}s"
    )
    return {
        "completed":  True,
        "timestamp":  time.time(),
    }


# ── Conditional Routing ───────────────────────────────────

def route_after_verify(state: SecurityState) -> str:
    """
    Conditional edge after verification node.
    Determines which node to go to based on verdict.

    CONFIRMED_THREAT → arbiter (take action)
    anything else   → complete (end cycle)
    """
    verdict      = state.get("final_verdict", "NORMAL")
    action_level = state.get("action_level", "IGNORE")

    if verdict == "CONFIRMED_THREAT" and action_level in ("AUTO_BLOCK", "ALERT"):
        log_info(f"[Graph] Routing to arbiter | verdict={verdict} | action={action_level}")
        return "arbiter"

    log_info(f"[Graph] Routing to complete | verdict={verdict}")
    return "complete"


# ── Main Orchestrator Class ───────────────────────────────

class LangGraphOrchestrator:
    """
    Main orchestrator — builds and runs the security agent graph.

    Usage in backend.py:
        orchestrator = LangGraphOrchestrator(
            sentinel_agent, arbiter_agent, cryptographer_agent,
            research_agent, coding_agent, vision_agent, threat_det_agent
        )
        orchestrator.start()

        # Run one cycle manually
        result = orchestrator.run_cycle(trigger="scheduled")

        # Run with a specific threat event
        result = orchestrator.run_cycle(
            trigger  = "threat_detected",
            payload  = {"agent_id": "AGENT-AD-01", "url": "http://phishing.com"}
        )
    """

    def __init__(self,
                 sentinel_agent,
                 arbiter_agent,
                 cryptographer_agent,
                 research_agent,
                 coding_agent,
                 vision_agent,
                 threat_det_agent):

        self._sentinel     = sentinel_agent
        self._arbiter      = arbiter_agent
        self._crypto       = cryptographer_agent
        self._research     = research_agent
        self._coding       = coding_agent
        self._vision       = vision_agent
        self._threat_det   = threat_det_agent

        self._graph        = None
        self._compiled     = None
        self._running      = False
        self._cycle_count  = 0
        self._cycle_history: list = []

        self._langgraph_ok = _LANGGRAPH_AVAILABLE

        if self._langgraph_ok:
            self._build_graph()
        else:
            log_error("[Orchestrator] LangGraph not available — running in fallback threading mode")

        log_info(f"[Orchestrator] Initialized | langgraph={self._langgraph_ok}")

    def _build_graph(self):
        """
        Build the StateGraph with all nodes and edges.
        Called once at startup — graph structure never changes at runtime.
        """
        log_info("[Orchestrator] Building security graph")

        graph = StateGraph(SecurityState)

        # Add all nodes — each wraps the agent with the shared state interface
        graph.add_node("research",      lambda s: research_node(s, self._research))
        graph.add_node("sentinel",      lambda s: sentinel_node(s, self._sentinel))
        graph.add_node("threat_det",    lambda s: threat_detection_node(s, self._threat_det))
        graph.add_node("vision",        lambda s: vision_node(s, self._vision))
        graph.add_node("verify",        lambda s: verify_node(s, self._sentinel))
        graph.add_node("arbiter",       lambda s: arbiter_node(s, self._arbiter))
        graph.add_node("cryptographer", lambda s: cryptographer_node(s, self._crypto))
        graph.add_node("coding",        lambda s: coding_node(s, self._coding))
        graph.add_node("complete",      complete_node)

        # Define edges — the flow between nodes
        graph.add_edge(START,        "research")
        graph.add_edge("research",   "sentinel")
        graph.add_edge("sentinel",   "threat_det")
        graph.add_edge("threat_det", "vision")
        graph.add_edge("vision",     "verify")

        # Conditional edge after verification
        graph.add_conditional_edges(
            "verify",
            route_after_verify,
            {
                "arbiter":  "arbiter",
                "complete": "complete",
            }
        )

        # Threat response chain
        graph.add_edge("arbiter",       "cryptographer")
        graph.add_edge("cryptographer", "coding")
        graph.add_edge("coding",        "complete")
        graph.add_edge("complete",      END)

        # Compile with SQLite checkpointing
        # State is saved after every node — crash recovery works automatically
        # Compile with checkpointing
        try:
            if SqliteSaver is not None:
                try:
                    from config.settings import LANGGRAPH_DB_PATH
                    checkpointer   = SqliteSaver.from_conn_string(LANGGRAPH_DB_PATH)
                    self._compiled = graph.compile(checkpointer=checkpointer)
                    log_info("[Orchestrator] Graph compiled with SQLite checkpointer")
                except Exception:
                    checkpointer   = SqliteSaver()
                    self._compiled = graph.compile(checkpointer=checkpointer)
                    log_info("[Orchestrator] Graph compiled with Memory checkpointer")
            else:
                self._compiled = graph.compile()
                log_info("[Orchestrator] Graph compiled without checkpointer")
        except Exception as e:
            log_error(f"[Orchestrator] Checkpointer failed: {e} — compiling without checkpoint")
            self._compiled = graph.compile()

        self._graph = graph
        log_info("[Orchestrator] Graph built successfully")

    def run_cycle(self, trigger: str = "scheduled", payload: dict = None) -> dict:
        """
        Run one complete security cycle through the graph.
        All agents execute in order, state flows between them automatically.

        trigger: "scheduled" | "threat_detected" | "manual"
        payload: optional dict with event-specific data
        """
        self._cycle_count += 1
        log_info(f"[Orchestrator] Starting cycle #{self._cycle_count} | trigger={trigger}")

        # Build initial state
        initial_state = _default_state(trigger)
        if payload:
            initial_state["trigger_payload"] = payload
            initial_state["trigger_agent"]   = payload.get("source_agent", "external")

        if self._langgraph_ok and self._compiled:
            try:
                # Run the graph — LangGraph handles node execution order
                config = {"configurable": {"thread_id": initial_state["cycle_id"]}}
                result = self._compiled.invoke(initial_state, config=config)

                self._cycle_history.append({
                    "cycle_id":      result.get("cycle_id"),
                    "trigger":       trigger,
                    "verdict":       result.get("final_verdict"),
                    "score":         result.get("consensus_score"),
                    "action":        result.get("action_level"),
                    "duration":      time.time() - initial_state["cycle_start"],
                    "timestamp":     time.time(),
                })

                log_info(
                    f"[Orchestrator] Cycle #{self._cycle_count} done | "
                    f"verdict={result.get('final_verdict')} | "
                    f"score={result.get('consensus_score', 0):.2f}"
                )
                return dict(result)

            except Exception as e:
                log_error(f"[Orchestrator] Graph execution error: {e}")
                return self._fallback_cycle(initial_state, trigger, payload)
        else:
            return self._fallback_cycle(initial_state, trigger, payload)

    def _fallback_cycle(self, state: dict, trigger: str, payload: dict) -> dict:
        """
        Fallback when LangGraph is not available.
        Runs all agents sequentially using direct calls.
        Same logic, no graph structure.
        """
        log_info("[Orchestrator] Running fallback cycle (no LangGraph)")
        try:
            # Research
            r_result = self._research.search_threats("security threats", top_k=2)
            state["research_context"] = r_result.get("recommendation", "")

            # Sentinel
            token     = self._sentinel._ensure_token()
            p         = payload or {}
            s_result  = self._sentinel.analyze_behavior(
                token, p.get("agent_id", "AGENT-AD-01"),
                p.get("action", "scan"), p.get("metadata", {})
            )
            state["sentinel_result"] = s_result
            state["all_flags"]       = s_result.get("flags", [])

            # Verification
            state["final_verdict"]   = s_result.get("final_verdict", "NORMAL")
            state["consensus_score"] = s_result.get("consensus_score", 0.0)
            state["action_level"]    = s_result.get("action_level", "IGNORE")
            state["completed"]       = True

        except Exception as e:
            log_error(f"[Orchestrator] Fallback cycle error: {e}")
            state["errors"] = [str(e)]

        return state

    def get_status(self) -> dict:
        return {
            "langgraph_available": self._langgraph_ok,
            "graph_compiled":      self._compiled is not None,
            "cycle_count":         self._cycle_count,
            "recent_cycles":       self._cycle_history[-5:],
            "nodes": [
                "research", "sentinel", "threat_det",
                "vision", "verify", "arbiter",
                "cryptographer", "coding", "complete"
            ],
        }