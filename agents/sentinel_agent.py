"""
agents/sentinel_agent.py

Sentinel Agent — AGENT-ST-01
Upgraded with:
  1. ResultVerifier integration — every detection verified before action
  2. Cryptographer reference — can request token revocation
  3. Research Agent reference — gets CVE context for detections
  4. False positive tracking — accuracy metrics reported to dashboard
"""

import time
import requests
from agents.base_agent import BaseAgent
from config.settings import MOCK_MODE, BACKEND_URL
from logger import log_info, log_threat, log_blocked, log_error
from suggestion_engine import suggestion_engine
from anomaly_detection.anomaly_detector import AnomalyDetector
from verification.result_verifier import ResultVerifier, AgentClaim
from dataclasses import asdict
from threat_intelligence import threat_tracker

# Suggestion Engine — imported lazily to avoid circular imports
_suggestion_engine = None

SENTINEL_PROMPT = """You are The Sentinel — the AI monitoring agent for NFTCipher.

Analyze agent behavior and detect threats using ONLY observed facts with specific numbers.

Flag as THREAT if:
  - Same agent making too many requests (cite exact count vs baseline of 20)
  - Agent trying unauthorized access (cite failed attempt count vs baseline of 5)
  - Unusual data export — cite exact MB vs baseline of 50MB
  - Metric deviations beyond defined baselines

Flag as NORMAL if:
  - All metrics within baseline limits
  - Access patterns consistent with agent role

ALWAYS cite specific numbers in your reasoning. Never speculate."""


class SentinelAgent(BaseAgent):

    def __init__(self):
        super().__init__(
            agent_id      = "AGENT-ST-01",
            role          = "Sentinel",
            system_prompt = SENTINEL_PROMPT,
        )
        self.threat_log       = []
        self.monitored_agents = {}
        self.anomaly_detector = AnomalyDetector()
        self._adversary_ref   = None

        # Verification engine — all claims go through this
        self.verifier = ResultVerifier()

        # Agent references set by backend at startup
        self._cryptographer_ref = None
        self._research_ref      = None

        # Accuracy tracking
        self.confirmed_threats = 0
        self.false_positives   = 0

        # Verification history — stored for dashboard
        self._latest_verification    = None
        self._verification_history   = []
        self._total_scans            = 0

        # Suggestion Engine reference — set by backend after all agents ready
        self._suggestion_engine = None

        log_info("[Sentinel] Initialized with verification engine")

    # ── BACKGROUND CYCLE ──────────────────────────────────
    def run_cycle(self):
        """
        Runs every 15 seconds.
        Fetches recent logs from backend and scans monitored agents.
        """
        log_info("[Sentinel] Background cycle")

        try:
            token    = self._ensure_token()
            response = requests.get(
                f"{BACKEND_URL}/logs",
                headers = {"Authorization": f"Bearer {token}"},
                params  = {"limit": 20},
                timeout = 5,
            )
            if response.status_code == 200:
                logs = response.json()
                log_info(f"[Sentinel] Fetched {len(logs)} logs from backend")
        except Exception as e:
            log_error(f"[Sentinel] Backend log fetch error: {e}")

        # ── Ensure all known agents exist in monitored_agents ──────────
        # This guarantees history populates from first cycle, even before
        # any agent makes 20+ requests
        _KNOWN_AGENTS = [
            "AGENT-ST-01", "AGENT-AR-01", "AGENT-DA-01",
            "AGENT-CA-01", "AGENT-AD-01", "AGENT-CR-01",
            "AGENT-RE-01", "AGENT-CO-01", "AGENT-VS-01",
            "AGENT-TD-01",
        ]
        now = time.time()
        for ag_id in _KNOWN_AGENTS:
            if ag_id not in self.monitored_agents:
                self.monitored_agents[ag_id] = {
                    "request_count": 0,
                    "actions":       [],
                    "first_seen":    now,
                }

        # ── Scan ALL monitored agents every cycle ───────────────────────
        # FIXED: was only scanning agents with >20 requests, meaning
        # _verification_history stayed empty on fresh start.
        for agent_id, agent_data in list(self.monitored_agents.items()):
            self._auto_scan(agent_id, agent_data)

        # Broadcast cycle status
        self.broadcast("INFO", {
            "event":           "SENTINEL_CYCLE",
            "agent_id":        self.agent_id,
            "monitored":       len(self.monitored_agents),
            "total_threats":   len(self.threat_log),
            "confirmed":       self.confirmed_threats,
            "false_positives": self.false_positives,
            "timestamp":       time.time(),
        })
        threat_tracker.check_and_close_stale_sessions()
        # ── Record adversary threats into DB ─────────────────────────────
        for msg in list(getattr(self, "_pending_threat_msgs", [])):
            try:
                _flag_map = {
                    "BRUTE_FORCE":             "BRUTE_FORCE",
                    "TOKEN_HIJACKING":         "TOKEN_HIJACKING",
                    "API_FLOODING":            "API_FLOODING",
                    "DATA_EXFILTRATION":       "DATA_EXFILTRATION",
                    "PRIVILEGE_ESCALATION":    "PRIVILEGE_ESCALATION",
                    "NETWORK_ANOMALY":         "NETWORK_ANOMALY",
                    "HIGH_REQUEST_COUNT":      "BRUTE_FORCE",
                    "HIGH_RPM":                "API_FLOODING",
                    "DISTRIBUTED":             "DISTRIBUTED_ATTACK",
                    "DATA_EXFIL":              "DATA_EXFILTRATION",
                }
                _flags  = msg.get("flags", [])
                _ttype  = "UNKNOWN_THREAT"
                for _f in _flags:
                    _key = str(_f).split(":")[0].upper()
                    if _key in _flag_map:
                        _ttype = _flag_map[_key]
                        break
                if _ttype == "UNKNOWN_THREAT" and msg.get("event"):
                    _ev = msg["event"].upper()
                    if "BRUTE"   in _ev: _ttype = "BRUTE_FORCE"
                    elif "TOKEN" in _ev: _ttype = "TOKEN_HIJACKING"
                    elif "FLOOD" in _ev: _ttype = "API_FLOODING"
                    elif "EXFIL" in _ev: _ttype = "DATA_EXFILTRATION"
                threat_tracker.record_threat(
                    threat_type     = _ttype,
                    agent_id        = msg.get("agent_id", "AGENT-AD-01"),
                    flags           = _flags,
                    consensus_score = msg.get("score", 0.85),
                    metadata        = msg,
                )
            except Exception:
                pass
        self._pending_threat_msgs = []

    def _auto_scan(self, agent_id: str, agent_data: dict):
        """
        Automatically analyze an agent in the background cycle.
        Called every 15 seconds for every monitored agent.

        Fix: The old code calculated ml_risk with a manual formula
             (0.3 + req_count * 0.01) instead of calling the real trained
             RandomForest model. Now self.anomaly_detector.detect() is called
             so the ML vote in the consensus engine reflects the actual model.
        """
        req_count      = agent_data.get("request_count", 0)
        unique_actions = len(set(agent_data.get("actions", [])))
        first_seen     = agent_data.get("first_seen", time.time())
        elapsed_min    = max((time.time() - first_seen) / 60, 1)

        # --- Real ML model call (was a manual formula before) ---
        ml_result = self.anomaly_detector.detect(
            agent_id   = agent_id,
            agent_data = {
                "request_count":   req_count,
                "failed_attempts": 0,
                "data_size":       0,
                "unique_actions":  unique_actions,
                "time_window":     60,
                "repeated_action": False,
                "unusual_hour":    False,
            },
        )
        ml_risk = ml_result["risk_score"]

        # Build flags from ML output + rule thresholds
        flags = []
        if req_count > 20:
            flags.append("HIGH_REQUEST_COUNT")
        if ml_result["is_anomaly"]:
            flags.append(f"ML_{ml_result['attack_type']}")

        # For normal (no-flag) scans: skip LLM to avoid rate limiting on
        # 10 agents/cycle. ML + Rules layers still run and return a verdict.
        if not flags:
            from verification.result_verifier import ConsensusEngine, ActionGate, IntegrityHasher
            import hashlib, json as _json

            _ce          = ConsensusEngine()
            _llm_result  = {
                "verdict":    "NORMAL",
                "confidence": ml_risk * 0.4,
                "reasoning":  "Baseline scan — no flags",
                "penalized":  False,
            }
            _rule_result = {
                "verdict":    "NORMAL",
                "confidence": max(1.0 - ml_risk, 0.1),
                "reasoning":  "No rules triggered",
            }
            _consensus     = _ce.vote(_llm_result, ml_risk, _rule_result)
            _action        = ActionGate().decide(_consensus["consensus_score"], flags)
            _hash_payload  = _json.dumps(
                {"agent_id": agent_id, "flags": flags, "ts": time.time()},
                sort_keys=True,
            )
            _integrity     = hashlib.sha256(_hash_payload.encode()).hexdigest()[:16]

            final_verdict   = "NORMAL" if not _consensus["majority_threat"] else "UNCERTAIN"
            consensus_score = _consensus["consensus_score"]
            vote_breakdown  = {
                "llm":   round(_llm_result["confidence"], 4),
                "ml":    round(ml_risk, 4),          # now real model score
                "rules": round(_rule_result["confidence"], 4),
            }
            action_level   = _action
            integrity_hash = _integrity
            notes          = []

        else:
            # Full 4-layer verification with LLM when flags exist
            claim = AgentClaim(
                agent_id     = agent_id,
                claim_type   = "THREAT",
                confidence   = ml_risk,
                flags        = flags,
                raw_evidence = {
                    "request_count":   req_count,
                    "rpm":             req_count / elapsed_min,
                    "failed_attempts": 0,
                    "data_mb":         0,
                },
                llm_reason = "Auto-scan: threshold exceeded",
            )
            verified        = self.verifier.verify(claim, self, ml_risk_score=ml_risk)
            final_verdict   = verified.final_verdict
            consensus_score = verified.consensus_score
            vote_breakdown  = verified.vote_breakdown
            action_level    = verified.action_level
            integrity_hash  = verified.integrity_hash
            notes           = verified.notes

            if action_level == "AUTO_BLOCK":
                self._execute_block(agent_id, flags, consensus_score)

        # Update accuracy counters
        if final_verdict == "FALSE_POSITIVE":
            self.false_positives += 1
        elif final_verdict == "CONFIRMED_THREAT":
            self.confirmed_threats += 1
            try:
                from threat_intelligence import threat_tracker
                # ml_result not available here — derive type from flags
                _flag_to_type = {
                    "ML_BRUTE_FORCE":          "BRUTE_FORCE",
                    "HIGH_REQUEST_COUNT":       "BRUTE_FORCE",
                    "BRUTE_FORCE":              "BRUTE_FORCE",
                    "ML_DATA_EXFILTRATION":     "DATA_EXFILTRATION",
                    "LARGE_DATA_EXPORT":        "DATA_EXFILTRATION",
                    "DATA_EXFIL":               "DATA_EXFILTRATION",
                    "ML_API_FLOODING":          "API_FLOODING",
                    "HIGH_RPM":                 "API_FLOODING",
                    "ML_PRIVILEGE_ESCALATION":  "PRIVILEGE_ESCALATION",
                    "LATERAL_MOVEMENT":         "PRIVILEGE_ESCALATION",
                    "NETWORK_ANOMALY":          "NETWORK_ANOMALY",
                    "ML_BASELINE_DEVIATION":    "ANOMALY",
                    "DISTRIBUTED":              "DISTRIBUTED_ATTACK",
                }
                _ttype = "UNKNOWN_THREAT"
                for flag in (flags or []):
                    flag_upper = str(flag).split(":")[0].upper()
                    if flag_upper in _flag_to_type:
                        _ttype = _flag_to_type[flag_upper]
                        break
                threat_tracker.record_threat(
                    threat_type     = _ttype,
                    agent_id        = agent_id,
                    flags           = flags or [],
                    consensus_score = consensus_score,
                )
            except Exception as _e:
                pass

        # Store for dashboard
        self._total_scans = getattr(self, "_total_scans", 0) + 1
        _ver_record = {
            "agent_id":        agent_id,
            "final_verdict":   final_verdict,
            "consensus_score": consensus_score,
            "action_level":    action_level,
            "vote_breakdown":  vote_breakdown,
            "integrity_hash":  integrity_hash,
            "flags":           flags,
            "ml_detection":    ml_result["attack_type"],   # real model label
            "ml_risk_score":   ml_risk,                    # real model score
            "llm_reason":      "Auto-scan: background cycle" if not flags
                               else "Auto-scan: anomaly detected by ML model",
            "notes":           notes,
            "timestamp":       time.time(),
        }
        self._latest_verification = _ver_record
        if not hasattr(self, "_verification_history"):
            self._verification_history = []
        self._verification_history.append(_ver_record)
        if len(self._verification_history) > 100:
            self._verification_history = self._verification_history[-100:]

    # ── AGENT REFERENCES ──────────────────────────────────
    def set_adversary_ref(self, adversary_agent):
        self._adversary_ref = adversary_agent
        log_info("[Sentinel] Adversary reference connected")

    def set_cryptographer_ref(self, cryptographer_agent):
        self._cryptographer_ref = cryptographer_agent
        log_info("[Sentinel] Cryptographer reference connected")

    def set_research_ref(self, research_agent):
        self._research_ref = research_agent
        log_info("[Sentinel] Research reference connected")
        # Wire Suggestion Engine with Research Agent as soon as reference is available
        suggestion_engine.set_agents(
            research_agent = research_agent,
            coding_agent   = getattr(self, "_coding_ref", None),
            sentinel_agent = self,
        )

    def set_suggestion_engine(self, suggestion_engine):
        self._suggestion_engine = suggestion_engine
        log_info("[Sentinel] Suggestion Engine connected")

    def set_coding_ref(self, coding_agent):
        """Store Coding Agent reference and wire it to Suggestion Engine."""
        self._coding_ref = coding_agent
        log_info("[Sentinel] Coding reference connected")
        # Wire Suggestion Engine with Coding Agent as soon as reference is available
        suggestion_engine.set_agents(
            research_agent = getattr(self, "_research_ref", None),
            coding_agent   = coding_agent,
            sentinel_agent = self,
        )

    # ── BLOCK EXECUTION ───────────────────────────────────
    def _execute_block(self, agent_id: str, flags: list, score: float):
        """
        Execute a verified block decision.
        Revokes tokens via Cryptographer, blocks agent directly if possible.
        """
        log_threat(f"[Sentinel] Executing block | agent={agent_id} | score={score:.2f}")

        # Ask Cryptographer to revoke all tokens
        if self._cryptographer_ref:
            self._cryptographer_ref.revoke_all_tokens(
                agent_id = agent_id,
                reason   = f"Sentinel verified block: {flags}",
            )

        # Block adversary directly if it is the adversary agent
        if agent_id == "AGENT-AD-01":
            self.block_adversary_directly(reason=f"Verified: {flags} | score={score:.2f}")
        else:
            self.send_message(agent_id, "BLOCK", {
                "target_id": agent_id,
                "reason":    f"Sentinel verified block: {flags}",
                "score":     score,
            })

        self.broadcast("THREAT", {
            "event":      "AGENT_BLOCKED",
            "agent_id":   agent_id,
            "flags":      flags,
            "score":      score,
            "blocked_by": self.agent_id,
            "timestamp":  time.time(),
        })

    def block_adversary_directly(self, reason: str = "Threat detected"):
        """Direct block of Adversary Agent via stored reference."""
        log_threat(f"[Sentinel] Direct block: Adversary | reason={reason}")

        if self._adversary_ref:
            self._adversary_ref.receive_block_signal(reason)
            log_blocked("[Sentinel] Adversary BLOCKED via direct ref")

        try:
            token = self._ensure_token()
            requests.post(
                f"{BACKEND_URL}/admin/lockdown/AGENT-AD-01",
                headers = {"Authorization": f"Bearer {token}"},
                timeout = 5,
            )
        except Exception as e:
            log_error(f"[Sentinel] Backend lockdown call failed: {e}")

        self.broadcast("THREAT", {
            "event":      "ADVERSARY_BLOCKED",
            "blocked_by": self.agent_id,
            "reason":     reason,
            "timestamp":  time.time(),
        })

    # ── MAIN ANALYZE — with verification ──────────────────
    def analyze_behavior(self, token: str, agent_id: str,
                         action: str, metadata: dict) -> dict:
        """
        Two-step process:
          Step 1: Detect using ML + rules + LLM
          Step 2: Verify using 4-layer consensus engine
        Action is only taken after Step 2 confirms the threat.
        """
        log_info(f"[Sentinel] Analyzing [{agent_id}] → [{action}]")

        if not self.authenticate(token):
            return {
                "agent_id":    agent_id,
                "is_threat":   False,
                "threat_level":"UNKNOWN",
                "flags":       [],
                "reason":      "Authentication failed",
                "status":      "DENIED",
            }

        # Track this agent
        if agent_id not in self.monitored_agents:
            self.monitored_agents[agent_id] = {
                "request_count": 0,
                "actions":       [],
                "first_seen":    time.time(),
            }

        agent_data = self.monitored_agents[agent_id]
        agent_data["request_count"] += 1
        agent_data["actions"].append(action)

        req_count      = agent_data["request_count"]
        data_size      = metadata.get("data_size", 0)
        unique_actions = len(set(agent_data["actions"]))

        # Step 1a — Rule-based flag detection
        flags = []
        if req_count > 20:                             flags.append("HIGH_REQUEST_COUNT")
        if agent_data["actions"].count(action) > 5:   flags.append("REPEATED_ACTION")
        if unique_actions > 8:                         flags.append("LATERAL_MOVEMENT")
        if data_size > 1000:                           flags.append("LARGE_DATA_EXPORT")

        # Step 1b — ML anomaly detection
        ml_result = self.anomaly_detector.detect(
            agent_id   = agent_id,
            agent_data = {
                "request_count":   req_count,
                "failed_attempts": self.memory.failed_attempts,
                "data_size":       data_size,
                "unique_actions":  unique_actions,
                "time_window":     60,
                "repeated_action": "REPEATED_ACTION" in flags,
                "unusual_hour":    False,
            },
        )

        if ml_result["is_anomaly"]:
            flags.append(f"ML_{ml_result['attack_type']}")

        # Step 1c — Get research context if Research Agent is connected
        research_context = metadata.get("research_context", "")
        if not research_context and self._research_ref and flags:
            research_context = self._research_ref.get_context_for_threat(
                flags    = flags,
                evidence = {
                    "rpm":             req_count / max((time.time() - agent_data["first_seen"]) / 60, 1),
                    "failed_attempts": self.memory.failed_attempts,
                    "data_mb":         data_size / 1024,
                },
            )

        # Step 1d — LLM analysis (only if flags exist)
        llm_reason = ""
        if flags:
            decision = self.think(
                task    = (
                    f"Agent [{agent_id}] triggered flags: {flags}. "
                    f"ML: {ml_result['attack_type']} risk={ml_result['risk_score']:.2f}. "
                    f"Research context: {research_context[:200]}. Is this a real threat?"
                ),
                context = {
                    "agent_id":       agent_id,
                    "action":         action,
                    "flags":          str(flags),
                    "ml_detection":   ml_result["attack_type"],
                    "ml_risk_score":  ml_result["risk_score"],
                    "request_count":  req_count,
                    "metadata":       str(metadata)[:300],
                },
            )
            llm_reason = decision.get("reason", "")

        # Step 2 — Verify the claim
        claim = AgentClaim(
            agent_id     = agent_id,
            claim_type   = "THREAT" if flags else "NORMAL",
            confidence   = ml_result["risk_score"],
            flags        = flags,
            raw_evidence = {
                "request_count":   req_count,
                "rpm":             req_count / max((time.time() - agent_data["first_seen"]) / 60, 1),
                "failed_attempts": self.memory.failed_attempts,
                "data_mb":         data_size / 1024,
                "unique_actions":  unique_actions,
            },
            llm_reason = llm_reason,
        )

        verified = self.verifier.verify(claim, self, ml_risk_score=ml_result["risk_score"])

        # Determine final values from verification
        is_threat    = verified.final_verdict == "CONFIRMED_THREAT"
        threat_level = (
            "HIGH"   if is_threat and len(flags) > 2 else
            "MEDIUM" if is_threat else
            "LOW"
        )

        # Track accuracy
        if verified.final_verdict == "FALSE_POSITIVE":
            self.false_positives += 1
        elif verified.final_verdict == "CONFIRMED_THREAT":
            self.confirmed_threats += 1

        # ── Store for dashboard /security/latest-verification & /security/verification-history ──
        self._total_scans = getattr(self, "_total_scans", 0) + 1
        _ver_record = {
            "agent_id":        agent_id,
            "final_verdict":   verified.final_verdict,
            "consensus_score": verified.consensus_score,
            "action_level":    verified.action_level,
            "vote_breakdown":  verified.vote_breakdown,
            "integrity_hash":  verified.integrity_hash,
            "flags":           flags,
            "ml_detection":    ml_result["attack_type"],
            "ml_risk_score":   ml_result["risk_score"],
            "llm_reason":      llm_reason,
            "notes":           verified.notes,
            "timestamp":       time.time(),
        }
        self._latest_verification = _ver_record
        if not hasattr(self, "_verification_history"):
            self._verification_history = []
        self._verification_history.append(_ver_record)
        if len(self._verification_history) > 100:   # keep last 100
            self._verification_history = self._verification_history[-100:]

        result = {
            "agent_id":         agent_id,
            "action":           action,
            "is_threat":        is_threat,
            "threat_level":     threat_level,
            "flags":            flags,
            "ml_detection":     ml_result["attack_type"],
            "ml_risk_score":    ml_result["risk_score"],
            "verified":         True,
            "final_verdict":    verified.final_verdict,
            "consensus_score":  verified.consensus_score,
            "action_level":     verified.action_level,
            "vote_breakdown":   verified.vote_breakdown,
            "false_positive":   verified.final_verdict == "FALSE_POSITIVE",
            "integrity_hash":   verified.integrity_hash,
            "notes":            verified.notes,
            "research_context": research_context,
            "request_count":    req_count,
            "timestamp":        time.time(),
        }

        if is_threat:
            self.threat_log.append(result)
            _threat_type = ml_result.get("attack_type", "UNKNOWN")
            if _threat_type in ("NORMAL", "", None):
                # ML said normal but flags exist — derive from flags
                if "ML_BRUTE_FORCE" in flags or "HIGH_REQUEST_COUNT" in flags:
                    _threat_type = "BRUTE_FORCE"
                elif "ML_DATA_EXFILTRATION" in flags or "LARGE_DATA_EXPORT" in flags:
                    _threat_type = "DATA_EXFILTRATION"
                elif "ML_API_FLOODING" in flags:
                    _threat_type = "API_FLOODING"
                elif "ML_PRIVILEGE_ESCALATION" in flags or "LATERAL_MOVEMENT" in flags:
                    _threat_type = "PRIVILEGE_ESCALATION"
                else:
                    # Unknown — use first flag as type name so it gets tracked
                    _threat_type = flags[0] if flags else "UNKNOWN_THREAT"
 
            threat_tracker.record_threat(
                threat_type     = _threat_type,
                agent_id        = agent_id,
                flags           = flags,
                consensus_score = verified.consensus_score,
                metadata        = {
                    "action"      : action,
                    "threat_level": threat_level,
                    "ml_score"    : ml_result.get("risk_score", 0.0),
                },
            )
            log_threat(
                f"[Sentinel] VERIFIED THREAT | agent={agent_id} | "
                f"level={threat_level} | score={verified.consensus_score:.2f} | "
                f"action={verified.action_level}"
            )

            # Execute action based on verification result
            if verified.action_level == "AUTO_BLOCK":
                self._execute_block(agent_id, flags, verified.consensus_score)

            self.broadcast("THREAT", {
                "event":           "VERIFIED_THREAT",
                "agent_id":        agent_id,
                "threat_level":    threat_level,
                "flags":           flags,
                "consensus_score": verified.consensus_score,
                "action_level":    verified.action_level,
                "vote_breakdown":  verified.vote_breakdown,
                "timestamp":       time.time(),
            })

            # Directly call CodingAgent to generate firewall rule.
            # MessageBus broadcast is unreliable for cross-agent triggering because
            # CodingAgent only reads its inbox every 30s in run_cycle.
            # Direct call is synchronous and guaranteed to produce a rule immediately.
            _coding = getattr(self, "_coding_ref", None)
            if _coding is not None:
                try:
                    import threading
                    _threat_info = {
                        "ip":          metadata.get("ip") or metadata.get("source_ip", f"10.0.0.{abs(hash(agent_id)) % 254 + 1}"),
                        "attack_type": flags[0] if flags else ml_result.get("attack_type", "UNKNOWN"),
                        "agent_id":    agent_id,
                        "score":       verified.consensus_score,
                    }
                    threading.Thread(
                        target=_coding.generate_firewall_rule,
                        args=(_threat_info,),
                        daemon=True,
                    ).start()
                    log_info(f"[Sentinel] Firewall rule generation triggered for {agent_id}")
                except Exception as _e:
                    log_error(f"[Sentinel] Could not trigger firewall rule: {_e}")

            # Automatically generate suggestion after confirmed threat
            # Suggestion Engine asks Research + Coding agents and builds recommendation
            if self._suggestion_engine is not None:
                try:
                    import threading
                    evidence = {
                        "request_count":   req_count,
                        "rpm":             req_count / max((time.time() - agent_data["first_seen"]) / 60, 1),
                        "failed_attempts": self.memory.failed_attempts,
                        "data_mb":         data_size / 1024,
                    }
                    # Background thread mein chalao — main flow block na ho
                    threading.Thread(
                        target = self._generate_suggestion_async,
                        args   = (verified, flags, evidence, agent_id),
                        daemon = True,
                    ).start()
                except Exception as e:
                    log_error(f"[Sentinel] Suggestion trigger error: {e}")

            # Trigger Suggestion Engine — starts Research→Coding pipeline.
            # Non-blocking: runs in background thread, Sentinel stays responsive.
            suggestion_engine.trigger({
                "agent_id"       : agent_id,
                "threat_level"   : threat_level,
                "flags"          : flags,
                "consensus_score": verified.consensus_score,
                "action_level"   : verified.action_level,
                "timestamp"      : time.time(),
            })

        elif verified.final_verdict == "FALSE_POSITIVE":
            log_info(f"[Sentinel] FALSE POSITIVE caught | agent={agent_id} | original flags: {flags}")
            self.send_message(agent_id, "INFO", {
                "event":    "FALSE_POSITIVE_CLEARED",
                "agent_id": agent_id,
                "flags":    flags,
                "reason":   "Consensus engine overrode raw detection",
            })

        else:
            log_info(f"[Sentinel] NORMAL | agent={agent_id} | ML risk: {ml_result['risk_score']:.2f}")

        return result

    def _generate_suggestion_async(self, verified, flags: list,
                                    evidence: dict, agent_id: str):
        """
        Trigger suggestion pipeline in background thread.
        Uses trigger() -- the correct public method of SuggestionEngine.
        Runs Research -> Coding -> Final Suggestion pipeline autonomously.
        """
        try:
            log_info(f"[Sentinel] Triggering suggestion pipeline | agent={agent_id}")
            # Use trigger() which is the actual public method on SuggestionEngine
            self._suggestion_engine.trigger({
                "agent_id"       : agent_id,
                "threat_level"   : verified.action_level if hasattr(verified, 'action_level') else 'HIGH',
                "flags"          : flags,
                "consensus_score": verified.consensus_score if hasattr(verified, 'consensus_score') else 0.8,
                "action_level"   : verified.action_level if hasattr(verified, 'action_level') else 'ALERT',
                "threat_type"    : flags[0] if flags else 'UNKNOWN',
                "timestamp"      : time.time(),
            })
            log_info(f"[Sentinel] Suggestion pipeline triggered | agent={agent_id} | flags={flags}")
        except Exception as e:
            log_error(f"[Sentinel] Suggestion trigger failed: {e}")

    def get_threat_report(self) -> dict:
        return {
            "total_threats":     len(self.threat_log),
            "monitored_agents":  len(self.monitored_agents),
            "confirmed_threats": self.confirmed_threats,
            "false_positives":   self.false_positives,
            "accuracy":          f"{round(self.confirmed_threats / max(self.confirmed_threats + self.false_positives, 1) * 100, 1)}%",
            "recent_threats":    self.threat_log[-5:],
        }

    def get_status(self) -> dict:
        base = super().get_status()
        base.update({
            "total_threats":            len(self.threat_log),
            "monitored_agents":         len(self.monitored_agents),
            "confirmed_threats":        self.confirmed_threats,
            "false_positives":          self.false_positives,
            "adversary_linked":         self._adversary_ref is not None,
            "cryptographer_linked":     self._cryptographer_ref is not None,
            "research_linked":          self._research_ref is not None,
            "suggestion_engine_linked": self._suggestion_engine is not None,
            "verifier_active":          True,
        })
        return base