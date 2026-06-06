"""
The Arbiter - Decision Agent — AUTONOMOUS VERSION
Central brain of NftCipher.

Now the Arbiter actively monitors agents in the background,
takes decisions using the LLM, and automatically triggers lockdowns.
"""
import time
import requests
from agents.base_agent import BaseAgent
from config.settings import MOCK_MODE, BACKEND_URL
from verification.result_verifier import ResultVerifier, AgentClaim

# Mock fallback — used if backend is unavailable
MOCK_PERMISSIONS = {
    "AGENT-DA-01": ["read_database", "fetch_users", "fetch_logs"],
    "AGENT-CA-01": ["call_cloud", "aws_s3", "aws_ec2", "aws_lambda"],
    "AGENT-AR-01": ["arbitrate", "allow", "deny"],
    "AGENT-ST-01": ["monitor", "scan_logs", "flag_threat"],
    "AGENT-AD-01": ["simulate_attack"],
}

RISK_LOW    = 0.3
RISK_MEDIUM = 0.6
RISK_HIGH   = 0.9

ARBITER_PROMPT = """You are The Arbiter — the central security decision agent for NftCipher.
Your job is to ALLOW or DENY every request based on security rules.

Rules you MUST follow:
- If token is invalid → DENY immediately
- If agent does not have permission → DENY immediately
- If request pattern looks suspicious → DENY
- If risk score is HIGH (above 0.8) → DENY
- Only ALLOW if everything checks out perfectly
- You are the last line of defense — be strict
"""


class ArbiterAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            agent_id="AGENT-AR-01",
            role="Arbiter",
            system_prompt=ARBITER_PROMPT
        )

        self.blocked_agents = []
        self.request_counts = {}
        self.request_times  = {}

        # Verification engine — autonomous monitoring decisions go through this
        # so Arbiter blocks are consensus-based, not just risk-score-based
        self.verifier = ResultVerifier()

        # Anomaly detector — used in autonomous monitoring cycle
        from anomaly_detection.anomaly_detector import AnomalyDetector
        self.anomaly_detector = AnomalyDetector()

        # These agents are monitored autonomously by the Arbiter
        self._monitor_agents = [
            "AGENT-DA-01",
            "AGENT-CA-01",
            "AGENT-ST-01",
            "AGENT-AD-01"
        ]

        self._monitor_index = 0

    # ── AUTONOMOUS CYCLE ────────────────────────────────────
    def run_cycle(self):
        """
        Runs every 20 seconds.
        Fix: Old code blocked agents based only on risk_score >= 0.9 and
        LLM opinion — no consensus verification. Now every autonomous block
        goes through ResultVerifier (4-layer: LLM + ML + Rules + Hash) before
        any action is taken, same as Sentinel does.
        """

        # Check one agent per cycle (rotating)
        agent_to_check = self._monitor_agents[
            self._monitor_index % len(self._monitor_agents)
        ]
        self._monitor_index += 1

        # Skip if already blocked
        if agent_to_check in self.blocked_agents:
            self.broadcast("INFO", {
                "event":     "ARBITER_SKIP",
                "agent_id":  self.agent_id,
                "target":    agent_to_check,
                "reason":    "Already blocked",
                "timestamp": time.time(),
            })
            return

        risk = self.calculate_risk_score(agent_to_check, "autonomous_health_check")
        req_count = self.request_counts.get(agent_to_check, 0)

        # --- Real ML score from AnomalyDetector (not just risk formula) ---
        ml_result = self.anomaly_detector.detect(
            agent_id   = agent_to_check,
            agent_data = {
                "request_count":   req_count,
                "failed_attempts": 0,
                "data_size":       0,
                "unique_actions":  1,
                "time_window":     60,
                "repeated_action": False,
                "unusual_hour":    False,
            },
        )
        ml_risk = ml_result["risk_score"]

        # Build flags from risk score + ML output
        flags = []
        if risk >= 0.5:
            flags.append("HIGH_REQUEST_COUNT")
        if ml_result["is_anomaly"]:
            flags.append(f"ML_{ml_result['attack_type']}")

        # --- Run through 4-layer verifier before any block decision ---
        claim = AgentClaim(
            agent_id     = agent_to_check,
            claim_type   = "THREAT" if flags else "NORMAL",
            confidence   = max(risk, ml_risk),
            flags        = flags,
            raw_evidence = {
                "request_count":   req_count,
                "rpm":             req_count / 1.0,
                "failed_attempts": 0,
                "data_mb":         0,
            },
            llm_reason = f"Arbiter autonomous check — risk={risk:.2f}",
        )

        verified = self.verifier.verify(claim, self, ml_risk_score=ml_risk)

        # Broadcast full verification result to dashboard
        self.broadcast("INFO", {
            "event":           "ARBITER_MONITOR",
            "agent_id":        self.agent_id,
            "target":          agent_to_check,
            "risk_score":      round(risk, 2),
            "ml_risk":         round(ml_risk, 2),
            "final_verdict":   verified.final_verdict,
            "consensus_score": verified.consensus_score,
            "action_level":    verified.action_level,
            "vote_breakdown":  verified.vote_breakdown,
            "integrity_hash":  verified.integrity_hash[:16],
            "flags":           flags,
            "timestamp":       time.time(),
        })

        # Only block if verifier confirms — not just on raw risk score
        if verified.action_level == "AUTO_BLOCK":
            self.block_agent(
                agent_to_check,
                f"Arbiter verified block — consensus={verified.consensus_score:.2f} "
                f"flags={flags}",
            )
            self.broadcast("THREAT", {
                "event":           "ARBITER_AUTO_LOCKDOWN",
                "agent_id":        self.agent_id,
                "target":          agent_to_check,
                "consensus_score": verified.consensus_score,
                "vote_breakdown":  verified.vote_breakdown,
                "flags":           flags,
                "integrity_hash":  verified.integrity_hash[:16],
                "timestamp":       time.time(),
            })

    # ── RISK SCORE ──────────────────────────────────────────
    def calculate_risk_score(self, agent_id: str, action: str) -> float:

        risk = 0.0

        if agent_id in self.blocked_agents:
            return 1.0

        current_time = time.time()

        if agent_id in self.request_times:

            time_diff = current_time - self.request_times[agent_id]
            count     = self.request_counts.get(agent_id, 0)

            if time_diff < 60 and count > 10:
                risk += 0.5

        suspicious_keywords = [
            "delete",
            "drop",
            "hack",
            "bypass",
            "admin",
            "root"
        ]

        for keyword in suspicious_keywords:
            if keyword in action.lower():
                risk += 0.4

        self.request_counts[agent_id] = (
            self.request_counts.get(agent_id, 0) + 1
        )

        self.request_times[agent_id] = current_time

        return min(risk, 1.0)

    # ── PERMISSION CHECK ────────────────────────────────────
    def check_permission(self, agent_id: str, action: str) -> bool:

        try:
            response = requests.get(
                f"{BACKEND_URL}/rbac/my-permissions",
                headers=self._backend_headers(),
                timeout=5
            )

            if response.status_code == 200:

                permissions = response.json().get("permissions", [])

                if "admin:all" in permissions:
                    return True

                for perm in permissions:
                    if perm.split(":")[0] in action.lower():
                        return True

                agent_perms = MOCK_PERMISSIONS.get(agent_id, [])

                for perm in agent_perms:
                    if perm in action.lower():
                        return True

                return False

        except Exception:
            pass

        permissions = MOCK_PERMISSIONS.get(agent_id, [])

        for perm in permissions:
            if perm in action.lower():
                return True

        return False

    # ── MAIN ARBITRATE (Called through API) ───────────────
    def arbitrate(self, token: str, agent_id: str, action: str) -> dict:
        """
        Main function — ALLOW or DENY.

        Flow:
        Token → Permission → Risk Score → ML → 4-Layer Verifier → Decision

        Fix: Old Step 3 blocked agents directly when risk >= 0.9 without
        running the verification engine. Now the final block/allow decision
        always goes through ResultVerifier so Arbiter decisions are
        consensus-verified (LLM + ML + Rules), not just risk-score-gated.
        """

        # Step 1 — Validate token
        if not self.authenticate(token):
            return {
                "decision":   "DENY",
                "reason":     "Invalid or expired token",
                "risk_score": 1.0,
                "agent_id":   agent_id,
                "verified":   False,
            }

        # Step 2 — Permission check (hard gate — no need to verify further)
        has_permission = self.check_permission(agent_id, action)
        if not has_permission:
            self.log_action(f"NO_PERMISSION_{agent_id}", False)
            return {
                "decision":   "DENY",
                "reason":     f"Agent [{agent_id}] has no permission for [{action}]",
                "risk_score": 0.0,
                "agent_id":   agent_id,
                "verified":   False,
            }

        # Step 3 — Risk score + ML anomaly detection
        risk_score = self.calculate_risk_score(agent_id, action)
        req_count  = self.request_counts.get(agent_id, 0)

        ml_result = self.anomaly_detector.detect(
            agent_id   = agent_id,
            agent_data = {
                "request_count":   req_count,
                "failed_attempts": 0,
                "data_size":       0,
                "unique_actions":  1,
                "time_window":     60,
                "repeated_action": False,
                "unusual_hour":    False,
            },
        )
        ml_risk = ml_result["risk_score"]

        # Build flags
        flags = []
        if risk_score >= RISK_MEDIUM:
            flags.append("HIGH_REQUEST_COUNT")
        if ml_result["is_anomaly"]:
            flags.append(f"ML_{ml_result['attack_type']}")

        # Step 4 — Run 4-layer verification (LLM + ML + Rules + Hash)
        # This is the key fix: block only happens if verifier confirms,
        # not just because risk_score crossed a threshold.
        claim = AgentClaim(
            agent_id     = agent_id,
            claim_type   = "THREAT" if flags else "NORMAL",
            confidence   = max(risk_score, ml_risk),
            flags        = flags,
            raw_evidence = {
                "request_count":   req_count,
                "rpm":             req_count / 1.0,
                "failed_attempts": 0,
                "data_mb":         0,
            },
            llm_reason = (
                f"Arbiter arbitrate check — risk={risk_score:.2f} "
                f"action={action}"
            ),
        )

        verified = self.verifier.verify(claim, self, ml_risk_score=ml_risk)

        # Broadcast full verification result to dashboard
        self.broadcast("INFO", {
            "event":           "ARBITER_DECISION",
            "agent_id":        self.agent_id,
            "target":          agent_id,
            "action":          action,
            "risk_score":      round(risk_score, 2),
            "ml_risk":         round(ml_risk, 2),
            "final_verdict":   verified.final_verdict,
            "consensus_score": verified.consensus_score,
            "action_level":    verified.action_level,
            "vote_breakdown":  verified.vote_breakdown,
            "integrity_hash":  verified.integrity_hash[:16],
            "flags":           flags,
            "timestamp":       time.time(),
        })

        # Step 5 — Final decision based on verified result
        if verified.action_level == "AUTO_BLOCK":
            self.block_agent(
                agent_id,
                f"Arbiter verified block — consensus={verified.consensus_score:.2f} "
                f"flags={flags}",
            )
            self.log_action(f"BLOCKED_{agent_id}", False)
            return {
                "decision":        "DENY",
                "reason":          (
                    f"Verified threat — consensus={verified.consensus_score:.2f} "
                    f"flags={flags}"
                ),
                "risk_score":      risk_score,
                "agent_id":        agent_id,
                "verified":        True,
                "consensus_score": verified.consensus_score,
                "integrity_hash":  verified.integrity_hash[:16],
            }

        if verified.final_verdict in ("CONFIRMED_THREAT", "UNCERTAIN") and \
           verified.action_level == "ALERT":
            # Threat flagged but not severe enough for auto-block
            self.log_action(f"ALERT_{agent_id}_{action}", False)
            return {
                "decision":        "DENY",
                "reason":          (
                    f"Alert-level threat — consensus={verified.consensus_score:.2f}"
                ),
                "risk_score":      risk_score,
                "agent_id":        agent_id,
                "verified":        True,
                "consensus_score": verified.consensus_score,
            }

        # Verifier cleared — ALLOW
        self.log_action(f"ALLOWED_{agent_id}_{action}", True)
        return {
            "decision":        "ALLOW",
            "reason":          "All checks passed — verifier cleared",
            "risk_score":      risk_score,
            "agent_id":        agent_id,
            "verified":        True,
            "consensus_score": verified.consensus_score,
            "integrity_hash":  verified.integrity_hash[:16],
        }

    # ── AUTO LOCKDOWN (Also called by Sentinel) ────────────
    def block_agent(self, agent_id: str, reason: str):
        """
        Force block.

        This can be called by the Sentinel agent
        or by the autonomous monitoring cycle.

        Auto-lockdown is also triggered on the backend.
        """

        if agent_id not in self.blocked_agents:

            self.blocked_agents.append(agent_id)

            # Trigger backend lockdown API
            try:
                requests.post(
                    f"{BACKEND_URL}/admin/lockdown/{agent_id}",
                    headers=self._backend_headers(),
                    timeout=5
                )

            except Exception:
                pass

            self.log_action(
                f"FORCE_BLOCKED_{agent_id}",
                False
            )

    def get_status(self) -> dict:

        base = super().get_status()

        base["autonomous"]     = self._running
        base["blocked_agents"] = self.blocked_agents
        base["total_requests"] = sum(self.request_counts.values())

        base["backend"] = (
            "connected"
            if self.backend_token
            else "disconnected"
        )

        return base