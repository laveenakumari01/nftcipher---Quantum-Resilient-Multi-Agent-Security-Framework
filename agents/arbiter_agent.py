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
        The background thread calls this every 20 seconds.

        The Arbiter automatically reviews agents and asks the LLM
        whether there is any suspicious activity.
        """

        # Check one agent per cycle (rotating)
        agent_to_check = self._monitor_agents[
            self._monitor_index % len(self._monitor_agents)
        ]

        self._monitor_index += 1

        # Skip if already blocked
        if agent_to_check in self.blocked_agents:

            self.broadcast("INFO", {
                "event":      "ARBITER_SKIP",
                "agent_id":   self.agent_id,
                "target":     agent_to_check,
                "reason":     "Already blocked",
                "timestamp":  time.time()
            })

            return

        risk = self.calculate_risk_score(
            agent_to_check,
            "autonomous_health_check"
        )

        # Ask the LLM whether this agent is safe
        decision = self.think(
            task=(
                f"Autonomous monitoring: Agent [{agent_to_check}] "
                f"has risk score {risk:.2f}. "
                f"Should I flag it or is it safe?"
            ),

            context={
                "target_agent":   agent_to_check,
                "risk_score":     risk,
                "blocked_agents": self.blocked_agents,
                "request_count":  self.request_counts.get(agent_to_check, 0),
                "mode":           "autonomous_monitor"
            }
        )

        # Send LLM reasoning and status to dashboard
        self.broadcast("INFO", {
            "event":       "ARBITER_MONITOR",
            "agent_id":    self.agent_id,
            "target":      agent_to_check,
            "risk_score":  round(risk, 2),
            "llm_action":  decision.get("action", "unknown"),
            "llm_reason":  decision.get("reason", ""),
            "llm_safe":    decision.get("safe", True),
            "timestamp":   time.time()
        })

        # If the LLM marks it unsafe → trigger auto-lockdown
        if not decision.get("safe") or risk >= RISK_HIGH:

            self.block_agent(
                agent_to_check,
                f"Arbiter autonomous flag — LLM: {decision.get('reason')}"
            )

            self.broadcast("THREAT", {
                "event":       "ARBITER_AUTO_LOCKDOWN",
                "agent_id":    self.agent_id,
                "target":      agent_to_check,
                "risk_score":  round(risk, 2),
                "llm_reason":  decision.get("reason"),
                "timestamp":   time.time()
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
        Token → Risk Score → Permission → ML → LLM → Decision
        """

        # Step 1 — Validate token
        if not self.authenticate(token):

            return {
                "decision":   "DENY",
                "reason":     "Invalid or expired token",
                "risk_score": 1.0,
                "agent_id":   agent_id
            }

        # Step 2 — Calculate risk score
        risk_score = self.calculate_risk_score(agent_id, action)

        # Step 3 — High risk → deny and trigger auto-lockdown
        if risk_score >= RISK_HIGH:

            self.block_agent(
                agent_id,
                f"Risk too high: {risk_score:.2f}"
            )

            self.log_action(f"BLOCKED_{agent_id}", False)

            return {
                "decision":   "DENY",
                "reason": (
                    f"Risk score too high: {risk_score:.2f} "
                    f"— Auto-lockdown triggered"
                ),
                "risk_score": risk_score,
                "agent_id":   agent_id
            }

        # Step 4 — Permission check
        has_permission = self.check_permission(agent_id, action)

        if not has_permission:

            self.log_action(f"NO_PERMISSION_{agent_id}", False)

            return {
                "decision":   "DENY",
                "reason": (
                    f"Agent [{agent_id}] has no permission "
                    f"for [{action}]"
                ),
                "risk_score": risk_score,
                "agent_id":   agent_id
            }

        # Step 5 — ML security check
        ml_result = self.analyze_with_backend(
            event=f"arbiter check {agent_id} {action}",
            rpm=2.0,
            failed=0.0,
            data_mb=0.1,
            endpoints=1.0,
            login_time=1.0
        )

        if ml_result.get("status") == "anomaly":

            return {
                "decision":   "DENY",
                "reason": (
                    f"ML anomaly detected — "
                    f"{ml_result.get('risk_level')}"
                ),
                "risk_score": risk_score,
                "agent_id":   agent_id
            }

        # Step 6 — Final LLM decision
        decision = self.think(
            task=(
                f"Agent [{agent_id}] wants to [{action}]. "
                f"Risk: {risk_score:.2f}. "
                f"Permission: granted. Allow or Deny?"
            ),

            context={
                "agent_id":       agent_id,
                "action":         action,
                "risk_score":     risk_score,
                "has_permission": has_permission
            }
        )

        # Send LLM reasoning to dashboard
        self.broadcast("INFO", {
            "event":       "ARBITER_DECISION",
            "agent_id":    self.agent_id,
            "target":      agent_id,
            "action":      action,
            "risk_score":  round(risk_score, 2),
            "llm_action":  decision.get("action"),
            "llm_reason":  decision.get("reason"),
            "llm_safe":    decision.get("safe"),
            "timestamp":   time.time()
        })

        if decision.get("safe") and decision.get("action") != "BLOCKED":

            self.log_action(
                f"ALLOWED_{agent_id}_{action}",
                True
            )

            return {
                "decision":   "ALLOW",
                "reason":     decision.get(
                    "reason",
                    "All checks passed"
                ),
                "risk_score": risk_score,
                "agent_id":   agent_id
            }

        self.log_action(
            f"DENIED_{agent_id}_{action}",
            False
        )

        return {
            "decision":   "DENY",
            "reason":     decision.get(
                "reason",
                "LLM denied request"
            ),
            "risk_score": risk_score,
            "agent_id":   agent_id
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