"""
The Arbiter - Decision Agent
Central brain of NftCipher
Real permissions from backend PostgreSQL
"""
import time
import requests
from agents.base_agent import BaseAgent
from config.settings import MOCK_MODE, BACKEND_URL

# Mock fallback — backend down 
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

    def calculate_risk_score(self, agent_id: str, action: str) -> float:
        """calculate risk score."""
        risk = 0.0

        if agent_id in self.blocked_agents:
            return 1.0

        current_time = time.time()
        if agent_id in self.request_times:
            time_diff = current_time - self.request_times[agent_id]
            count     = self.request_counts.get(agent_id, 0)
            if time_diff < 60 and count > 10:
                risk += 0.5

        suspicious_keywords = ["delete", "drop", "hack", "bypass", "admin", "root"]
        for keyword in suspicious_keywords:
            if keyword in action.lower():
                risk += 0.4

        self.request_counts[agent_id] = self.request_counts.get(agent_id, 0) + 1
        self.request_times[agent_id]  = current_time

        return min(risk, 1.0)

    def check_permission(self, agent_id: str, action: str) -> bool:
        """
        get real permission from backend
        Fallback: mock permissions if backend is down
        """
        try:
            # real permission from backend
            response = requests.get(
                f"{BACKEND_URL}/rbac/my-permissions",
                headers=self._backend_headers(),
                timeout=5
            )
            if response.status_code == 200:
                permissions = response.json().get("permissions", [])
                # admin:all ho to sab allow
                if "admin:all" in permissions:
                    return True
                for perm in permissions:
                    if perm.split(":")[0] in action.lower():
                        return True
                # Agent specific mock check
                agent_perms = MOCK_PERMISSIONS.get(agent_id, [])
                for perm in agent_perms:
                    if perm in action.lower():
                        return True
                return False
        except Exception:
            pass

        # Fallback — mock permissions
        permissions = MOCK_PERMISSIONS.get(agent_id, [])
        for perm in permissions:
            if perm in action.lower():
                return True
        return False

    def arbitrate(self, token: str, agent_id: str, action: str) -> dict:
        """
        Main function — ALLOW or DENY.
        Flow: Token → Risk Score → Permission → ML → LLM → Decision
        """
        print(f"\n⚖️  Arbiter evaluating: [{agent_id}] → [{action}]")

        # Step 1 — Token validate
        if not self.authenticate(token):
            return {
                "decision":   "DENY",
                "reason":     "Invalid or expired token",
                "risk_score": 1.0,
                "agent_id":   agent_id
            }

        # Step 2 — Risk score
        risk_score = self.calculate_risk_score(agent_id, action)
        print(f"📊 Risk Score: {risk_score:.2f}")

        # Step 3 — High risk → deny
        if risk_score >= RISK_HIGH:
            self.blocked_agents.append(agent_id)
            # lockdown in backend
            try:
                requests.post(
                    f"{BACKEND_URL}/admin/lockdown/{agent_id}",
                    headers=self._backend_headers(),
                    timeout=5
                )
            except Exception:
                pass
            self.log_action(f"BLOCKED_{agent_id}", False)
            return {
                "decision":   "DENY",
                "reason":     f"Risk score too high: {risk_score:.2f} — Auto-lockdown triggered",
                "risk_score": risk_score,
                "agent_id":   agent_id
            }

        # Step 4 — Permission check (real backend)
        has_permission = self.check_permission(agent_id, action)
        if not has_permission:
            self.log_action(f"NO_PERMISSION_{agent_id}", False)
            return {
                "decision":   "DENY",
                "reason":     f"Agent [{agent_id}] has no permission for [{action}]",
                "risk_score": risk_score,
                "agent_id":   agent_id
            }

        # Step 5 — Backend ML check
        ml_result = self.analyze_with_backend(
            event=f"arbiter check {agent_id} {action}",
            rpm=2.0, failed=0.0, data_mb=0.1,
            endpoints=1.0, login_time=1.0
        )
        if ml_result.get("status") == "anomaly":
            return {
                "decision":   "DENY",
                "reason":     f"ML anomaly detected — {ml_result.get('risk_level')}",
                "risk_score": risk_score,
                "agent_id":   agent_id
            }

        # Step 6 — LLM final decision
        decision = self.think(
            task=(
                f"Agent [{agent_id}] wants to [{action}]. "
                f"Risk: {risk_score:.2f}. Permission: granted. Allow or Deny?"
            ),
            context={
                "agent_id":       agent_id,
                "action":         action,
                "risk_score":     risk_score,
                "has_permission": has_permission
            }
        )

        if decision.get("safe") and decision.get("action") != "BLOCKED":
            self.log_action(f"ALLOWED_{agent_id}_{action}", True)
            return {
                "decision":   "ALLOW",
                "reason":     decision.get("reason", "All checks passed"),
                "risk_score": risk_score,
                "agent_id":   agent_id
            }

        self.log_action(f"DENIED_{agent_id}_{action}", False)
        return {
            "decision":   "DENY",
            "reason":     decision.get("reason", "LLM denied request"),
            "risk_score": risk_score,
            "agent_id":   agent_id
        }

    def block_agent(self, agent_id: str, reason: str):
        """Force block — Sentinel se call hota hai."""
        if agent_id not in self.blocked_agents:
            self.blocked_agents.append(agent_id)
            # lockdown in Backend 
            try:
                requests.post(
                    f"{BACKEND_URL}/admin/lockdown/{agent_id}",
                    headers=self._backend_headers(),
                    timeout=5
                )
            except Exception:
                pass
            print(f"🚫 Arbiter FORCE BLOCKED: {agent_id} | Reason: {reason}")

    def get_status(self) -> dict:
        return {
            "agent_id":        self.agent_id,
            "role":            self.role,
            "status":          "BLOCKED" if self.is_blocked else "ACTIVE",
            "failed_attempts": self.memory.failed_attempts,
            "blocked_agents":  self.blocked_agents,
            "total_requests":  sum(self.request_counts.values()),
            "backend":         "connected" if self.backend_token else "disconnected",
        }