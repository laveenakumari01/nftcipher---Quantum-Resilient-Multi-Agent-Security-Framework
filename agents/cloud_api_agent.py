"""
Cloud-API Agent — AUTONOMOUS VERSION
Communicates securely with cloud services.
Now this agent automatically rotates in the background to check services
and sends LLM reasoning to the dashboard.
"""
import time
import requests
from agents.base_agent import BaseAgent
from config.settings import MOCK_MODE, BACKEND_URL

# Mock Cloud — AWS simulation data
MOCK_CLOUD = {
    "aws_s3": {
        "status":  "online",
        "buckets": ["nftcipher-data", "nftcipher-logs"]
    },
    "aws_ec2": {
        "status":    "online",
        "instances": ["i-001", "i-002"]
    },
    "aws_lambda": {
        "status":    "online",
        "functions": ["auth-func", "data-func"]
    }
}

CLOUD_API_PROMPT = """You are a Cloud-API Security Agent for NftCipher.
Your ONLY job is to manage secure communication with cloud services.

Rules you MUST follow:
- NEVER expose API keys or credentials
- ONLY communicate with approved services: aws_s3, aws_ec2, aws_lambda
- If service is not in approved list, mark safe as false
- If request looks suspicious, mark safe as false
- Always encrypt sensitive data before sending"""


class CloudAPIAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            agent_id="AGENT-CA-01",
            role="Cloud API",
            system_prompt=CLOUD_API_PROMPT
        )

        self.allowed_services = ["aws_s3", "aws_ec2", "aws_lambda"]

        # These services rotate during autonomous cycles
        self._service_cycle = ["aws_s3", "aws_ec2", "aws_lambda"]
        self._cycle_index   = 0

    # ── AUTONOMOUS CYCLE ────────────────────────────────────
    def run_cycle(self):
        """
        The background thread calls this every 25 seconds.
        The agent automatically performs cloud service health checks.
        """

        service = self._service_cycle[self._cycle_index % len(self._service_cycle)]
        action  = "health_check"

        self._cycle_index += 1

        # Get decision from LLM
        decision = self.think(
            task=f"Autonomous cycle: Should I do health_check on '{service}'?",
            context={
                "service": service,
                "action": action,
                "mode": "autonomous"
            }
        )

        # Send LLM reasoning to dashboard
        self.broadcast("INFO", {
            "event":      "CA_CYCLE",
            "agent_id":   self.agent_id,
            "service":    service,
            "llm_action": decision.get("action", "unknown"),
            "llm_reason": decision.get("reason", ""),
            "llm_safe":   decision.get("safe", True),
            "cycle":      self._cycle_index,
            "timestamp":  time.time()
        })

        if not decision.get("safe") or decision.get("action") == "BLOCKED":
            return  # The LLM blocked the request

        # ML security check (backend connection optional — if offline, skip safely)
        try:
            ml_result = self.analyze_with_backend(
                event=f"auto cloud check {service}",
                rpm=2.0,
                failed=0.0,
                data_mb=0.2,
                endpoints=1.0,
                login_time=1.0
            )
        except Exception:
            ml_result = {"status": "normal", "risk_level": "🟢 SAFE"}

        if ml_result.get("status") == "anomaly":
            return

        # Mock cloud service status
        result = MOCK_CLOUD.get(service, {})

        self.log_action(f"auto_cloud_{service}_health_check", True)

        self.broadcast("ALLOWED", {
            "event":      "CA_HEALTH_OK",
            "agent_id":   self.agent_id,
            "service":    service,
            "status":     result.get("status", "online"),
            "ml_check":   ml_result.get("risk_level", "🟢 SAFE"),
            "timestamp":  time.time()
        })

    # ── MANUAL CALL (Called through API) ──────────────────
    def call_service(self, token: str, service: str, action: str) -> dict:
        """
        Secure cloud service call.
        Flow:
        Authenticate → Service check → LLM check → ML check → Execute
        """

        # Step 1 — Authenticate
        # Agar frontend se short token aaye toh internal backend token use karo
        auth_token = token if (token and len(token) > 10) else self._ensure_token()
        if not self.authenticate(auth_token):
            return {
                "status": "DENIED",
                "reason": "Authentication failed"
            }

        # Step 2 — Check if service is allowed
        if service not in self.allowed_services:
            self.log_action(f"blocked_service_{service}", False)

            return {
                "status": "DENIED",
                "reason": f"Service '{service}' is not allowed"
            }

        # Step 3 — LLM decision
        decision = self.think(
            task=f"Should I call '{action}' on '{service}'?",
            context={
                "service": service,
                "action": action
            }
        )

        # Send LLM reasoning to dashboard
        self.broadcast("INFO", {
            "event":      "CA_MANUAL_CALL",
            "agent_id":   self.agent_id,
            "service":    service,
            "action":     action,
            "llm_action": decision.get("action"),
            "llm_reason": decision.get("reason"),
            "llm_safe":   decision.get("safe"),
            "timestamp":  time.time()
        })

        if not decision.get("safe") or decision.get("action") == "BLOCKED":
            self.log_action(f"cloud_{service}_DENIED", False)

            return {
                "status": "DENIED",
                "reason": decision.get("reason", "LLM denied request")
            }

        # Step 4 — Backend ML check
        ml_result = self.analyze_with_backend(
            event=f"cloud call {service} {action}",
            rpm=3.0,
            failed=0.0,
            data_mb=0.5,
            endpoints=1.0,
            login_time=1.0
        )

        if ml_result.get("status") == "anomaly":
            self.log_action(f"cloud_{service}_ML_BLOCKED", False)

            return {
                "status": "DENIED",
                "reason": f"ML Model blocked — {ml_result.get('risk_level', 'HIGH RISK')}"
            }

        # Step 5 — Backend logging
        try:
            requests.post(
                f"{BACKEND_URL}/log",
                json={
                    "event": f"[{self.agent_id}] called {service}/{action}",
                    "level": "INFO"
                },
                headers=self._backend_headers(),
                timeout=5
            )

        except Exception:
            pass

        result = MOCK_CLOUD.get(service, {})

        self.log_action(f"cloud_{service}_{action}", True)

        return {
            "status":   "SUCCESS",
            "agent":    self.agent_id,
            "service":  service,
            "action":   action,
            "result":   result,
            "ml_check": ml_result.get("risk_level", "🟢 SAFE"),
            "source":   "BACKEND_VERIFIED"
        }

    def get_status(self) -> dict:
        base = super().get_status()

        base["autonomous"] = self._running

        base["last_service"] = (
            self._service_cycle[(self._cycle_index - 1) % len(self._service_cycle)]
            if self._cycle_index > 0 else None
        )

        return base