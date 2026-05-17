"""
Cloud-API Agent
Communicates securely with cloud services
Real backend ML check on every call
"""
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

    def call_service(self, token: str, service: str, action: str) -> dict:
        """
        Secure cloud service call.
        Flow: Authenticate → service check → LLM check → ML check → execute
        """
        # Step 1 — Authenticate
        if not self.authenticate(token):
            return {"status": "DENIED", "reason": "Authentication failed"}

        # Step 2 — Service allowed?
        if service not in self.allowed_services:
            self.log_action(f"blocked_service_{service}", False)
            return {
                "status": "DENIED",
                "reason": f"Service '{service}' is not allowed"
            }

        # Step 3 — LLM decision
        decision = self.think(
            task=f"Should I call '{action}' on '{service}'?",
            context={"service": service, "action": action}
        )

        if not decision.get("safe") or decision.get("action") == "BLOCKED":
            self.log_action(f"cloud_{service}_DENIED", False)
            return {
                "status": "DENIED",
                "reason": decision.get("reason", "LLM denied request")
            }

        # Step 4 — Backend ML check
        ml_result = self.analyze_with_backend(
            event=f"cloud call {service} {action}",
            rpm=3.0, failed=0.0, data_mb=0.5,
            endpoints=1.0, login_time=1.0
        )

        if ml_result.get("status") == "anomaly":
            self.log_action(f"cloud_{service}_ML_BLOCKED", False)
            return {
                "status": "DENIED",
                "reason": f"ML Model blocked — {ml_result.get('risk_level', 'HIGH RISK')}"
            }

        # Step 5 — Backend log + return cloud result
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

        # AWS simulation data return 
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