"""
Data-Access Agent
Fetches real data from backend (PostgreSQL via FastAPI)
"""
import requests
from agents.base_agent import BaseAgent
from config.settings import MOCK_MODE, BACKEND_URL

DATA_ACCESS_PROMPT = """You are a Data-Access Security Agent for NftCipher.
Your ONLY job is to fetch data from the database safely.

Rules you MUST follow:
- NEVER delete or modify any data
- NEVER share password or secret fields
- Mark safe as FALSE only if the query contains: delete, drop, truncate, modify, update, insert
- Normal read operations like fetch, get, list, select are ALWAYS safe — mark safe as TRUE
- Always respond with valid JSON only"""


class DataAccessAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            agent_id="AGENT-DA-01",
            role="Data Access",
            system_prompt=DATA_ACCESS_PROMPT
        )

    def fetch_data(self, token: str, table: str, query: str) -> dict:
        """
        Fetch real data from backend.
        Flow: Authenticate → LLM check → ML check → real data fetch
        """
        # Step 1 — Authenticate
        if not self.authenticate(token):
            return {"status": "DENIED", "reason": "Authentication failed"}

        # Step 2 — LLM decision
        decision = self.think(
            task=f"Should I fetch data from table '{table}' for query: {query}",
            context={"table": table, "query": query}
        )

        if not decision.get("safe") or decision.get("action") == "BLOCKED":
            self.log_action(f"fetch_{table}_DENIED", False)
            return {
                "status": "DENIED",
                "reason": decision.get("reason", "LLM denied request")
            }

        # Step 3 — Backend ML check
        ml_result = self.analyze_with_backend(
            event=f"fetch {table}: {query}",
            rpm=5.0, failed=0.0, data_mb=1.0,
            endpoints=1.0, login_time=1.0
        )

        if ml_result.get("status") == "anomaly":
            self.log_action(f"fetch_{table}_ML_BLOCKED", False)
            return {
                "status": "DENIED",
                "reason": f"ML Model blocked — {ml_result.get('risk_level', 'HIGH RISK')}"
            }

        # Step 4 — Real data from backend
        try:
            
            if table == "logs":
                response = requests.get(
                    f"{BACKEND_URL}/logs",
                    headers=self._backend_headers(),
                    timeout=5
                )
            elif table == "alerts":
                response = requests.get(
                    f"{BACKEND_URL}/alerts",
                    headers=self._backend_headers(),
                    timeout=5
                )
            elif table == "users":
                response = requests.get(
                    f"{BACKEND_URL}/rbac/all-agents",
                    headers=self._backend_headers(),
                    timeout=5
                )
            elif table == "stats":
                response = requests.get(
                    f"{BACKEND_URL}/agent/stats",
                    headers=self._backend_headers(),
                    timeout=5
                )
            else:
                response = requests.get(
                    f"{BACKEND_URL}/logs",
                    headers=self._backend_headers(),
                    timeout=5
                )

            if response.status_code == 200:
                data = response.json()
                self.log_action(f"fetch_{table}", True)
                return {
                    "status":     "SUCCESS",
                    "agent":      self.agent_id,
                    "table":      table,
                    "data":       data,
                    "ml_check":   ml_result.get("risk_level", "🟢 SAFE"),
                    "source":     "REAL_DB"
                }
            else:
                return {
                    "status": "ERROR",
                    "reason": f"Backend returned {response.status_code}"
                }

        except Exception as e:
            log_error = f"Backend fetch error: {e}"
            self.log_action(f"fetch_{table}_ERROR", False)
            return {"status": "ERROR", "reason": str(e)}