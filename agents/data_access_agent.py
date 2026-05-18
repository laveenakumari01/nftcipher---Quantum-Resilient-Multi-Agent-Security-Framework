"""
Data-Access Agent — AUTONOMOUS VERSION
Fetches real data from backend (PostgreSQL via FastAPI)
Now this agent runs automatically in the background and in every cycle
it performs its task and sends LLM reasoning to the dashboard through SSE.
"""
import time
import random
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

        # These tables rotate during the autonomous cycle
        self._cycle_tables = ["logs", "stats", "alerts", "users"]
        self._cycle_index  = 0

    # ── AUTONOMOUS CYCLE ────────────────────────────────────
    def run_cycle(self):
        """
        The background thread calls this every 20 seconds.
        The agent fetches data automatically and updates the dashboard.
        """
        table = self._cycle_tables[self._cycle_index % len(self._cycle_tables)]
        self._cycle_index += 1

        # Take decision from the LLM
        decision = self.think(
            task=f"Autonomous cycle: Should I fetch data from table '{table}'?",
            context={"table": table, "mode": "autonomous", "cycle": self._cycle_index}
        )

        # Send LLM reasoning to the dashboard through SSE
        self.broadcast("INFO", {
            "event":       "DA_CYCLE",
            "agent_id":    self.agent_id,
            "table":       table,
            "llm_action":  decision.get("action", "unknown"),
            "llm_reason":  decision.get("reason", ""),
            "llm_safe":    decision.get("safe", True),
            "cycle":       self._cycle_index,
            "timestamp":   time.time()
        })

        if not decision.get("safe") or decision.get("action") == "BLOCKED":
            return  # The LLM blocked the request — skip this cycle

        # Fetch real data from backend
        try:
            if table == "logs":
                r = requests.get(
                    f"{BACKEND_URL}/logs",
                    headers=self._backend_headers(),
                    timeout=5
                )

            elif table == "alerts":
                r = requests.get(
                    f"{BACKEND_URL}/alerts",
                    headers=self._backend_headers(),
                    timeout=5
                )

            elif table == "users":
                r = requests.get(
                    f"{BACKEND_URL}/rbac/all-agents",
                    headers=self._backend_headers(),
                    timeout=5
                )

            else:
                r = requests.get(
                    f"{BACKEND_URL}/agent/stats",
                    headers=self._backend_headers(),
                    timeout=5
                )

            if r.status_code == 200:
                self.log_action(f"auto_fetch_{table}", True)

                # Send success event to dashboard
                self.broadcast("ALLOWED", {
                    "event":      "DA_FETCH_SUCCESS",
                    "agent_id":   self.agent_id,
                    "table":      table,
                    "source":     "REAL_DB",
                    "timestamp":  time.time()
                })

        except Exception as e:
            # Backend offline hoga toh silently skip — autonomous cycle continue karega
            self.log_action(f"auto_fetch_{table}_ERROR", False)
            self.broadcast("INFO", {
                "event":     "DA_BACKEND_OFFLINE",
                "agent_id":  self.agent_id,
                "table":     table,
                "reason":    f"Backend offline or unreachable: {str(e)[:80]}",
                "timestamp": time.time()
            })

    # ── MANUAL FETCH (Called through API) ─────────────────
    def fetch_data(self, token: str, table: str, query: str) -> dict:
        """
        Fetch real data from backend.
        Flow: Authenticate → LLM check → ML check → Real data fetch
        """

        # Step 1 — Authenticate
        # Agar frontend se short/empty token aaye toh internal token use karo
        auth_token = token if (token and len(token) > 10) else self._ensure_token()
        if not self.authenticate(auth_token):
            return {
                "status": "DENIED",
                "reason": "Authentication failed"
            }

        # Step 2 — LLM decision
        decision = self.think(
            task=f"Should I fetch data from table '{table}' for query: {query}",
            context={"table": table, "query": query}
        )

        # Send LLM reasoning to dashboard
        self.broadcast("INFO", {
            "event":       "DA_MANUAL_FETCH",
            "agent_id":    self.agent_id,
            "table":       table,
            "llm_action":  decision.get("action"),
            "llm_reason":  decision.get("reason"),
            "llm_safe":    decision.get("safe"),
            "timestamp":   time.time()
        })

        if not decision.get("safe") or decision.get("action") == "BLOCKED":
            self.log_action(f"fetch_{table}_DENIED", False)

            return {
                "status": "DENIED",
                "reason": decision.get("reason", "LLM denied request")
            }

        # Step 3 — Backend ML check
        ml_result = self.analyze_with_backend(
            event=f"fetch {table}: {query}",
            rpm=5.0,
            failed=0.0,
            data_mb=1.0,
            endpoints=1.0,
            login_time=1.0
        )

        if ml_result.get("status") == "anomaly":
            self.log_action(f"fetch_{table}_ML_BLOCKED", False)

            return {
                "status": "DENIED",
                "reason": f"ML Model blocked — {ml_result.get('risk_level', 'HIGH RISK')}"
            }

        # Step 4 — Fetch real data from backend
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
                    "status":   "SUCCESS",
                    "agent":    self.agent_id,
                    "table":    table,
                    "data":     data,
                    "ml_check": ml_result.get("risk_level", "🟢 SAFE"),
                    "source":   "REAL_DB"
                }

            else:
                return {
                    "status": "ERROR",
                    "reason": f"Backend returned {response.status_code}"
                }

        except Exception as e:
            self.log_action(f"fetch_{table}_ERROR", False)

            return {
                "status": "ERROR",
                "reason": str(e)
            }

    def get_status(self) -> dict:
        base = super().get_status()

        base["autonomous"] = self._running
        base["last_table"] = (
            self._cycle_tables[(self._cycle_index - 1) % len(self._cycle_tables)]
            if self._cycle_index > 0 else None
        )

        return base