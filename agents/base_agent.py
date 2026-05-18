"""
Base Agent - Foundation for all agents
Security + Memory + Guardrails + Logging + Messaging + Background Thread
Backend connected — token directly generated (no HTTP self-call)
"""
import json
import time
import threading
import requests
from openai import OpenAI
from memory.agent_memory import AgentMemory
from guardrails.security_rules import check_action_safe, sanitize_data
from config.settings import OPENROUTER_API_KEY, LLM_MODEL, BACKEND_URL, BACKEND_USER, BACKEND_PASS
from logger import log_info, log_blocked, log_allowed, log_denied, log_error
from messaging.message_bus import message_bus


class BaseAgent:
    def __init__(self, agent_id: str, role: str, system_prompt: str):
        self.agent_id      = agent_id
        self.role          = role
        self.system_prompt = system_prompt
        self.memory        = AgentMemory(agent_id)
        self.token         = None
        self.is_blocked    = False
        self.backend_token = None

        # Background thread controls
        self._bg_thread = None
        self._running   = False
        self._interval  = 15

        self.client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=OPENROUTER_API_KEY
        )

        self.backend_token = self._get_backend_token()

        # MessageBus pe register ho — apne messages sunne ke liye
        message_bus.subscribe(self.agent_id, self._on_message_received)

        log_info(f"Agent [{self.agent_id}] initialized | Role: {self.role}")

    # ── BACKGROUND THREAD ──────────────────────────────────
    def start_background(self, interval: int = None):
        """
        Background thread shuru karo.
        Agent apne aap kaam karta rahega continuously.
        interval = har kitne seconds pe (default 15).
        """
        if self._running:
            log_info(f"[{self.agent_id}] Background already running")
            return
        if interval:
            self._interval = interval
        self._running   = True
        self._bg_thread = threading.Thread(
            target=self._background_loop,
            name=f"{self.agent_id}-bg",
            daemon=True
        )
        self._bg_thread.start()
        log_info(f"[{self.agent_id}] Background thread started (interval: {self._interval}s)")

    def stop_background(self):
        """Background thread band karo."""
        self._running = False
        log_info(f"[{self.agent_id}] Background thread stopped")

    def _background_loop(self):
        """
        Ye loop background mein chalta rahta hai.
        Subclass run_cycle() override kare apna kaam likhne ke liye.
        """
        log_info(f"[{self.agent_id}] Background loop started")
        while self._running:
            try:
                if not self.is_blocked:
                    self.run_cycle()
                else:
                    log_info(f"[{self.agent_id}] BLOCKED — skipping cycle")
            except Exception as e:
                log_error(f"[{self.agent_id}] Background loop error: {e}")
            time.sleep(self._interval)
        log_info(f"[{self.agent_id}] Background loop ended")

    def run_cycle(self):
        """
        Subclass is function ko override kare.
        Base class mein kuch nahi hota.
        """
        pass

    # ── MESSAGING ──────────────────────────────────────────
    def send_message(self, recipient_id: str, msg_type: str, payload: dict):
        """
        Kisi bhi agent ko message bhejo.
        recipient_id = "ALL" → broadcast
        msg_type = "ALERT" / "BLOCK" / "INFO" / "THREAT"
        """
        return message_bus.publish(
            sender_id=self.agent_id,
            recipient_id=recipient_id,
            msg_type=msg_type,
            payload=payload
        )

    def broadcast(self, msg_type: str, payload: dict):
        """Sab agents ko ek saath message bhejo."""
        return self.send_message("ALL", msg_type, payload)

    def check_inbox(self) -> list:
        """Apni inbox check karo."""
        return message_bus.get_inbox(self.agent_id)

    def _on_message_received(self, msg):
        """
        Jab koi message aaye toh automatically call hota hai.
        Subclass override karke apna logic likh sakti hai.
        """
        log_info(f"[{self.agent_id}] Message from [{msg.sender_id}] | Type: {msg.msg_type}")

        # Agar BLOCK message aaya aur ye mera liye hai
        if msg.msg_type == "BLOCK" and msg.payload.get("target_id") == self.agent_id:
            reason = msg.payload.get("reason", "Blocked by another agent")
            self.receive_block_signal(reason)

    def receive_block_signal(self, reason: str):
        """
        Sentinel ne block kiya — ye signal receive karo.
        Direct communication: Sentinel → Adversary block.
        """
        if not self.is_blocked:
            self.is_blocked = True
            log_blocked(f"[{self.agent_id}] BLOCKED via MessageBus | Reason: {reason}")
            self.broadcast("INFO", {
                "event":    "AGENT_BLOCKED",
                "agent_id": self.agent_id,
                "reason":   reason
            })

    # ── BACKEND TOKEN ──────────────────────────────────────
    def _get_backend_token(self) -> str:
        try:
            from config.settings import BACKEND_USER, BACKEND_PASS
            import sys

            backend_mod = sys.modules.get("backend") or sys.modules.get("__main__")

            if backend_mod and hasattr(backend_mod, "authenticate_user") and hasattr(backend_mod, "create_pqc_token"):
                from datetime import timedelta
                user = backend_mod.authenticate_user(BACKEND_USER, BACKEND_PASS)
                if user:
                    token = backend_mod.create_pqc_token(
                        data={"sub": user.username, "role": user.role},
                        expires_delta=timedelta(minutes=30)
                    )
                    log_info(f"[{self.agent_id}] Token generated internally (direct)")
                    return token

            import hashlib, base64, json as _json
            from datetime import datetime, timedelta
            payload = _json.dumps({
                "sub": BACKEND_USER,
                "role": "admin",
                "exp": (datetime.utcnow() + timedelta(minutes=30)).isoformat(),
                "agent_internal": True
            })
            payload_b64 = base64.urlsafe_b64encode(payload.encode()).decode()
            ts  = str(int(time.time()))
            sig = hashlib.sha256(f"{payload}{ts}".encode()).hexdigest()
            token = f"{payload_b64}.{ts}.{sig}"
            log_info(f"[{self.agent_id}] Token generated internally (fallback)")
            return token

        except Exception as e:
            log_error(f"[{self.agent_id}] Internal token generation error: {e}")
            return f"agent-internal-{self.agent_id}-{int(time.time())}"

    def _ensure_token(self) -> str:
        if not self.backend_token:
            self.backend_token = self._get_backend_token()
        return self.backend_token

    def _backend_headers(self) -> dict:
        token = self._ensure_token()
        return {"Authorization": f"Bearer {token}"}

    # ── AUTHENTICATION ─────────────────────────────────────
    def authenticate(self, token: str) -> bool:
        if self.is_blocked:
            log_blocked(f"[{self.agent_id}] is blocked — rejecting request")
            return False

        if not token or len(token) < 10:
            self.memory.add("authenticate", "Invalid token", False)
            if self.memory.is_suspicious():
                self.is_blocked = True
                log_blocked(f"[{self.agent_id}] AUTO-BLOCKED — too many failed attempts")
                self.broadcast("ALERT", {
                    "event":    "AUTO_BLOCKED",
                    "agent_id": self.agent_id,
                    "reason":   "Too many failed authentication attempts"
                })
            return False

        self.token = token
        self.memory.add("authenticate", "Success", True)
        log_info(f"[{self.agent_id}] Authentication successful")
        return True

    # ── BACKEND ML ANALYZE ─────────────────────────────────
    def analyze_with_backend(self, event: str, rpm: float = 5.0,
                              failed: float = 0.0, data_mb: float = 1.0,
                              endpoints: float = 1.0, login_time: float = 1.0) -> dict:
        try:
            token    = self._ensure_token()
            response = requests.post(
                f"{BACKEND_URL}/analyze",
                json={
                    "event":                event,
                    "requests_per_minute":  rpm,
                    "failed_attempts":      failed,
                    "data_accessed_mb":     data_mb,
                    "unique_endpoints":     endpoints,
                    "login_time_seconds":   login_time
                },
                headers={"Authorization": f"Bearer {token}"},
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            return {"status": "normal", "risk_level": "🟢 SAFE"}
        except Exception as e:
            log_error(f"[{self.agent_id}] Backend analyze error: {e}")
            return {"status": "normal", "risk_level": "🟢 SAFE"}

    # ── LLM CALL ───────────────────────────────────────────
    def _call_llm(self, prompt: str) -> str:
        import re

        models_to_try = [
            LLM_MODEL,                                      # openrouter/free (primary)
            "meta-llama/llama-3.3-70b-instruct:free",       # Meta — most stable free model
            "openai/gpt-oss-20b:free",                      # OpenAI — lightweight
            "openai/gpt-oss-120b:free",                     # OpenAI — powerful
            "nvidia/nemotron-3-nano-30b-a3b:free",          # NVIDIA — tools support
            "google/gemma-4-31b-it:free",                   # Google — vision + tools
        ]
        seen = set()
        models_to_try = [m for m in models_to_try if not (m in seen or seen.add(m))]

        for model in models_to_try:
            try:
                log_info(f"[{self.agent_id}] Calling LLM: {model}")
                response = self.client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.1
                )
                if not response.choices or not response.choices[0].message.content:
                    log_error(f"[{self.agent_id}] LLM {model} empty response — trying next")
                    continue
                return response.choices[0].message.content.strip()

            except Exception as e:
                error_msg = str(e)
                if "429" in error_msg or "rate" in error_msg.lower():
                    wait = 5
                    try:
                        match = re.search(r"retry_after_seconds.*?(\d+)", error_msg)
                        if match:
                            wait = min(int(match.group(1)), 15)
                    except Exception:
                        pass
                    log_error(f"[{self.agent_id}] Rate limited — waiting {wait}s")
                    time.sleep(wait)
                    try:
                        response = self.client.chat.completions.create(
                            model=model,
                            messages=[{"role": "user", "content": prompt}],
                            temperature=0.1
                        )
                        if response.choices and response.choices[0].message.content:
                            return response.choices[0].message.content.strip()
                    except Exception as retry_error:
                        log_error(f"[{self.agent_id}] Retry failed: {retry_error}")
                elif "404" in error_msg or "No endpoints" in error_msg:
                    log_error(f"[{self.agent_id}] {model} not available — trying next")
                    continue
                else:
                    log_error(f"[{self.agent_id}] LLM error: {error_msg}")

        log_error(f"[{self.agent_id}] All LLM models failed — using safe default")
        return None

    # ── THINK ──────────────────────────────────────────────
    def think(self, task: str, context: dict) -> dict:
        safe_context   = sanitize_data(context)
        memory_context = self.memory.get_context()

        prompt = f"""{self.system_prompt}

TASK: {task}
CONTEXT: {safe_context}
PAST ACTIONS:
{memory_context}

Reply with JSON only — no extra text:
{{"action": "what to do", "reason": "why", "safe": true or false}}"""

        try:
            content = self._call_llm(prompt)

            if content is None:
                task_lower      = task.lower()
                unsafe_keywords = ["delete", "drop", "truncate", "modify", "update",
                                   "insert", "hack", "bypass", "exploit"]
                is_unsafe = any(kw in task_lower for kw in unsafe_keywords)
                if is_unsafe:
                    return {"action": "BLOCKED", "reason": "Unsafe keywords (LLM fallback)", "safe": False}
                return {"action": "fetch_data", "reason": "LLM unavailable — safe default", "safe": True}

            content = content.replace("```json", "").replace("```", "").strip()

            if "{" in content:
                start   = content.index("{")
                end     = content.rindex("}") + 1
                content = content[start:end]

            if not content.startswith("{"):
                return {"action": "fetch_data", "reason": "Invalid LLM response", "safe": True}

            parsed = json.loads(content)

            if not check_action_safe(parsed.get("action", "")):
                log_blocked(f"[{self.agent_id}] Guardrail blocked: {parsed.get('action')}")
                return {"action": "BLOCKED", "reason": "Security guardrail triggered", "safe": False}

            return parsed

        except json.JSONDecodeError as e:
            log_error(f"[{self.agent_id}] JSON parse error: {e}")
            return {"action": "fetch_data", "reason": "JSON parse error", "safe": True}
        except Exception as e:
            log_error(f"[{self.agent_id}] Unexpected error: {e}")
            return {"action": "ERROR", "reason": str(e), "safe": False}

    # ── LOGGING + STATUS ───────────────────────────────────
    def log_action(self, action: str, success: bool):
        self.memory.add(action, "logged", success)
        if success:
            log_allowed(f"[{self.agent_id}] {action}")
        else:
            log_denied(f"[{self.agent_id}] {action}")

    def get_status(self) -> dict:
        return {
            "agent_id":        self.agent_id,
            "role":            self.role,
            "status":          "BLOCKED" if self.is_blocked else "ACTIVE",
            "failed_attempts": self.memory.failed_attempts,
            "backend":         "connected" if self.backend_token else "disconnected",
            "bg_running":      self._running,
        }