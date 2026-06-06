"""
agents/base_agent.py

Base Agent — Foundation for ALL 10 agents.


Now:
  - OpenRouter via direct requests (free, no SDK needed)
  - Long-term SQLite memory (persists across restarts)
  - Messages signed via Cryptographer Agent
  - Enhanced 3-tier guardrails
  - LangGraph state compatible
  - Autonomous background cycle with self-healing

Security focus:
  - Every LLM output validated before acting
  - Guardrail rate limiting — 5 blocked actions = auto escalate
  - Memory tracks false positives — same thing not flagged twice
  - Token management via Cryptographer Agent
"""

import json
import time
import threading
import requests

from memory.agent_memory import AgentMemory
from guardrails.security_rules import (
    check_action_safe,
    sanitize_data,
    validate_llm_output,
    check_rate_limit,
)
from config.settings import (
    OPENROUTER_API_KEY,
    LLM_MODEL,
    BACKEND_URL,
    BACKEND_USER,
    BACKEND_PASS,
)
from logger import log_info, log_blocked, log_allowed, log_denied, log_error
from messaging.message_bus import message_bus


# OpenRouter API endpoint — no SDK needed
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

# Free models to try in order — fallback chain
LLM_MODELS = [
    LLM_MODEL,
    "meta-llama/llama-3.3-70b-instruct:free",
    "openai/gpt-oss-20b:free",
    "openai/gpt-oss-120b:free",
    "nvidia/nemotron-3-nano-30b-a3b:free",
    "google/gemma-4-31b-it:free",
]


class BaseAgent:
    """
    Base class for all 10 NFTCipher agents.

    Every agent gets:
      - Long-term persistent memory (SQLite)
      - Autonomous background thread
      - MessageBus subscription (signed messages)
      - OpenRouter LLM access (free, no SDK)
      - 3-tier security guardrails
      - LangGraph state compatibility
    """

    def __init__(self, agent_id: str, role: str, system_prompt: str):
        self.agent_id      = agent_id
        self.role          = role
        self.system_prompt = system_prompt
        self.is_blocked    = False
        self.backend_token = None

        # Long-term persistent memory
        self.memory = AgentMemory(agent_id)

        # Background thread controls
        self._bg_thread = None
        self._running   = False
        self._interval  = 15

        # OpenRouter HTTP session — reused across calls
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization":  f"Bearer {OPENROUTER_API_KEY}",
            "Content-Type":   "application/json",
            "HTTP-Referer":   "https://nftcipher.security",
            "X-Title":        "NFTCipher Security System",
        })

        # Get backend token at startup
        self.backend_token = self._get_backend_token()

        # Register on MessageBus to receive messages
        message_bus.subscribe(self.agent_id, self._on_message_received)

        log_info(f"[{self.agent_id}] Initialized | role={self.role} | memory=persistent")

    # ── BACKGROUND THREAD ─────────────────────────────────

    def start_background(self, interval: int = None):
        """
        Start the autonomous background loop.
        Agent runs run_cycle() every interval seconds without any external trigger.
        This is what makes each agent truly autonomous.
        """
        if self._running:
            log_info(f"[{self.agent_id}] Background already running")
            return
        if interval:
            self._interval = interval

        self._running   = True
        self._bg_thread = threading.Thread(
            target = self._background_loop,
            name   = f"{self.agent_id}-bg",
            daemon = True,
        )
        self._bg_thread.start()
        log_info(f"[{self.agent_id}] Background started | interval={self._interval}s")

    def stop_background(self):
        """Stop the background loop gracefully."""
        self._running = False
        log_info(f"[{self.agent_id}] Background stopped")

    def _background_loop(self):
        """
        Main autonomous loop.
        Runs run_cycle() on schedule.
        Self-healing: catches all exceptions so loop never dies.
        Skips cycle if agent is blocked.
        """
        log_info(f"[{self.agent_id}] Autonomous loop started | interval={self._interval}s")

        while self._running:
            try:
                if not self.is_blocked:
                    self.run_cycle()
                    # Save cycle summary to long-term memory
                    self.memory.save_session_summary(
                        cycle_id = f"{self.agent_id}-{int(time.time())}",
                        summary  = f"Cycle completed at {time.strftime('%H:%M:%S')}",
                        verdict  = "NORMAL",
                    )
                else:
                    log_info(f"[{self.agent_id}] BLOCKED — skipping cycle")
            except Exception as e:
                log_error(f"[{self.agent_id}] Background loop error: {e}")
                # Self-healing: log error and continue — never crash the loop
                self.memory.add("background_cycle", f"error: {e}", False)

            time.sleep(self._interval)

        log_info(f"[{self.agent_id}] Autonomous loop ended")

    def run_cycle(self):
        """
        Override this in each subclass.
        Called automatically every interval seconds.
        """
        pass

    # ── MESSAGING ─────────────────────────────────────────

    def send_message(self, recipient_id: str, msg_type: str, payload: dict):
        """Send a signed message to another agent via MessageBus."""
        return message_bus.publish(
            sender_id    = self.agent_id,
            recipient_id = recipient_id,
            msg_type     = msg_type,
            payload      = payload,
        )

    def broadcast(self, msg_type: str, payload: dict):
        """Broadcast a signed message to all agents."""
        return self.send_message("ALL", msg_type, payload)

    def ask_agent(self, target_agent, question: str, context: dict = None) -> dict:
        """
        Ask another agent a specific question and wait for its structured answer.

        This is different from send_message() which is fire-and-forget, and
        broadcast() which sends to everyone blindly. ask_agent() is a targeted,
        synchronous question-answer conversation between two specific agents.

        How it works:
          1. Logs the question on MessageBus for audit trail
          2. Calls target_agent.handle_query() directly and waits for the answer
          3. Returns the answer dict — caller gets real data, not just an ACK

        Used by Suggestion Engine to chain: Sentinel → Research → Coding

        Args:
            target_agent : the agent object to ask (ResearchAgent or CodingAgent)
            question     : natural language question string
            context      : optional dict with extra data (thread_id, flags, etc.)

        Returns:
            dict — the agent's answer, or {} if agent cannot respond
        """
        if target_agent is None:
            log_error(f"[{self.agent_id}] ask_agent() called with None target")
            return {}

        context   = context or {}
        target_id = getattr(target_agent, "agent_id", "UNKNOWN")

        log_info(
            f"[{self.agent_id}] ask_agent() → [{target_id}] | "
            f"q={question[:60]}..."
        )

        # Log the question on MessageBus so conversation history is auditable
        self.send_message(target_id, "QUERY", {
            "question"  : question,
            "context"   : context,
            "asked_by"  : self.agent_id,
            "timestamp" : time.time(),
        })

        # Call target agent's handle_query() directly — synchronous, returns real answer
        if hasattr(target_agent, "handle_query"):
            try:
                answer = target_agent.handle_query(question, context)
                log_info(f"[{self.agent_id}] ask_agent() got answer from [{target_id}]")
                return answer or {}
            except Exception as e:
                log_error(
                    f"[{self.agent_id}] ask_agent() error from [{target_id}]: {e}"
                )
                return {}

        # Target agent does not have handle_query — cannot answer
        log_info(f"[{self.agent_id}] [{target_id}] has no handle_query — skipping")
        return {}

    def check_inbox(self) -> list:
        """
        Check inbox — returns messages sorted by priority.
        THREAT and BLOCK messages come first.
        Tampered messages are automatically filtered.
        """
        return message_bus.get_inbox(self.agent_id)

    def _on_message_received(self, msg):
        """
        Called automatically when a message arrives.
        Handles BLOCK signals — subclasses can override for custom handling.
        """
        log_info(f"[{self.agent_id}] Message from [{msg.sender_id}] | type={msg.msg_type}")

        if msg.msg_type == "BLOCK" and msg.payload.get("target_id") == self.agent_id:
            self.receive_block_signal(msg.payload.get("reason", "Blocked by agent"))

    def receive_block_signal(self, reason: str):
        """
        Receive a block signal from Sentinel or Arbiter.
        Saves block event to long-term memory.
        """
        if not self.is_blocked:
            self.is_blocked = True
            log_blocked(f"[{self.agent_id}] BLOCKED | reason={reason}")
            self.memory.add("blocked", reason, False)
            self.broadcast("INFO", {
                "event":    "AGENT_BLOCKED",
                "agent_id": self.agent_id,
                "reason":   reason,
                "timestamp": time.time(),
            })

    # ── TOKEN MANAGEMENT ──────────────────────────────────

    def _get_backend_token(self) -> str:
        """
        Get authentication token for backend API calls.
        Tries direct internal generation first, falls back to signed hash.
        """
        try:
            import sys
            backend_mod = sys.modules.get("backend") or sys.modules.get("__main__")

            if backend_mod and hasattr(backend_mod, "authenticate_user") and \
               hasattr(backend_mod, "create_pqc_token"):
                from datetime import timedelta
                user = backend_mod.authenticate_user(BACKEND_USER, BACKEND_PASS)
                if user:
                    token = backend_mod.create_pqc_token(
                        data          = {"sub": user.username, "role": user.role},
                        expires_delta = timedelta(minutes=30),
                    )
                    log_info(f"[{self.agent_id}] Token generated internally")
                    return token

            # Fallback signed token
            import hashlib, base64, json as _json
            from datetime import datetime, timedelta
            payload = _json.dumps({
                "sub":            BACKEND_USER,
                "role":           "admin",
                "exp":            (datetime.utcnow() + timedelta(minutes=30)).isoformat(),
                "agent_internal": True,
            })
            payload_b64 = base64.urlsafe_b64encode(payload.encode()).decode()
            ts          = str(int(time.time()))
            sig         = hashlib.sha256(f"{payload}{ts}".encode()).hexdigest()
            return f"{payload_b64}.{ts}.{sig}"

        except Exception as e:
            log_error(f"[{self.agent_id}] Token generation error: {e}")
            return f"agent-internal-{self.agent_id}-{int(time.time())}"

    def _ensure_token(self) -> str:
        """Return existing token or generate a new one."""
        if not self.backend_token:
            self.backend_token = self._get_backend_token()
        return self.backend_token

    def _backend_headers(self) -> dict:
        return {"Authorization": f"Bearer {self._ensure_token()}"}

    # ── AUTHENTICATION ────────────────────────────────────

    def authenticate(self, token: str) -> bool:
        """
        Validate an incoming token.
        Records result in long-term memory.
        Auto-blocks on 3+ failures.
        """
        if self.is_blocked:
            log_blocked(f"[{self.agent_id}] Blocked — rejecting auth")
            return False

        if not token or len(token) < 10:
            self.memory.add("authenticate", "Invalid token", False)
            if self.memory.is_suspicious():
                self.is_blocked = True
                log_blocked(f"[{self.agent_id}] AUTO-BLOCKED — too many auth failures")
                self.broadcast("ALERT", {
                    "event":    "AUTO_BLOCKED",
                    "agent_id": self.agent_id,
                    "reason":   "Too many failed authentication attempts",
                })
            return False

        self.memory.add("authenticate", "success", True)
        log_info(f"[{self.agent_id}] Authentication successful")
        return True

    # ── BACKEND ML ANALYZE ────────────────────────────────

    def analyze_with_backend(self, event: str, rpm: float = 5.0,
                              failed: float = 0.0, data_mb: float = 1.0,
                              endpoints: float = 1.0, login_time: float = 1.0) -> dict:
        """Call backend /analyze endpoint for ML analysis."""
        try:
            response = requests.post(
                f"{BACKEND_URL}/analyze",
                json = {
                    "event":               event,
                    "requests_per_minute": rpm,
                    "failed_attempts":     failed,
                    "data_accessed_mb":    data_mb,
                    "unique_endpoints":    endpoints,
                    "login_time_seconds":  login_time,
                },
                headers = self._backend_headers(),
                timeout = 10,
            )
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            log_error(f"[{self.agent_id}] Backend analyze error: {e}")

        return {"status": "normal", "risk_level": "SAFE"}

    # ── LLM CALL — OpenRouter direct (no SDK) ─────────────

    def _call_llm(self, prompt: str) -> str:
        """
        Call OpenRouter LLM using direct HTTP requests.
        Tries multiple free models with automatic fallback.
        Rate limit handling with exponential backoff.
        """
        # Deduplicate model list
        seen   = set()
        models = [m for m in LLM_MODELS if not (m in seen or seen.add(m))]

        for model in models:
            try:
                log_info(f"[{self.agent_id}] Calling LLM via OpenRouter | model={model}")

                response = self._session.post(
                    OPENROUTER_URL,
                    json = {
                        "model":       model,
                        "messages":    [{"role": "user", "content": prompt}],
                        "temperature": 0.1,
                        "max_tokens":  800,
                    },
                    timeout = 30,
                )

                if response.status_code == 429:
                    # Rate limited — wait and retry once
                    wait = 5
                    try:
                        retry_after = response.json().get("error", {}).get("metadata", {}).get("retry_after", 5)
                        wait = min(int(retry_after), 15)
                    except Exception:
                        pass
                    log_error(f"[{self.agent_id}] Rate limited — waiting {wait}s")
                    time.sleep(wait)
                    # Retry once
                    response = self._session.post(
                        OPENROUTER_URL,
                        json    = {"model": model, "messages": [{"role": "user", "content": prompt}], "temperature": 0.1},
                        timeout = 30,
                    )

                if response.status_code == 200:
                    data    = response.json()
                    choices = data.get("choices", [])
                    if choices and choices[0].get("message", {}).get("content"):
                        content = choices[0]["message"]["content"].strip()
                        if content:
                            return content

                elif response.status_code in (404, 503):
                    log_error(f"[{self.agent_id}] Model {model} unavailable — trying next")
                    continue

                else:
                    log_error(f"[{self.agent_id}] LLM HTTP {response.status_code} | model={model}")

            except requests.exceptions.Timeout:
                log_error(f"[{self.agent_id}] LLM timeout | model={model} — trying next")
                continue
            except Exception as e:
                log_error(f"[{self.agent_id}] LLM error: {e} | model={model}")

        log_error(f"[{self.agent_id}] All LLM models failed — using safe default")
        return None

    # ── THINK — Secure LLM Reasoning ──────────────────────

    def think(self, task: str, context: dict) -> dict:
        """
        Secure LLM reasoning with full guardrail pipeline:
          1. Sanitize context — remove sensitive fields
          2. Add long-term memory context — grounded reasoning
          3. Call LLM
          4. Validate output — check for injection, blocked actions
          5. Record in memory
        """
        # Step 1 — Sanitize
        safe_context = sanitize_data(context)

        # Step 2 — Rich memory context (includes threat patterns + FP history)
        memory_context = self.memory.get_rich_context()

        prompt = f"""{self.system_prompt}

TASK: {task}
CONTEXT: {safe_context}
AGENT HISTORY:
{memory_context}

Reply with JSON only — no extra text:
{{"action": "what to do", "reason": "why (cite specific numbers)", "safe": true or false}}"""

        try:
            content = self._call_llm(prompt)

            # LLM unavailable — safe keyword-based fallback
            if content is None:
                unsafe_kw = ["delete", "drop", "truncate", "modify", "hack",
                             "bypass", "exploit", "inject", "override"]
                if any(kw in task.lower() for kw in unsafe_kw):
                    return {"action": "BLOCKED", "reason": "Unsafe task (LLM fallback)", "safe": False}
                return {"action": "fetch_data", "reason": "LLM unavailable — safe default", "safe": True}

            # Clean response
            content = content.replace("```json", "").replace("```", "").strip()
            if "{" in content:
                content = content[content.index("{") : content.rindex("}") + 1]

            if not content.startswith("{"):
                return {"action": "fetch_data", "reason": "Invalid LLM response format", "safe": True}

            parsed = json.loads(content)

            # Step 4 — Validate output (injection check + action check)
            validated = validate_llm_output(parsed, self.agent_id)
            if validated.get("action") == "BLOCKED":
                log_blocked(f"[{self.agent_id}] Guardrail blocked LLM output: {parsed.get('action')}")
                self.memory.add(task, "blocked_by_guardrail", False)
                # Check rate limit
                if not check_rate_limit(self.agent_id):
                    self.send_message("AGENT-ST-01", "THREAT", {
                        "event":    "GUARDRAIL_RATE_EXCEEDED",
                        "agent_id": self.agent_id,
                        "task":     task[:100],
                        "timestamp": time.time(),
                    })
                return validated

            # Step 5 — Record in memory
            self.memory.add(task, validated.get("action", "unknown"), validated.get("safe", True))
            return validated

        except json.JSONDecodeError as e:
            log_error(f"[{self.agent_id}] JSON parse error: {e}")
            return {"action": "fetch_data", "reason": "JSON parse error", "safe": True}
        except Exception as e:
            log_error(f"[{self.agent_id}] think() error: {e}")
            return {"action": "ERROR", "reason": str(e), "safe": False}

    # ── LOGGING + STATUS ──────────────────────────────────

    def log_action(self, action: str, success: bool):
        """Log an action to memory and logger."""
        self.memory.add(action, "logged", success)
        if success:
            log_allowed(f"[{self.agent_id}] {action}")
        else:
            log_denied(f"[{self.agent_id}] {action}")

    def get_status(self) -> dict:
        """Base status — all agents extend this."""
        return {
            "agent_id":        self.agent_id,
            "role":            self.role,
            "status":          "BLOCKED" if self.is_blocked else "ACTIVE",
            "failed_attempts": self.memory.failed_attempts,
            "backend":         "connected" if self.backend_token else "disconnected",
            "bg_running":      self._running,
            "memory":          self.memory.get_stats(),
            "llm_provider":    "OpenRouter (free)",
        }