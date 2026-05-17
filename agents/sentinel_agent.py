"""
The Sentinel - Monitoring Agent
Behavioral watchman — scans logs for threats
NEW: Background thread + Direct Adversary block via MessageBus
"""
import time
import requests
from agents.base_agent import BaseAgent
from config.settings import MOCK_MODE, BACKEND_URL
from logger import log_info, log_threat, log_blocked, log_error
from anomaly_detection.anomaly_detector import AnomalyDetector

SENTINEL_PROMPT = """You are The Sentinel — the AI monitoring agent for NftCipher.
Your job is to analyze agent behavior and detect threats.

You must flag as THREAT if you see:
- Same agent making too many requests (flooding)
- Agent trying to access unauthorized tables or services
- Unusual data export patterns (large amounts)
- Login attempts from blocked agents
- Any behavior that deviates from normal patterns

You must mark as NORMAL if:
- Request count is within limits
- Agent is accessing permitted resources
- Timing and patterns look regular"""


class SentinelAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            agent_id="AGENT-ST-01",
            role="Sentinel",
            system_prompt=SENTINEL_PROMPT
        )
        self.threat_log        = []
        self.monitored_agents  = {}
        self.anomaly_detector  = AnomalyDetector()
        # Direct reference to Adversary — Sentinel ↔ Adversary communication
        self._adversary_ref    = None

    # ── BACKGROUND LOOP — Har 15s mein automatically scan ─
    def run_cycle(self):
        """
        Background mein automatically chale.
        Har cycle mein backend logs check karo aur known agents monitor karo.
        """
        log_info("[Sentinel] Background cycle — scanning for threats...")

        # Backend se live logs fetch karo
        try:
            token    = self._ensure_token()
            response = requests.get(
                f"{BACKEND_URL}/logs",
                headers={"Authorization": f"Bearer {token}"},
                params={"limit": 20},
                timeout=5
            )
            if response.status_code == 200:
                logs = response.json()
                log_info(f"[Sentinel] Fetched {len(logs)} log entries from backend")
        except Exception as e:
            log_error(f"[Sentinel] Could not fetch backend logs: {e}")

        # Monitored agents ko check karo
        for agent_id, agent_data in list(self.monitored_agents.items()):
            req_count = agent_data.get("request_count", 0)
            if req_count > 20:
                log_threat(f"[Sentinel BG] {agent_id} has {req_count} requests — triggering auto-analysis")
                self._auto_analyze(agent_id, agent_data)

        # MessageBus broadcasts check karo
        broadcasts = self.check_inbox()
        for msg in broadcasts:
            if msg.get("msg_type") == "ALERT":
                log_threat(f"[Sentinel BG] Alert received: {msg.get('payload')}")

        log_info("[Sentinel] Background cycle complete")

    def _auto_analyze(self, agent_id: str, agent_data: dict):
        """Background mein automatically kisi agent ko analyze karo."""
        flags = []
        if agent_data.get("request_count", 0) > 20:
            flags.append("HIGH_REQUEST_COUNT")

        if flags:
            log_threat(f"[Sentinel BG] Auto-detected flags for {agent_id}: {flags}")
            # Agar Adversary hai toh direct block karo
            if agent_id == "AGENT-AD-01":
                self.block_adversary_directly(reason=f"Auto-detected: {flags}")
            else:
                # Doosre agents ke liye message bhejo
                self.send_message(agent_id, "BLOCK", {
                    "target_id": agent_id,
                    "reason":    f"Sentinel auto-block: {flags}",
                    "flags":     flags
                })

    # ── SENTINEL ↔ ADVERSARY DIRECT COMMUNICATION ─────────
    def set_adversary_ref(self, adversary_agent):
        """
        Adversary agent ka direct reference store karo.
        Ye backend startup pe set hota hai.
        Direct object access — MessageBus se bhi fast.
        """
        self._adversary_ref = adversary_agent
        log_info("[Sentinel] Adversary reference connected — direct communication ready")

    def block_adversary_directly(self, reason: str = "Threat detected by Sentinel"):
        """
        Sentinel → Adversary ko DIRECTLY block karo.
        2 tarike hain:
        1. Direct object reference (fastest)
        2. MessageBus (fallback)
        """
        log_threat(f"[Sentinel] Blocking Adversary directly | Reason: {reason}")

        # Tarika 1: Direct object reference
        if self._adversary_ref is not None:
            self._adversary_ref.receive_block_signal(reason)
            log_blocked("[Sentinel] Adversary BLOCKED via direct reference")
        else:
            # Tarika 2: MessageBus fallback
            self.send_message(
                recipient_id="AGENT-AD-01",
                msg_type="BLOCK",
                payload={
                    "target_id": "AGENT-AD-01",
                    "reason":    reason,
                    "sender":    "AGENT-ST-01"
                }
            )
            log_blocked("[Sentinel] Adversary BLOCK signal sent via MessageBus")

        # Backend ko bhi inform karo — lockdown trigger karo
        try:
            token    = self._ensure_token()
            requests.post(
                f"{BACKEND_URL}/admin/lockdown/AGENT-AD-01",
                headers={"Authorization": f"Bearer {token}"},
                timeout=5
            )
            log_info("[Sentinel] Backend lockdown triggered for Adversary")
        except Exception as e:
            log_error(f"[Sentinel] Backend lockdown failed: {e}")

        # Sab agents ko broadcast karo — Adversary block ho gaya
        self.broadcast("THREAT", {
            "event":      "ADVERSARY_BLOCKED",
            "blocked_by": "AGENT-ST-01",
            "reason":     reason,
            "timestamp":  time.time()
        })

    # ── ANALYZE BEHAVIOR (existing function — improved) ────
    def analyze_behavior(self, token: str, agent_id: str, action: str, metadata: dict) -> dict:
        """
        Analyze agent behavior — is it normal or a threat?
        Ab agar threat milta hai toh Adversary ko directly block bhi karta hai.
        """
        log_info(f"Sentinel analyzing: [{agent_id}] → [{action}]")

        # Step 1 — Validate token
        if not self.authenticate(token):
            return {
                "agent_id":    agent_id,
                "is_threat":   False,
                "threat_level":"UNKNOWN",
                "flags":       [],
                "reason":      "Sentinel authentication failed",
                "status":      "DENIED"
            }

        # Step 2 — Track agent
        if agent_id not in self.monitored_agents:
            self.monitored_agents[agent_id] = {
                "request_count": 0,
                "actions":       [],
                "first_seen":    time.time()
            }

        agent_data = self.monitored_agents[agent_id]
        agent_data["request_count"] += 1
        agent_data["actions"].append(action)

        # Step 3 — Rule-based checks
        flags = []
        if agent_data["request_count"] > 20:
            flags.append("HIGH_REQUEST_COUNT")
        if agent_data["actions"].count(action) > 5:
            flags.append("REPEATED_ACTION")
        unique_actions = len(set(agent_data["actions"]))
        if unique_actions > 8:
            flags.append("LATERAL_MOVEMENT")
        data_size = metadata.get("data_size", 0)
        if data_size > 1000:
            flags.append("LARGE_DATA_EXPORT")

        # Step 4 — ML Model
        ml_result = self.anomaly_detector.detect(
            agent_id=agent_id,
            agent_data={
                "request_count":  agent_data["request_count"],
                "failed_attempts":self.memory.failed_attempts,
                "data_size":      data_size,
                "unique_actions": unique_actions,
                "time_window":    60,
                "repeated_action":"REPEATED_ACTION" in flags,
                "unusual_hour":   False
            }
        )

        log_info(f"ML Detection: [{agent_id}] → {ml_result['attack_type']} | Risk: {ml_result['risk_score']}")

        if ml_result["is_anomaly"]:
            flags.append(f"ML_{ml_result['attack_type']}")

        # Step 5 — LLM deeper analysis
        if flags:
            decision = self.think(
                task=f"Agent [{agent_id}] has triggered flags: {flags}. ML: {ml_result['attack_type']} risk {ml_result['risk_score']}. Threat?",
                context={
                    "agent_id":       agent_id,
                    "action":         action,
                    "flags":          str(flags),
                    "ml_detection":   ml_result['attack_type'],
                    "ml_risk_score":  ml_result['risk_score'],
                    "request_count":  agent_data["request_count"],
                    "metadata":       str(metadata)
                }
            )
            is_threat = not decision.get("safe", True)
        else:
            is_threat = False

        # Step 6 — Threat level
        threat_level = "HIGH"   if is_threat and len(flags) > 2 else \
                       "MEDIUM" if is_threat else "LOW"

        result = {
            "agent_id":       agent_id,
            "action":         action,
            "is_threat":      is_threat,
            "threat_level":   threat_level,
            "flags":          flags,
            "ml_detection":   ml_result["attack_type"],
            "ml_risk_score":  ml_result["risk_score"],
            "ml_method":      ml_result["detection_method"],
            "request_count":  agent_data["request_count"],
            "timestamp":      time.time()
        }

        # Step 7 — Log + Alert via MessageBus
        if is_threat:
            self.threat_log.append(result)
            log_threat(f"[{agent_id}] Level: {threat_level} | Flags: {flags}")

            # Sab agents ko threat ka message bhejo
            self.broadcast("THREAT", {
                "event":        "THREAT_DETECTED",
                "agent_id":     agent_id,
                "threat_level": threat_level,
                "flags":        flags,
                "timestamp":    time.time()
            })

            # Agar Adversary hai aur HIGH threat hai → directly block karo
            if agent_id == "AGENT-AD-01" and threat_level in ("HIGH", "MEDIUM"):
                self.block_adversary_directly(
                    reason=f"Threat detected: {flags} | ML: {ml_result['attack_type']}"
                )
        else:
            log_info(f"[{agent_id}] Behavior NORMAL | Risk: {ml_result['risk_score']}")
            self.send_message(agent_id, "INFO", {
                "event":  "BEHAVIOR_NORMAL",
                "action": action,
                "risk":   ml_result["risk_score"]
            })

        return result

    def get_threat_report(self) -> dict:
        return {
            "total_threats":    len(self.threat_log),
            "monitored_agents": len(self.monitored_agents),
            "recent_threats":   self.threat_log[-5:],
            "threat_levels": {
                "HIGH":   len([t for t in self.threat_log if t["threat_level"] == "HIGH"]),
                "MEDIUM": len([t for t in self.threat_log if t["threat_level"] == "MEDIUM"]),
                "LOW":    len([t for t in self.threat_log if t["threat_level"] == "LOW"])
            }
        }

    def get_status(self) -> dict:
        return {
            "agent_id":           self.agent_id,
            "role":               self.role,
            "status":             "BLOCKED" if self.is_blocked else "ACTIVE",
            "failed_attempts":    self.memory.failed_attempts,
            "total_threats":      len(self.threat_log),
            "monitored_agents":   len(self.monitored_agents),
            "backend":            "connected" if self.backend_token else "disconnected",
            "bg_running":         self._running,
            "adversary_linked":   self._adversary_ref is not None,
        }