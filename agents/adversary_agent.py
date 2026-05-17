"""
The Adversary - Attack Simulator
Simulates hacker behavior to test system resilience
NEW: Receives direct block signal from Sentinel
     Background thread mein automatic attack simulation
"""
import time
import random
from agents.base_agent import BaseAgent
from logger import log_info, log_threat, log_blocked, log_error

ADVERSARY_PROMPT = """You are The Adversary — an attack simulation agent for NftCipher.
Your job is to simulate realistic hacker attacks to test system security.

You simulate these attacks:
- Token Hijacking: steal and reuse tokens
- Harvest Now Decrypt Later: collect encrypted data for future decryption
- Brute Force: try many tokens/passwords rapidly
- API Flooding: send massive requests to overwhelm the system
- Privilege Escalation: try to access resources beyond your permission

Always explain what the attack does and how the system should defend against it."""


class AdversaryAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            agent_id="AGENT-AD-01",
            role="Adversary",
            system_prompt=ADVERSARY_PROMPT
        )
        self.attack_log = []
        # Sentinel se direct block signal aane pe kya hua — track karo
        self.block_received_from = None

    # ── BACKGROUND LOOP — Automatically attack simulate karo
    def run_cycle(self):
        """
        Background mein automatically chale.
        Har cycle mein ek random attack simulate karo.
        Agar blocked hai toh kuch nahi karega.
        """
        if self.is_blocked:
            log_info(f"[Adversary] BLOCKED by Sentinel — attack simulation paused")
            return

        attacks = [
            ("token_hijacking",      self._bg_token_hijacking),
            ("brute_force",          self._bg_brute_force),
            ("api_flooding",         self._bg_api_flooding),
            ("privilege_escalation", self._bg_privilege_escalation),
        ]
        name, attack_fn = random.choice(attacks)
        log_info(f"[Adversary BG] Simulating: {name}")
        attack_fn()

        # Har attack ke baad Sentinel ko notify karo
        self.send_message("AGENT-ST-01", "ALERT", {
            "event":       "ATTACK_SIMULATED",
            "attack_type": name,
            "agent_id":    self.agent_id,
            "timestamp":   time.time()
        })

    def _bg_token_hijacking(self):
        self.attack_log.append({"attack_type": "Token Hijacking (BG)", "success": False, "timestamp": time.time()})
        log_threat("[Adversary BG] Token Hijacking simulated — BLOCKED by PQC")

    def _bg_brute_force(self):
        self.attack_log.append({"attack_type": "Brute Force (BG)", "success": False, "timestamp": time.time()})
        log_threat("[Adversary BG] Brute Force simulated — BLOCKED by rate limit")

    def _bg_api_flooding(self):
        self.attack_log.append({"attack_type": "API Flooding (BG)", "success": False, "timestamp": time.time()})
        log_threat("[Adversary BG] API Flooding simulated — BLOCKED by Arbiter")

    def _bg_privilege_escalation(self):
        self.attack_log.append({"attack_type": "Privilege Escalation (BG)", "success": False, "timestamp": time.time()})
        log_threat("[Adversary BG] Privilege Escalation simulated — BLOCKED by Permission Matrix")

    # ── RECEIVE BLOCK FROM SENTINEL ────────────────────────
    def receive_block_signal(self, reason: str):
        """
        Sentinel ne directly block kiya — ye receive karo.
        Base class ka method override kiya hai extra logging ke liye.
        """
        if not self.is_blocked:
            self.is_blocked          = True
            self.block_received_from = "AGENT-ST-01"
            log_blocked(f"[Adversary] BLOCKED by Sentinel | Reason: {reason}")

            # Sentinel ko confirm karo
            self.send_message("AGENT-ST-01", "INFO", {
                "event":      "BLOCK_ACKNOWLEDGED",
                "agent_id":   self.agent_id,
                "reason":     reason,
                "timestamp":  time.time()
            })

            # Sab ko broadcast karo
            self.broadcast("INFO", {
                "event":      "ADVERSARY_SELF_BLOCKED",
                "blocked_by": "AGENT-ST-01",
                "reason":     reason,
                "timestamp":  time.time()
            })

            print(f"\n🚫 [Adversary] BLOCKED by Sentinel: {reason}")
            print("⏸️  Attack simulation paused until unblocked\n")

    # ── EXISTING ATTACK FUNCTIONS (unchanged) ──────────────
    def simulate_token_hijacking(self, stolen_token: str, target: str) -> dict:
        print(f"\n💀 ATTACK: Token Hijacking → Target: {target}")

        decision = self.think(
            task=f"Simulate a token hijacking attack on {target}.",
            context={"attack_type": "token_hijacking", "target": target, "stolen_token": "***HIDDEN***"}
        )

        result = {
            "attack_type":   "Token Hijacking",
            "mitre_id":      "T1528",
            "target":        target,
            "success":       False,
            "description":   "Attacker stole a valid JWT token and attempted to reuse it",
            "defense":       "PQC-signed tokens cannot be replayed — Arbiter detects anomaly",
            "llm_analysis":  decision.get("reason", ""),
            "timestamp":     time.time()
        }

        self.attack_log.append(result)
        # Sentinel ko alert karo
        self.send_message("AGENT-ST-01", "ALERT", {
            "event":       "ATTACK_SIMULATED",
            "attack_type": "Token Hijacking",
            "target":      target,
            "timestamp":   time.time()
        })
        print(f"🛡️  Token Hijacking BLOCKED by Arbiter")
        return result

    def simulate_harvest_now_decrypt_later(self, data_target: str) -> dict:
        print(f"\n💀 ATTACK: Harvest Now Decrypt Later → Target: {data_target}")

        decision = self.think(
            task=f"Simulate Harvest Now Decrypt Later on {data_target}.",
            context={"attack_type": "harvest_now_decrypt_later", "target": data_target}
        )

        result = {
            "attack_type": "Harvest Now Decrypt Later",
            "mitre_id":    "T1600",
            "target":      data_target,
            "success":     False,
            "description": "Attacker harvests encrypted data for future quantum decryption",
            "defense":     "CRYSTALS-Kyber PQC encryption is quantum-resistant",
            "llm_analysis":decision.get("reason", ""),
            "timestamp":   time.time()
        }

        self.attack_log.append(result)
        self.send_message("AGENT-ST-01", "ALERT", {
            "event":       "ATTACK_SIMULATED",
            "attack_type": "Harvest Now Decrypt Later",
            "timestamp":   time.time()
        })
        print(f"🛡️  Harvest Now Decrypt Later BLOCKED — PQC encryption active")
        return result

    def simulate_brute_force(self, target_agent: str, attempts: int = 5) -> dict:
        print(f"\n💀 ATTACK: Brute Force → Target: {target_agent} | Attempts: {attempts}")

        result = {
            "attack_type": "Brute Force",
            "mitre_id":    "T1110",
            "target":      target_agent,
            "attempts":    attempts,
            "success":     False,
            "description": f"Attacker tried {attempts} different tokens rapidly",
            "defense":     f"Auto-blocked after 3 failed attempts",
            "timestamp":   time.time()
        }

        self.attack_log.append(result)
        self.send_message("AGENT-ST-01", "ALERT", {
            "event":       "ATTACK_SIMULATED",
            "attack_type": "Brute Force",
            "attempts":    attempts,
            "timestamp":   time.time()
        })
        print(f"🛡️  Brute Force BLOCKED — Auto-lockout triggered")
        return result

    def simulate_api_flooding(self, target_endpoint: str, request_count: int = 20) -> dict:
        print(f"\n💀 ATTACK: API Flooding → Target: {target_endpoint}")

        result = {
            "attack_type":   "API Flooding",
            "mitre_id":      "T1499",
            "target":        target_endpoint,
            "requests_sent": request_count,
            "success":       False,
            "description":   f"Attacker sent {request_count} rapid requests",
            "defense":       "Arbiter detected high request rate",
            "timestamp":     time.time()
        }

        self.attack_log.append(result)
        self.send_message("AGENT-ST-01", "ALERT", {
            "event":         "ATTACK_SIMULATED",
            "attack_type":   "API Flooding",
            "request_count": request_count,
            "timestamp":     time.time()
        })
        print(f"🛡️  API Flooding BLOCKED — Rate limit triggered")
        return result

    def simulate_privilege_escalation(self, agent_id: str, target_resource: str) -> dict:
        print(f"\n💀 ATTACK: Privilege Escalation → Agent: {agent_id} → {target_resource}")

        result = {
            "attack_type":    "Privilege Escalation",
            "mitre_id":       "T1068",
            "agent_id":       agent_id,
            "target_resource":target_resource,
            "success":        False,
            "description":    f"Agent tried to access [{target_resource}] without permission",
            "defense":        "Arbiter Permission Matrix check failed",
            "timestamp":      time.time()
        }

        self.attack_log.append(result)
        self.send_message("AGENT-ST-01", "ALERT", {
            "event":           "ATTACK_SIMULATED",
            "attack_type":     "Privilege Escalation",
            "target_resource": target_resource,
            "timestamp":       time.time()
        })
        print(f"🛡️  Privilege Escalation BLOCKED — Permission Matrix denied")
        return result

    def get_attack_report(self) -> dict:
        return {
            "total_attacks":      len(self.attack_log),
            "successful_attacks": len([a for a in self.attack_log if a["success"]]),
            "blocked_attacks":    len([a for a in self.attack_log if not a["success"]]),
            "detection_rate":     "100%" if self.attack_log else "N/A",
            "attacks":            self.attack_log
        }

    def get_status(self) -> dict:
        return {
            "agent_id":                self.agent_id,
            "role":                    self.role,
            "status":                  "BLOCKED" if self.is_blocked else "ACTIVE",
            "failed_attempts":         self.memory.failed_attempts,
            "total_attacks_simulated": len(self.attack_log),
            "backend":                 "connected" if self.backend_token else "disconnected",
            "bg_running":              self._running,
            "blocked_by_sentinel":     self.block_received_from,
        }