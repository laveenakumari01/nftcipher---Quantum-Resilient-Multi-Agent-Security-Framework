"""
agents/cryptographer_agent.py

Cryptographer Agent — AGENT-CR-01
Was defined in Phase 2 document but missing from the project.

Responsibilities:
  1. Generate Kyber-768 keypairs for every agent
  2. Sign all inter-agent messages with Dilithium3
  3. Verify signatures — catch tampered messages
  4. Issue and revoke PQC tokens
  5. Rotate keys every 30 minutes automatically

Security position in architecture:
  Any Agent
      ↓
  [Cryptographer] — signs + encrypts every message
      ↓
  Arbiter — validates token
      ↓
  Sentinel — monitors
"""

import time
import json
import hashlib
from agents.base_agent import BaseAgent
from quantum_simulation.pqc_simulation import (
    CrystalsKyber,
    CrystalsDilithium,
    QuantumTokenGenerator,
    _OQS_AVAILABLE,
)
from logger import log_info, log_threat, log_blocked, log_error, log_allowed


CRYPTOGRAPHER_PROMPT = """You are The Cryptographer — the encryption enforcement agent for NFTCipher.

Your ONLY job is to protect all inter-agent communications with post-quantum cryptography.

Rules you MUST follow:
- EVERY agent message must be signed with Dilithium3
- NEVER issue a token without verifying the agent identity
- If signature verification fails, report THREAT immediately
- Key rotation happens every 30 minutes — old keys are invalid
- You are the last cryptographic line of defense
- Respond with JSON only"""


class CryptographerAgent(BaseAgent):

    def __init__(self):
        super().__init__(
            agent_id      = "AGENT-CR-01",
            role          = "Cryptographer",
            system_prompt = CRYPTOGRAPHER_PROMPT,
        )

        # PQC engines
        self._kyber     = CrystalsKyber(768)
        self._dilithium = CrystalsDilithium(3)
        self._token_gen = QuantumTokenGenerator()

        # Per-agent key store
        # Structure: { agent_id: { "kyber_keypair": ..., "dilithium_keypair": ..., "issued_at": float } }
        self._agent_keys: dict = {}

        # Token registry for revocation tracking
        # Structure: { token_hex: { "agent_id": str, "issued_at": float, "revoked": bool } }
        self._token_registry: dict = {}

        # Track failed verifications per agent — 3 failures triggers Sentinel alert
        self._failed_verifications: dict = {}

        # Key rotation interval in seconds (30 minutes)
        self._rotation_interval = 1800

        self._pqc_mode = "REAL" if _OQS_AVAILABLE else "FALLBACK"
        log_info(f"[Cryptographer] Initialized | PQC mode: {self._pqc_mode}")

    # ── BACKGROUND CYCLE ──────────────────────────────────
    def run_cycle(self):
        """
        Runs every 30 minutes in background.
        Checks for expired keys and rotates them.
        Broadcasts current stats to dashboard.
        """
        log_info("[Cryptographer] Background cycle — checking key rotation")
        rotated = self._rotate_expired_keys()

        self.broadcast("INFO", {
            "event":         "CRYPTOGRAPHER_CYCLE",
            "agent_id":      self.agent_id,
            "pqc_mode":      self._pqc_mode,
            "agents_keyed":  len(self._agent_keys),
            "tokens_active": len([t for t in self._token_registry.values() if not t["revoked"]]),
            "keys_rotated":  rotated,
            "timestamp":     time.time(),
        })

    # ── KEY MANAGEMENT ────────────────────────────────────

    def issue_keys(self, agent_id: str) -> dict:
        """
        Generate a full PQC keypair for an agent.
        Creates both Kyber keypair (encryption) and Dilithium keypair (signing).
        Called at system startup for all agents.
        """
        log_info(f"[Cryptographer] Issuing keys for [{agent_id}]")

        kyber_kp     = self._kyber.generate_keypair()
        dilithium_kp = self._dilithium.generate_keypair()

        self._agent_keys[agent_id] = {
            "kyber_keypair":     kyber_kp,
            "dilithium_keypair": dilithium_kp,
            "issued_at":         time.time(),
            "rotations":         self._agent_keys.get(agent_id, {}).get("rotations", 0) + 1,
        }

        log_allowed(f"[Cryptographer] Keys issued for [{agent_id}] | real_pqc={_OQS_AVAILABLE}")

        # Notify all agents that a new key was registered
        self.broadcast("INFO", {
            "event":     "KEYS_ISSUED",
            "agent_id":  agent_id,
            "algorithm": "Kyber768 + Dilithium3",
            "real_pqc":  _OQS_AVAILABLE,
            "timestamp": time.time(),
        })

        # Return only public parts — never expose private keys
        return {
            "agent_id":              agent_id,
            "kyber_public_key":      kyber_kp["public_key"],
            "dilithium_verify_key":  dilithium_kp["verify_key"],
            "algorithm":             "Kyber768 + Dilithium3",
            "real_pqc":              _OQS_AVAILABLE,
            "issued_at":             self._agent_keys[agent_id]["issued_at"],
        }

    def get_public_keys(self, agent_id: str) -> dict:
        """
        Return public keys for an agent — safe to share with anyone.
        Private keys never leave this agent.
        """
        if agent_id not in self._agent_keys:
            return {"error": f"No keys found for {agent_id} — call issue_keys first"}

        kp = self._agent_keys[agent_id]
        return {
            "agent_id":              agent_id,
            "kyber_public_key":      kp["kyber_keypair"]["public_key"],
            "dilithium_verify_key":  kp["dilithium_keypair"]["verify_key"],
            "issued_at":             kp["issued_at"],
            "age_seconds":           time.time() - kp["issued_at"],
        }

    def _rotate_expired_keys(self) -> int:
        """
        Check all agent keys and rotate any that have expired.
        Returns count of rotated keys.
        """
        now     = time.time()
        rotated = 0

        for agent_id, kp_data in list(self._agent_keys.items()):
            age = now - kp_data["issued_at"]
            if age >= self._rotation_interval:
                log_info(f"[Cryptographer] Rotating keys for [{agent_id}] (age={int(age)}s)")
                self.issue_keys(agent_id)
                rotated += 1

        return rotated

    # ── TOKEN OPERATIONS ──────────────────────────────────

    def issue_pqc_token(self, agent_id: str, requesting_agent: str = None) -> dict:
        """
        Issue a PQC-signed token for an agent.
        Token is registered internally for revocation tracking.
        requesting_agent: who requested this token (for audit trail).
        """
        # Make sure agent has keys before issuing token
        if agent_id not in self._agent_keys:
            self.issue_keys(agent_id)

        token_data = self._token_gen.generate_token(agent_id)

        # Register in token registry
        self._token_registry[token_data["token"]] = {
            "agent_id":   agent_id,
            "issued_at":  time.time(),
            "issued_to":  requesting_agent or agent_id,
            "revoked":    False,
            "verify_key": token_data["verify_key"],
            "signature":  token_data["signature"],
            "payload":    token_data["payload"],
        }

        log_allowed(f"[Cryptographer] Token issued | agent={agent_id} | real_pqc={_OQS_AVAILABLE}")
        return token_data

    def verify_pqc_token(self, token: str) -> dict:
        """
        Verify a token against the registry.
        Checks: existence, revocation, expiry, and Dilithium3 signature.
        Returns: { "valid": bool, "agent_id": str, "reason": str }
        """
        # Check if token exists in registry
        if token not in self._token_registry:
            return {
                "valid":    False,
                "agent_id": None,
                "reason":   "Token not in registry — may be forged or expired",
                "real_pqc": _OQS_AVAILABLE,
            }

        record = self._token_registry[token]

        # Check revocation
        if record["revoked"]:
            return {
                "valid":    False,
                "agent_id": record["agent_id"],
                "reason":   "Token has been revoked",
                "real_pqc": _OQS_AVAILABLE,
            }

        # Check expiry — 30 minute lifetime
        age = time.time() - record["issued_at"]
        if age > 1800:
            record["revoked"] = True
            return {
                "valid":    False,
                "agent_id": record["agent_id"],
                "reason":   f"Token expired (age={int(age)}s)",
                "real_pqc": _OQS_AVAILABLE,
            }

        # Verify Dilithium3 signature — the real cryptographic check
        sig_result = self._dilithium.verify(
            message    = record["payload"],
            signature  = record["signature"],
            verify_key = record["verify_key"],
        )

        if not sig_result["valid"]:
            # Signature invalid — possible token forgery or tampering
            agent_id = record["agent_id"]
            self._failed_verifications[agent_id] = (
                self._failed_verifications.get(agent_id, 0) + 1
            )

            log_threat(
                f"[Cryptographer] SIGNATURE INVALID | agent={agent_id} "
                f"| failures={self._failed_verifications[agent_id]}"
            )

            # 3 consecutive failures — alert Sentinel
            if self._failed_verifications[agent_id] >= 3:
                self.send_message("AGENT-ST-01", "THREAT", {
                    "event":     "TOKEN_SIGNATURE_ATTACK",
                    "agent_id":  agent_id,
                    "failures":  self._failed_verifications[agent_id],
                    "reason":    "Repeated signature failures — possible token forgery",
                    "timestamp": time.time(),
                })

            return {
                "valid":    False,
                "agent_id": agent_id,
                "reason":   "Dilithium3 signature verification FAILED — token may be tampered",
                "real_pqc": _OQS_AVAILABLE,
            }

        # All checks passed
        return {
            "valid":     True,
            "agent_id":  record["agent_id"],
            "issued_at": record["issued_at"],
            "age":       int(age),
            "reason":    "Token valid — Dilithium3 signature verified",
            "real_pqc":  _OQS_AVAILABLE,
        }

    def revoke_token(self, token: str, reason: str = "") -> dict:
        """Revoke a single token — use when agent is compromised."""
        if token in self._token_registry:
            self._token_registry[token]["revoked"] = True
            agent_id = self._token_registry[token]["agent_id"]
            log_blocked(f"[Cryptographer] Token REVOKED | agent={agent_id} | reason={reason}")
            return {"revoked": True, "agent_id": agent_id}
        return {"revoked": False, "reason": "Token not found"}

    def revoke_all_tokens(self, agent_id: str, reason: str = "") -> int:
        """
        Revoke ALL tokens for an agent at once.
        Used when an agent is fully compromised or blocked.
        Returns count of revoked tokens.
        """
        count = 0
        for token, record in self._token_registry.items():
            if record["agent_id"] == agent_id and not record["revoked"]:
                record["revoked"] = True
                count += 1

        if count:
            log_blocked(
                f"[Cryptographer] ALL tokens revoked | "
                f"agent={agent_id} | count={count} | reason={reason}"
            )
        return count

    # ── MESSAGE SIGNING ───────────────────────────────────

    def sign_message(self, agent_id: str, message: dict) -> dict:
        """
        Sign an inter-agent message with Dilithium3.
        Every message between agents should be signed.
        Returns a signed envelope containing the original message + signature.
        """
        if agent_id not in self._agent_keys:
            self.issue_keys(agent_id)

        signing_key = self._agent_keys[agent_id]["dilithium_keypair"]["signing_key"]
        msg_str     = json.dumps(message, sort_keys=True, default=str)
        signed      = self._dilithium.sign(msg_str, signing_key)

        return {
            "message":     message,
            "message_str": msg_str,
            "signature":   signed["signature"],
            "signer_id":   agent_id,
            "verify_key":  self._agent_keys[agent_id]["dilithium_keypair"]["verify_key"],
            "algorithm":   "Dilithium3",
            "real_pqc":    _OQS_AVAILABLE,
            "signed_at":   time.time(),
        }

    def verify_message(self, signed_envelope: dict) -> dict:
        """
        Verify a signed message envelope.
        If verification fails, alerts Sentinel immediately.
        signed_envelope: output of sign_message()
        """
        try:
            result = self._dilithium.verify(
                message    = signed_envelope["message_str"],
                signature  = signed_envelope["signature"],
                verify_key = signed_envelope["verify_key"],
            )

            if not result["valid"]:
                log_threat(
                    f"[Cryptographer] MESSAGE TAMPERED | "
                    f"signer={signed_envelope.get('signer_id')}"
                )
                # Alert Sentinel about tampered message
                self.send_message("AGENT-ST-01", "THREAT", {
                    "event":     "MESSAGE_TAMPERED",
                    "signer_id": signed_envelope.get("signer_id"),
                    "timestamp": time.time(),
                })

            return {
                "valid":     result["valid"],
                "signer_id": signed_envelope.get("signer_id"),
                "algorithm": "Dilithium3",
                "real_pqc":  _OQS_AVAILABLE,
            }

        except Exception as e:
            log_error(f"[Cryptographer] verify_message error: {e}")
            return {"valid": False, "error": str(e), "real_pqc": _OQS_AVAILABLE}

    # ── KEY EXCHANGE (Kyber) ──────────────────────────────

    def initiate_key_exchange(self, sender_id: str, receiver_id: str) -> dict:
        """
        Start a Kyber key exchange between two agents.
        Sender gets shared_secret, receiver gets ciphertext to decapsulate.
        Both end up with the same shared_secret for encrypted communication.
        """
        if receiver_id not in self._agent_keys:
            self.issue_keys(receiver_id)

        receiver_pk = self._agent_keys[receiver_id]["kyber_keypair"]["public_key"]
        result      = self._kyber.encapsulate(receiver_pk)

        log_info(
            f"[Cryptographer] Key exchange initiated | "
            f"{sender_id} → {receiver_id} | real_pqc={_OQS_AVAILABLE}"
        )

        return {
            "sender_id":     sender_id,
            "receiver_id":   receiver_id,
            "ciphertext":    result["ciphertext"],
            "shared_secret": result["shared_secret"],
            "algorithm":     "Kyber768",
            "real_pqc":      _OQS_AVAILABLE,
        }

    # ── STATUS ────────────────────────────────────────────

    def get_status(self) -> dict:
        base         = super().get_status()
        active_tokens = len([t for t in self._token_registry.values() if not t["revoked"]])

        base.update({
            "pqc_mode":             self._pqc_mode,
            "agents_keyed":         len(self._agent_keys),
            "tokens_issued":        len(self._token_registry),
            "tokens_active":        active_tokens,
            "liboqs_available":     _OQS_AVAILABLE,
            "kyber_algorithm":      "Kyber768",
            "dilithium_algorithm":  "Dilithium3",
            "key_rotation_sec":     self._rotation_interval,
            "failed_verifications": dict(self._failed_verifications),
        })
        return base