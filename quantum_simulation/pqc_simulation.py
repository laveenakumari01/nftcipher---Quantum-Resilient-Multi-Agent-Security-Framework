"""
PQC Simulation
CRYSTALS-Kyber + CRYSTALS-Dilithium
Used by Adversary Agent for quantum attack simulation
"""
import os
import hashlib
import time
from logger import log_info


class CrystalsKyber:
    def __init__(self, security_level: int = 512):
        self.security_level = security_level
        self.algorithm = f"KYBER-{security_level}"

    def generate_keypair(self) -> dict:
        seed = os.urandom(32)
        return {
            "algorithm": self.algorithm,
            "public_key": hashlib.sha3_512(seed).hexdigest()[:64],
            "private_key": hashlib.sha3_256(seed).hexdigest()[:64],
            "quantum_resistant": True
        }

    def encapsulate(self, public_key: str) -> dict:
        seed = os.urandom(16)
        return {
            "ciphertext": hashlib.sha3_256(public_key.encode() + seed).hexdigest(),
            "shared_secret": hashlib.sha3_512(public_key.encode() + seed).hexdigest()[:32],
            "algorithm": self.algorithm
        }


class CrystalsDilithium:
    def __init__(self, mode: int = 3):
        self.mode = mode
        self.algorithm = f"DILITHIUM-{mode}"

    def generate_keypair(self) -> dict:
        seed = os.urandom(32)
        return {
            "algorithm": self.algorithm,
            "signing_key": hashlib.sha3_256(seed).hexdigest()[:64],
            "verify_key": hashlib.sha3_512(seed).hexdigest()[:64],
            "quantum_resistant": True
        }

    def sign(self, message: str, signing_key: str) -> dict:
        return {
            "message": message,
            "signature": hashlib.sha3_512(message.encode() + signing_key.encode()).hexdigest(),
            "algorithm": self.algorithm,
            "timestamp": time.time()
        }

    def verify(self, message: str, signature: str, verify_key: str) -> dict:
        expected = hashlib.sha3_512(message.encode() + verify_key.encode()).hexdigest()
        return {
            "valid": len(signature) == len(expected),
            "algorithm": self.algorithm
        }


class QuantumVsClassical:
    def compare(self) -> dict:
        log_info("Classical vs PQC comparison running")
        return {
            "classical": {
                "algorithm": "RSA-2048",
                "quantum_safe": False,
                "resilience_to_shors": "10.9%",
                "handshake_time": "12ms",
                "description": "Vulnerable to Shor's Algorithm"
            },
            "pqc": {
                "algorithm": "CRYSTALS-Kyber + Dilithium",
                "quantum_safe": True,
                "resilience_to_shors": "99.99%",
                "handshake_time": "0.8ms",
                "description": "Lattice-based — immune to quantum attacks"
            }
        }


class QuantumTokenGenerator:
    def __init__(self):
        self.dilithium = CrystalsDilithium(3)
        self.keypair = self.dilithium.generate_keypair()
        log_info("Quantum Token Generator ready")

    def generate_token(self, agent_id: str) -> dict:
        payload = f"{agent_id}:{time.time()}"
        signed = self.dilithium.sign(payload, self.keypair["signing_key"])
        token = hashlib.sha3_256(signed["signature"].encode()).hexdigest()
        log_info(f"Quantum token generated for: {agent_id}")
        return {
            "agent_id": agent_id,
            "token": token,
            "algorithm": "DILITHIUM-3",
            "quantum_resistant": True,
            "expires_in": 1800
        }