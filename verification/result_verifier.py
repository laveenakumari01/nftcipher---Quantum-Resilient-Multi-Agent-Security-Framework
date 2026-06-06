"""
verification/result_verifier.py

Result Verification Engine
Answers the main question: "Is what the agent reported actually true?"

4-layer verification process:
  Layer 1 — LLM Grounding    : Force LLM to cite numbers, penalize hallucination
  Layer 2 — Rule Scorer      : Deterministic flag-based scoring (no LLM needed)
  Layer 3 — Consensus Vote   : 3 voters (LLM + ML + Rules), need 2-of-3 to confirm
  Layer 4 — Integrity Hash   : SHA3-512 hash on every result for tamper detection

Action levels based on consensus score:
  score >= 0.80  →  AUTO_BLOCK   (agent acts autonomously, no human needed)
  score >= 0.50  →  ALERT        (log and notify, action still taken)
  score >= 0.25  →  WATCHLIST    (monitor closely)
  score <  0.25  →  IGNORE       (not a threat)
"""

import json
import time
import hashlib
import secrets
from dataclasses import dataclass, field, asdict
from typing import Optional
from logger import log_info, log_threat, log_blocked, log_error
from config.settings import (
    VERIFY_AUTO_BLOCK_SCORE,
    VERIFY_ALERT_SCORE,
    VERIFY_WATCHLIST_SCORE,
)


# ── Data structures ───────────────────────────────────────

@dataclass
class AgentClaim:
    """
    Raw claim from any agent before verification.
    Sentinel, ThreatDetection, or any agent fills this.
    raw_evidence must contain actual numbers — not descriptions.
    """
    agent_id:     str
    claim_type:   str           # "THREAT" | "NORMAL" | "ANOMALY"
    confidence:   float         # 0.0 to 1.0 — agent's own confidence
    flags:        list          # ["HIGH_REQUEST_COUNT", "ML_BRUTE_FORCE", ...]
    raw_evidence: dict          # actual observed data with numbers
    llm_reason:   str  = ""     # what the LLM said originally
    timestamp:    float = field(default_factory=time.time)


@dataclass
class VerifiedResult:
    """
    Final trusted result after all 4 verification layers pass.
    Only this result is used to take action — raw claims are never acted on.
    """
    original_claim:    AgentClaim
    is_verified:       bool
    final_verdict:     str        # "CONFIRMED_THREAT" | "FALSE_POSITIVE" | "UNCERTAIN" | "NORMAL"
    consensus_score:   float      # 0.0 to 1.0
    action_level:      str        # "AUTO_BLOCK" | "ALERT" | "WATCHLIST" | "IGNORE"
    vote_breakdown:    dict       # {"llm": 0.82, "ml": 0.91, "rules": 0.40}
    integrity_hash:    str        # tamper detection fingerprint
    verification_time: float = field(default_factory=time.time)
    notes:             list  = field(default_factory=list)


# ── Layer 1: LLM Grounding ────────────────────────────────

class LLMGrounder:
    """
    Forces the LLM to reason only from observed facts with specific numbers.
    If the LLM reasoning contains no numbers, it is penalized for hallucination.
    This prevents the LLM from saying "this looks suspicious" with no evidence.
    """

    # Normal baseline values — deviations from these trigger flags
    BASELINES = {
        "max_rpm":            30.0,
        "max_failed_auth":    5,
        "max_data_mb":        50.0,
        "max_unique_actions": 8,
        "max_request_count":  20,
    }

    def build_grounded_prompt(self, claim: AgentClaim) -> str:
        """
        Build a prompt that forces the LLM to cite specific numbers.
        Pre-calculates deviations so the LLM cannot ignore them.
        """
        e = claim.raw_evidence
        b = self.BASELINES

        # Pre-calculate which metrics are outside normal range
        deviations = []
        if e.get("rpm", 0)            > b["max_rpm"]:            deviations.append(f"rpm={e['rpm']} (baseline {b['max_rpm']})")
        if e.get("failed_attempts", 0) > b["max_failed_auth"]:   deviations.append(f"failed={e['failed_attempts']} (baseline {b['max_failed_auth']})")
        if e.get("data_mb", 0)         > b["max_data_mb"]:       deviations.append(f"data_mb={e['data_mb']} (baseline {b['max_data_mb']})")
        if e.get("request_count", 0)   > b["max_request_count"]: deviations.append(f"requests={e['request_count']} (baseline {b['max_request_count']})")

        return f"""You are a security classifier. Analyze ONLY the facts below.
Do NOT speculate. Every claim MUST reference a specific number from the evidence.
If you cannot cite a number, do not make the claim.

OBSERVED FACTS:
- Agent ID: {claim.agent_id}
- Triggered flags: {claim.flags}
- Metrics outside baseline: {deviations if deviations else 'none'}
- Full evidence: {json.dumps(claim.raw_evidence)}

Respond ONLY with this exact JSON format:
{{"verdict": "THREAT" or "NORMAL", "confidence": <float 0.0-1.0>, "cited_numbers": ["num1", "num2"], "reasoning": "<one sentence referencing specific numbers only>"}}"""

    def score(self, claim: AgentClaim, agent) -> dict:
        """
        Get LLM score with grounding applied.
        Returns confidence penalized if no numbers were cited.
        """
        prompt = self.build_grounded_prompt(claim)
        try:
            raw = agent._call_llm(prompt)
            if not raw:
                return {"verdict": "NORMAL", "confidence": 0.3, "reasoning": "LLM unavailable", "penalized": False}

            raw = raw.replace("```json", "").replace("```", "").strip()
            if "{" in raw:
                raw = raw[raw.index("{") : raw.rindex("}") + 1]

            parsed = json.loads(raw)

            # Hallucination check — reasoning must contain at least one number
            reasoning  = parsed.get("reasoning", "")
            has_number = any(ch.isdigit() for ch in reasoning)
            conf       = float(parsed.get("confidence", 0.5))

            if not has_number:
                # Penalize — no numbers means LLM was guessing
                conf = conf * 0.5
                parsed["reasoning"] += " [GROUNDING_PENALTY: no numbers cited in reasoning]"

            return {
                "verdict":    parsed.get("verdict", "NORMAL"),
                "confidence": round(conf, 3),
                "reasoning":  parsed.get("reasoning", ""),
                "cited":      parsed.get("cited_numbers", []),
                "penalized":  not has_number,
            }

        except Exception as e:
            log_error(f"[LLMGrounder] parse error: {e}")
            return {"verdict": "NORMAL", "confidence": 0.3, "reasoning": f"parse error: {e}", "penalized": False}


# ── Layer 2: Rule Scorer ──────────────────────────────────

class RuleScorer:
    """
    Deterministic rule-based scoring.
    No LLM involvement — fast, predictable, consistent.
    Each flag maps to a fixed threat weight.
    Multiple flags compound the score.
    """

    # Flag → threat weight mapping
    RULES = [
        ("HIGH_REQUEST_COUNT",        0.55),
        ("REPEATED_ACTION",           0.40),
        ("LATERAL_MOVEMENT",          0.70),
        ("LARGE_DATA_EXPORT",         0.80),
        ("ML_BRUTE_FORCE",            0.85),
        ("ML_API_FLOODING",           0.75),
        ("ML_PRIVILEGE_ESCALATION",   0.90),
        ("ML_DATA_EXFILTRATION",      0.95),
        ("TOKEN_SIGNATURE_ATTACK",    0.99),
        ("MESSAGE_TAMPERED",          0.99),
        ("PHISHING_DETECTED",         0.80),
        ("MALWARE_DETECTED",          0.90),
        ("NETWORK_ANOMALY",           0.70),
        ("PHYSICAL_ANOMALY",          0.65),
    ]

    def score(self, claim: AgentClaim) -> dict:
        """
        Score based on flags present in the claim.
        Worst-case flag sets the base, additional flags add compound risk.
        """
        score   = 0.0
        matched = []

        for flag, weight in self.RULES:
            if flag in claim.flags:
                score = max(score, weight)
                matched.append(flag)

        # Multiple flags together = higher risk than any single flag
        if len(matched) > 1:
            score = min(score + 0.08 * (len(matched) - 1), 1.0)

        verdict = "THREAT" if score >= 0.50 else "NORMAL"
        return {
            "verdict":       verdict,
            "confidence":    round(score, 3),
            "matched_rules": matched,
        }


# ── Layer 3: Consensus Engine ─────────────────────────────

class ConsensusEngine:
    """
    Combines votes from 3 independent sources.
    Decision requires majority (2-of-3) plus weighted score.

    Weights:
      LLM   35% — flexible but can hallucinate
      ML    45% — trained model, most reliable for known patterns
      Rules 20% — simple but fast and consistent
    """

    WEIGHTS = {
        "llm":   0.35,
        "ml":    0.45,
        "rules": 0.20,
    }

    def vote(self,
             llm_result:    dict,
             ml_risk_score: float,
             rule_result:   dict) -> dict:
        """
        Combine all 3 votes into a single consensus.
        ml_risk_score comes from AnomalyDetector.detect()["risk_score"]
        """
        scores = {
            "llm":   llm_result.get("confidence", 0.3) if llm_result.get("verdict") == "THREAT"
                     else llm_result.get("confidence", 0.3) * 0.2,
            "ml":    float(ml_risk_score),
            "rules": rule_result.get("confidence", 0.0) if rule_result.get("verdict") == "THREAT"
                     else 0.0,
        }

        # Weighted average across all sources
        weighted_score  = sum(scores[k] * self.WEIGHTS[k] for k in scores)
        consensus_score = weighted_score / sum(self.WEIGHTS.values())

        # Count how many sources voted THREAT
        votes_for_threat = sum(1 for v in scores.values() if v >= 0.5)
        majority_threat  = votes_for_threat >= 2

        return {
            "verdict":          "THREAT" if majority_threat else "NORMAL",
            "consensus_score":  round(consensus_score, 3),
            "vote_breakdown":   {k: round(v, 3) for k, v in scores.items()},
            "votes_for_threat": votes_for_threat,
            "majority_threat":  majority_threat,
        }


# ── Layer 4: Action Gate ──────────────────────────────────

class ActionGate:
    """
    Translates consensus score into a specific action level.
    Some flags bypass the threshold and trigger AUTO_BLOCK directly.
    """

    # These flags are so serious that they skip threshold checks
    CRITICAL_FLAGS = {
        "ML_DATA_EXFILTRATION",
        "ML_PRIVILEGE_ESCALATION",
        "TOKEN_SIGNATURE_ATTACK",
        "MESSAGE_TAMPERED",
        "MALWARE_DETECTED",
    }

    def decide(self, consensus_score: float, flags: list) -> str:
        """
        Determine what action to take based on score and flags.
        Critical flags always result in AUTO_BLOCK regardless of score.
        """
        if any(f in self.CRITICAL_FLAGS for f in flags):
            return "AUTO_BLOCK"

        if consensus_score >= VERIFY_AUTO_BLOCK_SCORE: return "AUTO_BLOCK"
        if consensus_score >= VERIFY_ALERT_SCORE:      return "ALERT"
        if consensus_score >= VERIFY_WATCHLIST_SCORE:  return "WATCHLIST"
        return "IGNORE"


# ── Integrity Hasher ──────────────────────────────────────

class IntegrityHasher:
    """
    Creates a SHA3-512 fingerprint on every verified result.
    During audit, recompute the hash — any mismatch means tampering occurred.
    The signing key is generated once at startup and never changes.
    """
    _KEY = secrets.token_hex(32)

    @classmethod
    def sign(cls, payload: dict) -> str:
        """Create tamper-proof hash of the result payload."""
        canonical = json.dumps(payload, sort_keys=True, default=str)
        raw       = f"{cls._KEY}|{canonical}"
        return hashlib.sha3_512(raw.encode()).hexdigest()

    @classmethod
    def verify_hash(cls, payload: dict, stored_hash: str) -> bool:
        """
        Recompute hash and compare with stored value.
        Returns False if the stored result was modified after creation.

        Fix: sign() uses _KEY in the hash input but the old verify_hash()
        did not — so recomputed hash never matched the stored one, making
        tamper detection always report TAMPERED even on untouched results.
        Now both sign() and verify_hash() use the same _KEY so hashes match.
        """
        canonical    = json.dumps(payload, sort_keys=True, default=str)
        raw          = f"{cls._KEY}|{canonical}"   # same formula as sign()
        recomputed   = hashlib.sha3_512(raw.encode()).hexdigest()
        return recomputed == stored_hash


# ── Main ResultVerifier ───────────────────────────────────

class ResultVerifier:
    """
    Runs all 4 verification layers on an agent claim.
    No agent can take action without going through this verifier first.

    Usage in sentinel_agent.py:

        from verification.result_verifier import ResultVerifier, AgentClaim

        verifier = ResultVerifier()

        claim = AgentClaim(
            agent_id     = "AGENT-ST-01",
            claim_type   = "THREAT",
            confidence   = ml_result["risk_score"],
            flags        = flags,
            raw_evidence = {
                "request_count":   req_count,
                "rpm":             45.2,
                "failed_attempts": 8,
                "data_mb":         120.5,
            },
            llm_reason = decision.get("reason", "")
        )

        result = verifier.verify(claim, sentinel_agent, ml_risk_score=ml_result["risk_score"])

        if result.action_level == "AUTO_BLOCK":
            sentinel.block_adversary_directly(result.final_verdict)
        elif result.action_level == "ALERT":
            sentinel.broadcast("THREAT", asdict(result))
    """

    def __init__(self):
        self.grounder  = LLMGrounder()
        self.rules     = RuleScorer()
        self.consensus = ConsensusEngine()
        self.gate      = ActionGate()
        self.hasher    = IntegrityHasher()

    def verify(self,
               claim:         AgentClaim,
               agent,
               ml_risk_score: float = 0.5) -> VerifiedResult:
        """
        Run all 4 layers and return a verified result.
        agent: the BaseAgent instance (needed for LLM access in Layer 1)
        ml_risk_score: from AnomalyDetector.detect()["risk_score"]
        """
        log_info(
            f"[Verifier] Verifying claim | agent={claim.agent_id} | "
            f"type={claim.claim_type} | flags={claim.flags}"
        )
        notes = []

        # Layer 1 — Grounded LLM
        llm_result = self.grounder.score(claim, agent)
        if llm_result.get("penalized"):
            notes.append("LLM_HALLUCINATION_SUSPECTED: reasoning had no cited numbers")
        log_info(f"[Verifier] LLM vote: {llm_result['verdict']} | conf={llm_result['confidence']:.2f}")

        # Layer 2 — Rule score
        rule_result = self.rules.score(claim)
        log_info(f"[Verifier] Rule vote: {rule_result['verdict']} | conf={rule_result['confidence']:.2f}")

        # Layer 3 — Consensus
        consensus = self.consensus.vote(llm_result, ml_risk_score, rule_result)
        log_info(
            f"[Verifier] Consensus: score={consensus['consensus_score']:.2f} | "
            f"{consensus['votes_for_threat']}/3 voted THREAT"
        )

        # Layer 4 — Action decision
        action = self.gate.decide(consensus["consensus_score"], claim.flags)

        # Determine final verdict
        if consensus["majority_threat"] and consensus["consensus_score"] >= 0.50:
            final = "CONFIRMED_THREAT"
        elif not consensus["majority_threat"] and claim.claim_type == "THREAT":
            final = "FALSE_POSITIVE"
            notes.append("ORIGINAL_CLAIM_OVERRIDDEN: consensus disagreed with agent claim")
        elif consensus["consensus_score"] >= 0.25:
            final = "UNCERTAIN"
            notes.append("LOW_CONFIDENCE: continued monitoring recommended")
        else:
            final = "NORMAL"

        # Create integrity hash for tamper detection
        payload_for_hash = {
            "agent_id":        claim.agent_id,
            "final_verdict":   final,
            "consensus_score": consensus["consensus_score"],
            "action_level":    action,
            "flags":           claim.flags,
            "timestamp":       claim.timestamp,
        }
        integrity_hash = self.hasher.sign(payload_for_hash)

        result = VerifiedResult(
            original_claim  = claim,
            is_verified     = True,
            final_verdict   = final,
            consensus_score = consensus["consensus_score"],
            action_level    = action,
            vote_breakdown  = consensus["vote_breakdown"],
            integrity_hash  = integrity_hash,
            notes           = notes,
        )

        # Log based on verdict
        if final == "CONFIRMED_THREAT":
            log_threat(
                f"[Verifier] CONFIRMED_THREAT | agent={claim.agent_id} | "
                f"action={action} | score={consensus['consensus_score']:.2f}"
            )
        elif final == "FALSE_POSITIVE":
            log_info(f"[Verifier] FALSE_POSITIVE caught | agent={claim.agent_id} | flags={claim.flags}")
        else:
            log_info(f"[Verifier] Result: {final} | action={action}")

        return result


# ── Audit utility ─────────────────────────────────────────

def audit_log_integrity(stored_results: list) -> dict:
    """
    Audit stored results for tampering.
    Recomputes hash for each entry and compares with stored value.
    Any mismatch means the log was modified after creation.

    Usage:
        rows = db.execute("SELECT payload, hash FROM verified_results", fetch=True)
        report = audit_log_integrity([{"payload": r[0], "hash": r[1]} for r in rows])
        if report["integrity"] == "FAIL":
            sentinel.broadcast("THREAT", report)
    """
    hasher   = IntegrityHasher()
    ok       = []
    tampered = []

    for entry in stored_results:
        payload     = entry.get("payload", {})
        stored_hash = entry.get("hash", "")

        if hasher.verify_hash(payload, stored_hash):
            ok.append(entry)
        else:
            tampered.append({
                "agent_id":  payload.get("agent_id", "unknown"),
                "timestamp": payload.get("timestamp"),
                "status":    "TAMPERED",
            })
            log_blocked(f"[Audit] TAMPER DETECTED | agent={payload.get('agent_id')}")

    return {
        "total":            len(stored_results),
        "ok":               len(ok),
        "tampered":         len(tampered),
        "tampered_entries": tampered,
        "integrity":        "PASS" if not tampered else "FAIL",
        "audit_time":       time.time(),
    }