"""
agents/threat_detection_agent.py

AI Threat Detection Agent — AGENT-TD-01

Responsibilities:
  - Phishing URL and email detection
  - Malware signature analysis
  - Network anomaly detection
  - Vote in the verification consensus alongside Sentinel and ML model
  - Run autonomously every 20 seconds

Three detection engines running in parallel:
  1. Phishing Engine  — URL pattern matching + LLM analysis
  2. Malware Engine   — signature database matching
  3. Network Engine   — traffic anomaly scoring

All detections go through ResultVerifier before alerting Sentinel.
This agent's confidence score feeds into the 3-voter consensus system.
"""

import time
import json
import hashlib
import re
from agents.base_agent import BaseAgent
from rag.vector_store import VectorStore
from rag.vectorless_store import VectorlessStore
from verification.result_verifier import ResultVerifier, AgentClaim
from logger import log_info, log_threat, log_error, log_allowed


THREAT_DETECTION_PROMPT = """You are an AI Threat Detection Agent for NFTCipher.

Your job is to detect: phishing URLs, malware patterns, and network anomalies.
Base ALL verdicts on specific indicators present in the data.
Never guess — only flag what you can directly observe.
Respond with JSON only."""


# Known phishing indicators — fast lookup without LLM
PHISHING_INDICATORS = [
    "paypa1.com", "g00gle.com", "amaz0n.com", "arnazon.com",
    "bank-secure-login", "verify-account-now", "suspended-account",
    "urgent-action-required", "login-confirm-secure", "free-gift-claim",
    "account-verification-needed", "security-alert-immediate",
    "update-billing-info", "confirm-your-identity",
]

# Malware family signatures — string patterns found in malicious code
MALWARE_SIGNATURES = {
    "EMOTET": [
        "powershell -enc",
        "cmd /c echo",
        "regsvr32 /s /n /u /i:",
        "wscript.shell",
    ],
    "MIRAI": [
        "/bin/busybox LZRD",
        "SCANNER ON",
        "/proc/net/tcp",
        "tftp -g -r",
    ],
    "RANSOMWARE": [
        "YOUR FILES HAVE BEEN ENCRYPTED",
        "bitcoin_address",
        ".locked extension",
        "decrypt_instructions",
        "pay within 72 hours",
    ],
    "COBALT_STRIKE": [
        "beacon.dll",
        "ReflectiveDLLInjection",
        "cs_beacon",
        "METERPRETER",
    ],
    "CREDENTIAL_STEALER": [
        "document.cookie",
        "localStorage.getItem",
        "keylogger",
        "screenshot()",
        "clipboard_capture",
    ],
}


class ThreatDetectionAgent(BaseAgent):

    def __init__(self):
        super().__init__(
            agent_id      = "AGENT-TD-01",
            role          = "Threat Detection",
            system_prompt = THREAT_DETECTION_PROMPT,
        )

        # Vector store for threat pattern storage
        # Stores detected threats for future similarity matching
        self.vector_store = VectorStore(
            collection_name = "threat_patterns",
            db_path         = "./chroma_db",
        )

        # Fast cache for active blacklists and counters
        self.fast_cache = VectorlessStore()

        # Verification engine — all detections verified before alerting
        self.verifier = ResultVerifier()

        # Detection history per engine
        self._phishing_detections: list = []
        self._malware_detections:  list = []
        self._network_detections:  list = []
        self._false_positives:     int  = 0

        # Seed known phishing domains into fast cache blacklist
        self._seed_blacklists()

        log_info(
            f"[ThreatDetection] Agent ready | "
            f"phishing_indicators={len(PHISHING_INDICATORS)} | "
            f"malware_families={len(MALWARE_SIGNATURES)}"
        )

    def _seed_blacklists(self):
        """Load known bad domains and IPs into the fast cache at startup."""
        for indicator in PHISHING_INDICATORS:
            if "." in indicator:
                self.fast_cache.blacklist_domain(indicator, reason="Known phishing domain", ttl_hours=720)

        log_info(f"[ThreatDetection] Blacklists seeded | domains={len(PHISHING_INDICATORS)}")

    # ── BACKGROUND CYCLE ──────────────────────────────────
    def run_cycle(self):
        """
        Runs every 20 seconds.
        Monitors network traffic metrics and checks for anomalies automatically.
        In production, connect to real network monitoring tools here.
        """
        log_info("[ThreatDetection] Background cycle — scanning")

        # Simulate network traffic monitoring
        simulated_traffic = self._get_network_snapshot()
        if simulated_traffic:
            result = self.detect_network_anomaly(simulated_traffic)
            if result.get("verdict") == "ANOMALY":
                log_threat(f"[ThreatDetection] Background anomaly: {result.get('flags')}")

        # Broadcast cycle stats
        self.broadcast("INFO", {
            "event":       "TD_CYCLE",
            "agent_id":    self.agent_id,
            "phishing":    len(self._phishing_detections),
            "malware":     len(self._malware_detections),
            "network":     len(self._network_detections),
            "false_pos":   self._false_positives,
            "timestamp":   time.time(),
        })

    def _get_network_snapshot(self) -> dict | None:
        """
        Get current network traffic metrics.
        In production, pull from: Zeek logs, Snort alerts, netflow data, or SIEM.
        Simulation returns realistic values with occasional anomalies.
        """
        import random

        # 10% chance of generating an anomaly in simulation
        if random.random() < 0.10:
            return {
                "rpm":             random.randint(150, 500),  # high — anomaly
                "failed_attempts": random.randint(15, 50),
                "unique_ips":      random.randint(60, 200),
                "data_mb":         random.uniform(200, 500),
                "protocols":       ["TCP", "UDP"],
                "source":          "simulated_monitor",
            }
        return None  # No anomaly — skip this cycle

    # ── ENGINE 1: PHISHING DETECTION ──────────────────────
    def detect_phishing(self, url: str) -> dict:
        """
        Two-stage phishing detection:
          Stage 1: Fast rule-based check against known indicators
          Stage 2: LLM deep analysis for unknown patterns

        Final score = max(rule_score, llm_confidence)
        Sends verified threat to Sentinel if confirmed.
        """
        log_info(f"[ThreatDetection] Phishing check: {url[:60]}")

        url_lower = url.lower()

        # Stage 1 — Rule-based fast check
        # Check against known bad indicators in URL
        rule_matched = [ind for ind in PHISHING_INDICATORS if ind in url_lower]

        # Check blacklisted domains in fast cache
        try:
            domain = url_lower.split("/")[2] if "//" in url_lower else url_lower.split("/")[0]
            if self.fast_cache.is_blacklisted_domain(domain):
                rule_matched.append(f"blacklisted:{domain}")
        except Exception:
            pass

        # Check common URL spoofing patterns with regex
        spoof_patterns = [
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # IP address as domain
            r"[a-z]+-secure-[a-z]+\.",                  # secure-login pattern
            r"[a-z]+\.tk$|\.ml$|\.ga$|\.cf$",          # free TLDs abused by phishers
            r"[a-z]+(0|1|l|rn)[a-z]+\.[a-z]{2,}",     # character substitution
        ]
        for pattern in spoof_patterns:
            if re.search(pattern, url_lower):
                rule_matched.append(f"pattern:{pattern[:30]}")

        rule_score = min(len(rule_matched) * 0.25, 0.95)

        # Stage 2 — LLM analysis (always runs for deeper inspection)
        prompt = f"""Analyze this URL for phishing indicators:

URL: {url}
Rule-based indicators already found: {rule_matched}
Rule score: {rule_score:.2f}

Check for:
  - Domain name lookalikes (paypal vs paypa1)
  - Suspicious subdomain structures
  - Urgency keywords in path
  - Mismatched brand name and TLD
  - Redirect chains or URL shorteners masking destination

Respond with JSON only:
{{
  "is_phishing":   true or false,
  "confidence":    <float 0.0-1.0>,
  "indicators":    ["specific indicator found in URL"],
  "reasoning":     "one sentence citing specific URL components"
}}"""

        response = self._call_llm(prompt)

        result = {
            "url":          url,
            "rule_matched": rule_matched,
            "rule_score":   rule_score,
            "timestamp":    time.time(),
        }

        llm_confidence = 0.0
        if response:
            try:
                raw = response.replace("```json", "").replace("```", "").strip()
                if "{" in raw:
                    raw = raw[raw.index("{") : raw.rindex("}") + 1]
                parsed        = json.loads(raw)
                llm_confidence = float(parsed.get("confidence", 0.0))
                result.update({
                    "is_phishing":  parsed.get("is_phishing", False),
                    "indicators":   parsed.get("indicators", []),
                    "reasoning":    parsed.get("reasoning", ""),
                    "llm_analyzed": True,
                })
            except Exception as e:
                log_error(f"[ThreatDetection] Phishing LLM parse error: {e}")

        # Final score — take higher of rule and LLM
        final_score = max(rule_score, llm_confidence)
        result["final_confidence"] = round(final_score, 3)
        result["verdict"]          = "PHISHING" if final_score > 0.50 else "CLEAN"

        if result["verdict"] == "PHISHING":
            # Verify before alerting
            claim = AgentClaim(
                agent_id     = self.agent_id,
                claim_type   = "THREAT",
                confidence   = final_score,
                flags        = ["PHISHING_DETECTED"],
                raw_evidence = {
                    "url":             url,
                    "rule_matched":    len(rule_matched),
                    "rule_score":      rule_score,
                    "llm_confidence":  llm_confidence,
                    "request_count":   1,
                    "rpm":             0,
                },
                llm_reason = result.get("reasoning", ""),
            )

            verified = self.verifier.verify(claim, self, ml_risk_score=final_score)
            result["verified"]         = True
            result["consensus_score"]  = verified.consensus_score
            result["action_level"]     = verified.action_level
            result["final_verdict"]    = verified.final_verdict

            if verified.final_verdict == "CONFIRMED_THREAT":
                self._phishing_detections.append(result)

                # Blacklist the domain automatically
                try:
                    domain = url.lower().split("/")[2] if "//" in url.lower() else url.split("/")[0]
                    self.fast_cache.blacklist_domain(domain, reason=f"Phishing detected: score={final_score:.2f}")
                except Exception:
                    pass

                # Store pattern in vector store for future similarity matching
                self.vector_store.add(
                    doc_id   = hashlib.sha256(url.encode()).hexdigest()[:16],
                    content  = f"phishing url {url} indicators: {' '.join(rule_matched)}",
                    metadata = {"type": "phishing", "url": url[:100], "score": final_score},
                )

                # Alert Sentinel
                self.send_message("AGENT-ST-01", "THREAT", {
                    "event":          "PHISHING_CONFIRMED",
                    "agent_id":       self.agent_id,
                    "url":            url,
                    "confidence":     final_score,
                    "consensus_score": verified.consensus_score,
                    "action_level":   verified.action_level,
                    "timestamp":      time.time(),
                })

                log_threat(f"[ThreatDetection] PHISHING CONFIRMED | {url[:50]} | score={final_score:.2f}")

            elif verified.final_verdict == "FALSE_POSITIVE":
                self._false_positives += 1
                result["verdict"] = "CLEAN"
                log_info(f"[ThreatDetection] Phishing false positive caught: {url[:50]}")

        return result

    # ── ENGINE 2: MALWARE ANALYSIS ────────────────────────
    def analyze_malware(self, content: str, content_type: str = "string") -> dict:
        """
        Scan content for malware signatures.
        Checks against known malware family signatures.
        Content can be: file content, network payload, command string, script.

        Returns matched families and threat score.
        """
        log_info(f"[ThreatDetection] Malware scan | type={content_type} | size={len(content)}B")

        content_hash    = hashlib.sha256(content.encode()).hexdigest()
        matched_families = {}

        # Check each malware family
        for family, signatures in MALWARE_SIGNATURES.items():
            hits = [sig for sig in signatures if sig.lower() in content.lower()]
            if hits:
                matched_families[family] = hits

        # Score based on matches
        total_hits = sum(len(v) for v in matched_families.values())
        rule_score = min(total_hits * 0.30, 1.0)

        result = {
            "content_hash":      content_hash,
            "content_type":      content_type,
            "content_size":      len(content),
            "matched_families":  matched_families,
            "family_count":      len(matched_families),
            "rule_score":        rule_score,
            "timestamp":         time.time(),
        }

        if matched_families:
            # Verify before alerting
            claim = AgentClaim(
                agent_id     = self.agent_id,
                claim_type   = "THREAT",
                confidence   = rule_score,
                flags        = ["MALWARE_DETECTED"],
                raw_evidence = {
                    "families_matched": len(matched_families),
                    "total_hits":       total_hits,
                    "rule_score":       rule_score,
                    "request_count":    1,
                    "rpm":              0,
                },
                llm_reason = f"Malware signatures matched: {list(matched_families.keys())}",
            )

            verified = self.verifier.verify(claim, self, ml_risk_score=rule_score)
            result["verified"]        = True
            result["consensus_score"] = verified.consensus_score
            result["action_level"]    = verified.action_level
            result["final_verdict"]   = verified.final_verdict

            if verified.final_verdict == "CONFIRMED_THREAT":
                self._malware_detections.append(result)

                # Store in vector store for pattern learning
                self.vector_store.add(
                    doc_id   = content_hash[:16],
                    content  = f"malware families:{' '.join(matched_families.keys())} hits:{total_hits}",
                    metadata = {
                        "type":     "malware",
                        "families": list(matched_families.keys()),
                        "hash":     content_hash,
                        "score":    rule_score,
                    },
                )

                self.send_message("AGENT-ST-01", "THREAT", {
                    "event":          "MALWARE_CONFIRMED",
                    "agent_id":       self.agent_id,
                    "families":       list(matched_families.keys()),
                    "score":          rule_score,
                    "consensus_score": verified.consensus_score,
                    "action_level":   verified.action_level,
                    "timestamp":      time.time(),
                })

                log_threat(
                    f"[ThreatDetection] MALWARE CONFIRMED | "
                    f"families={list(matched_families.keys())} | score={rule_score:.2f}"
                )

            elif verified.final_verdict == "FALSE_POSITIVE":
                self._false_positives += 1

            result["verdict"] = "MALWARE" if verified.final_verdict == "CONFIRMED_THREAT" else "CLEAN"
        else:
            result["verdict"] = "CLEAN"
            result["final_verdict"] = "NORMAL"

        return result

    # ── ENGINE 3: NETWORK ANOMALY ──────────────────────────
    def detect_network_anomaly(self, traffic_data: dict) -> dict:
        """
        Analyze network traffic metrics for anomalies.
        Uses rule-based thresholds + verification engine.

        traffic_data fields:
          rpm             : requests per minute
          failed_attempts : failed connection attempts
          unique_ips      : number of unique source IPs
          data_mb         : data transferred in MB
          protocols       : list of protocols observed
        """
        log_info("[ThreatDetection] Network anomaly check")

        rpm    = traffic_data.get("rpm", 0)
        failed = traffic_data.get("failed_attempts", 0)
        ips    = traffic_data.get("unique_ips", 1)
        data   = traffic_data.get("data_mb", 0)

        # Flag based on threshold violations
        flags = []
        if rpm    > 100:  flags.append(f"HIGH_RPM:{int(rpm)}_vs_baseline_30")
        if failed > 10:   flags.append(f"BRUTE_FORCE:{failed}_failures")
        if ips    > 50:   flags.append(f"DISTRIBUTED:{ips}_unique_ips")
        if data   > 100:  flags.append(f"DATA_EXFIL:{data:.1f}MB")

        rule_score = min(len(flags) * 0.25, 1.0)

        result = {
            "traffic_data":  traffic_data,
            "flags":         flags,
            "rule_score":    rule_score,
            "timestamp":     time.time(),
        }

        if flags:
            claim = AgentClaim(
                agent_id     = self.agent_id,
                claim_type   = "THREAT",
                confidence   = rule_score,
                flags        = ["NETWORK_ANOMALY"],
                raw_evidence = {
                    "rpm":             rpm,
                    "failed_attempts": failed,
                    "unique_ips":      ips,
                    "data_mb":         data,
                    "request_count":   int(rpm),
                },
                llm_reason = f"Network anomaly flags: {flags}",
            )

            verified = self.verifier.verify(claim, self, ml_risk_score=rule_score)
            result["verified"]        = True
            result["consensus_score"] = verified.consensus_score
            result["action_level"]    = verified.action_level
            result["final_verdict"]   = verified.final_verdict

            if verified.final_verdict == "CONFIRMED_THREAT":
                self._network_detections.append(result)

                self.send_message("AGENT-ST-01", "THREAT", {
                    "event":          "NETWORK_ANOMALY_CONFIRMED",
                    "agent_id":       self.agent_id,
                    "flags":          flags,
                    "score":          rule_score,
                    "consensus_score": verified.consensus_score,
                    "action_level":   verified.action_level,
                    "timestamp":      time.time(),
                })

                log_threat(f"[ThreatDetection] NETWORK ANOMALY CONFIRMED | flags={flags}")

            elif verified.final_verdict == "FALSE_POSITIVE":
                self._false_positives += 1

            result["verdict"] = "ANOMALY" if verified.final_verdict == "CONFIRMED_THREAT" else "NORMAL"
        else:
            result["verdict"]       = "NORMAL"
            result["final_verdict"] = "NORMAL"

        return result

    # ── STATUS ────────────────────────────────────────────
    def get_status(self) -> dict:
        base = super().get_status()
        base.update({
            "phishing_detections": len(self._phishing_detections),
            "malware_detections":  len(self._malware_detections),
            "network_detections":  len(self._network_detections),
            "false_positives":     self._false_positives,
            "vector_store":        self.vector_store.get_status(),
            "cache_status":        self.fast_cache.get_status(),
            "malware_families":    list(MALWARE_SIGNATURES.keys()),
            "phishing_indicators": len(PHISHING_INDICATORS),
        })
        return base