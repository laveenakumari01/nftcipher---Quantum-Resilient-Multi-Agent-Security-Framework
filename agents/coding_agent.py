"""
agents/coding_agent.py

Coding Agent — AGENT-CD-01

Responsibilities:
  - Auto-generate firewall rules when a threat is confirmed
  - Write Python incident response scripts
  - Generate patch suggestions for detected vulnerabilities
  - Validate all generated code for safety before returning it
  - Run autonomously — receives threats from MessageBus and acts immediately

Security rules this agent enforces:
  - Never generate offensive or destructive code
  - All generated rules go through a safety checker before returning
  - Sandbox flag is always set — execution is never triggered by this agent
  - Agent generates, Arbiter decides whether to apply
"""

import time
import json
import hashlib
from agents.base_agent import BaseAgent
from rag.vectorless_store import VectorlessStore
from logger import log_info, log_error, log_allowed, log_blocked, log_threat


CODING_PROMPT = """You are a Security Coding Agent for NFTCipher.

Your ONLY job is to generate DEFENSIVE security code.
You generate: firewall rules, incident response scripts, patch suggestions, detection rules.
You NEVER generate: offensive exploits, reverse shells, data destruction commands, privilege escalation tools.

Every piece of code you generate must:
  1. Include a comment explaining what it does
  2. Include a revert/undo command
  3. Be scoped to the minimum necessary permissions

Respond with JSON only."""


class CodingAgent(BaseAgent):

    # Commands that must never appear in generated code
    BLOCKED_PATTERNS = [
        "rm -rf", "dd if=", ":(){:|:&};:",   # destructive
        "chmod 777", "chmod -R 777",           # over-permissive
        "iptables -F", "iptables --flush",     # flush all rules
        "/dev/null > /etc/",                   # config destruction
        "base64 -d |", "curl | bash",          # remote code execution
        "nc -e", "ncat -e", "bash -i",         # reverse shells
        "DROP TABLE", "DELETE FROM",           # database destruction
    ]

    def __init__(self):
        super().__init__(
            agent_id      = "AGENT-CD-01",
            role          = "Coding",
            system_prompt = CODING_PROMPT,
        )

        # Store all generated scripts with metadata
        self._generated_scripts: list = []

        # Fast store for active firewall rules — so we can track and revert
        self.fast_cache = VectorlessStore()

        # Subscribe to threat messages from other agents
        # When Sentinel confirms a threat, Coding Agent generates response automatically
        self._pending_threats: list = []

        log_info("[Coding] Agent ready — waiting for threat events")

    # ── BACKGROUND CYCLE ──────────────────────────────────
    def run_cycle(self):
        """
        Runs every 30 seconds.
        Checks for pending threat messages and generates responses automatically.
        Also reports generation statistics to dashboard.
        """
        log_info("[Coding] Background cycle — checking pending threats")

        # Process any pending threats from inbox
        # Note: check_inbox() returns list of dicts (from MessageBus.get_inbox)
        inbox = self.check_inbox()
        for msg in inbox:
            # Support both dict (from MessageBus) and Message object
            if isinstance(msg, dict):
                msg_type = msg.get("msg_type", "")
                payload  = msg.get("payload", {})
            else:
                msg_type = getattr(msg, "msg_type", "")
                payload  = getattr(msg, "payload", {})

            # Trigger on AUTO_BLOCK, ALERT, or any VERIFIED_THREAT event
            # Previously only AUTO_BLOCK triggered rule generation — this caused
            # rules to never appear because most threats score below 0.80 (AUTO_BLOCK
            # threshold) but still need a firewall response at ALERT level (>= 0.50)
            if msg_type == "THREAT":
                action_level = payload.get("action_level", "")
                flags        = payload.get("flags", [])
                event        = payload.get("event", "")
                should_respond = (
                    action_level in ("AUTO_BLOCK", "ALERT")
                    or event == "VERIFIED_THREAT"
                    or (flags and action_level not in ("WATCHLIST", "IGNORE", ""))
                )
                if should_respond:
                    self._auto_respond_to_threat(payload)

        self.broadcast("INFO", {
            "event":              "CODING_CYCLE",
            "agent_id":           self.agent_id,
            "scripts_generated":  len(self._generated_scripts),
            "pending_threats":    len(self._pending_threats),
            "timestamp":          time.time(),
        })

    def _auto_respond_to_threat(self, threat_payload: dict):
        """
        Called automatically when a confirmed threat arrives.
        Generates a firewall rule without waiting for manual instruction.
        This is what makes the agent truly autonomous.
        """
        agent_id    = threat_payload.get("agent_id", "unknown")
        flags       = threat_payload.get("flags", [])
        score       = threat_payload.get("consensus_score", 0.0)

        log_info(f"[Coding] Auto-responding to threat from [{agent_id}] | score={score:.2f}")

        # Derive IP — use payload ip if present, else generate a deterministic
        # synthetic IP from agent_id hash (Sentinel doesn't always include raw IP)
        raw_ip = threat_payload.get("ip") or threat_payload.get("source_ip")
        if not raw_ip or raw_ip == "0.0.0.0/32":
            raw_ip = f"10.0.0.{abs(hash(agent_id)) % 254 + 1}/32"

        # Generate firewall rule for the threatening agent
        rule = self.generate_firewall_rule({
            "ip":          raw_ip,
            "attack_type": flags[0] if flags else "UNKNOWN",
            "agent_id":    agent_id,
            "score":       score,
        })

        # Generate incident response script
        script = self.generate_incident_response({
            "type":      "AUTO_RESPONSE",
            "agent_id":  agent_id,
            "flags":     flags,
            "score":     score,
        })

        # Broadcast that auto-response was generated
        self.broadcast("INFO", {
            "event":         "AUTO_RESPONSE_GENERATED",
            "agent_id":      self.agent_id,
            "threat_source": agent_id,
            "rule_generated": rule.get("rule", ""),
            "timestamp":     time.time(),
        })

    # ── SAFETY CHECKER ────────────────────────────────────
    def _is_code_safe(self, code: str) -> tuple[bool, str]:
        """
        Check generated code against blocked patterns.
        Returns (is_safe: bool, reason: str).
        This runs before any generated code is returned to the caller.
        """
        code_lower = code.lower()
        for pattern in self.BLOCKED_PATTERNS:
            if pattern.lower() in code_lower:
                return False, f"Blocked pattern detected: '{pattern}'"
        return True, "OK"

    # ── FIREWALL RULE GENERATION ──────────────────────────
    def generate_firewall_rule(self, threat_info: dict) -> dict:
        """
        Generate an iptables firewall rule for a detected threat.
        Always includes: the rule itself, an explanation, and a revert command.
        Never executes the rule — only generates and stores it.

        threat_info fields:
          ip          : target IP to block
          attack_type : type of attack detected
          agent_id    : which agent triggered this
          port        : optional specific port to block
        """
        ip          = threat_info.get("ip", "0.0.0.0")
        attack_type = threat_info.get("attack_type", "UNKNOWN")
        port        = threat_info.get("port", "")
        agent_id    = threat_info.get("agent_id", "unknown")
        score       = threat_info.get("score", 0.0)

        log_info(f"[Coding] Generating firewall rule | ip={ip} | attack={attack_type}")

        prompt = f"""Generate a Linux iptables firewall rule to block this security threat.

Threat details:
  - Source IP: {ip}
  - Attack type: {attack_type}
  - Detected by agent: {agent_id}
  - Threat score: {score:.2f}
  - Port (if relevant): {port if port else 'any'}

Requirements:
  - Rule must be as specific as possible (avoid blocking broad ranges)
  - Must include a comment with timestamp and reason
  - Must include exact revert command

Respond with JSON only:
{{
  "rule":         "complete iptables command with -m comment",
  "revert":       "exact iptables -D command to undo",
  "explanation":  "one sentence what this rule does",
  "scope":        "specific or broad",
  "safe":         true
}}"""

        response = self._call_llm(prompt)
        rule_id  = hashlib.sha256(f"{ip}{attack_type}{time.time()}".encode()).hexdigest()[:12]

        if response:
            try:
                raw = response.replace("```json", "").replace("```", "").strip()
                if "{" in raw:
                    raw = raw[raw.index("{") : raw.rindex("}") + 1]
                parsed = json.loads(raw)

                rule_text = parsed.get("rule", "")

                # Safety check before returning
                safe, reason = self._is_code_safe(rule_text)
                if not safe:
                    log_blocked(f"[Coding] Unsafe rule blocked: {reason}")
                    return {
                        "error":   f"Generated rule failed safety check: {reason}",
                        "blocked": True,
                        "rule_id": rule_id,
                    }

                script = {
                    "rule_id":      rule_id,
                    "type":         "firewall_rule",
                    "rule":         rule_text,
                    "revert":       parsed.get("revert", ""),
                    "explanation":  parsed.get("explanation", ""),
                    "scope":        parsed.get("scope", "unknown"),
                    "threat":       threat_info,
                    "generated_at": time.time(),
                    "applied":      False,  # agent never applies — Arbiter decides
                    "safe_checked": True,
                }

                self._generated_scripts.append(script)

                # Store in fast cache so Arbiter can retrieve and apply it
                self.fast_cache.set(
                    key         = f"rule:firewall:{rule_id}",
                    value       = script,
                    ttl_seconds = 3600,
                )

                log_allowed(f"[Coding] Firewall rule generated | id={rule_id} | ip={ip}")
                return script

            except Exception as e:
                log_error(f"[Coding] LLM parse error: {e}")

        # Fallback — generate a basic rule without LLM
        fallback_rule = (
            f"iptables -I INPUT -s {ip} -j DROP "
            f"-m comment --comment 'NFTCipher-{attack_type}-{int(time.time())}'"
        )

        safe, reason = self._is_code_safe(fallback_rule)
        if not safe:
            return {"error": reason, "blocked": True, "rule_id": rule_id}

        script = {
            "rule_id":      rule_id,
            "type":         "firewall_rule",
            "rule":         fallback_rule,
            "revert":       f"iptables -D INPUT -s {ip} -j DROP",
            "explanation":  f"Block all traffic from {ip} — detected as {attack_type}",
            "threat":       threat_info,
            "generated_at": time.time(),
            "applied":      False,
            "fallback":     True,
            "safe_checked": True,
        }

        self._generated_scripts.append(script)
        self.fast_cache.set(f"rule:firewall:{rule_id}", script, ttl_seconds=3600)

        log_allowed(f"[Coding] Fallback firewall rule generated | id={rule_id}")
        return script

    # ── INCIDENT RESPONSE SCRIPT ──────────────────────────
    def generate_incident_response(self, incident: dict) -> dict:
        """
        Generate a Python incident response script for a security event.
        Script collects evidence, logs the incident, and notifies admins.
        Agent never executes the script — it only generates it.

        incident fields:
          type      : incident type (AUTO_RESPONSE, BRUTE_FORCE, etc.)
          agent_id  : which agent detected it
          flags     : list of triggered security flags
          score     : threat consensus score
        """
        incident_type = incident.get("type", "UNKNOWN")
        agent_id      = incident.get("agent_id", "unknown")
        flags         = incident.get("flags", [])
        score         = incident.get("score", 0.0)

        log_info(f"[Coding] Generating incident response | type={incident_type} | agent={agent_id}")

        prompt = f"""Write a Python incident response script for this security incident.

Incident details:
  - Type:     {incident_type}
  - Agent:    {agent_id}
  - Flags:    {flags}
  - Score:    {score:.2f}

Script must:
  1. Log the full incident with timestamp to a file
  2. Collect system evidence (connections, processes, logs)
  3. Send an alert notification
  4. NOT modify any system state — read-only evidence collection only

Respond with JSON only:
{{
  "script":      "complete Python code as a string",
  "actions":     ["step1", "step2", "step3"],
  "read_only":   true,
  "safe":        true,
  "description": "one sentence summary"
}}"""

        response  = self._call_llm(prompt)
        script_id = hashlib.sha256(f"{incident_type}{agent_id}{time.time()}".encode()).hexdigest()[:12]

        result = {
            "script_id":    script_id,
            "type":         "incident_response",
            "incident":     incident,
            "generated_at": time.time(),
            "applied":      False,
        }

        if response:
            try:
                raw = response.replace("```json", "").replace("```", "").strip()
                if "{" in raw:
                    raw = raw[raw.index("{") : raw.rindex("}") + 1]
                parsed = json.loads(raw)

                script_code = parsed.get("script", "")

                # Safety check
                safe, reason = self._is_code_safe(script_code)
                if not safe:
                    log_blocked(f"[Coding] Unsafe script blocked: {reason}")
                    result["error"]   = f"Script failed safety check: {reason}"
                    result["blocked"] = True
                    return result

                result.update({
                    "script":      script_code,
                    "actions":     parsed.get("actions", []),
                    "description": parsed.get("description", ""),
                    "read_only":   parsed.get("read_only", True),
                    "safe_checked": True,
                })

            except Exception as e:
                log_error(f"[Coding] Incident response parse error: {e}")
                result["script"] = self._fallback_ir_script(incident)
                result["fallback"] = True
        else:
            result["script"]   = self._fallback_ir_script(incident)
            result["fallback"] = True

        self._generated_scripts.append(result)
        self.fast_cache.set(f"script:ir:{script_id}", result, ttl_seconds=3600)

        log_allowed(f"[Coding] Incident response generated | id={script_id}")
        return result

    def _fallback_ir_script(self, incident: dict) -> str:
        """
        Minimal Python incident response script when LLM is unavailable.
        Read-only — only collects and logs, never modifies.
        """
        return f'''"""
NFTCipher Incident Response Script
Generated: {time.strftime("%Y-%m-%d %H:%M:%S")}
Incident:  {incident.get("type", "UNKNOWN")}
Agent:     {incident.get("agent_id", "unknown")}
Flags:     {incident.get("flags", [])}
Score:     {incident.get("score", 0.0)}
"""
import subprocess
import datetime
import json

LOG_FILE = "incident_{int(time.time())}.log"

def collect_evidence():
    evidence = {{
        "timestamp":   str(datetime.datetime.utcnow()),
        "incident":    {json.dumps(incident)},
        "connections": None,
        "processes":   None,
    }}
    try:
        # Read-only system information collection
        evidence["connections"] = subprocess.check_output(
            ["netstat", "-an"], timeout=5
        ).decode(errors="ignore")
        evidence["processes"] = subprocess.check_output(
            ["ps", "aux"], timeout=5
        ).decode(errors="ignore")
    except Exception as e:
        evidence["collection_error"] = str(e)

    with open(LOG_FILE, "w") as f:
        json.dump(evidence, f, indent=2)

    print(f"Evidence collected and saved to {{LOG_FILE}}")
    return evidence

if __name__ == "__main__":
    collect_evidence()
'''

    # ── PATCH SUGGESTION ──────────────────────────────────
    def generate_patch_suggestion(self, cve_id: str, affected_component: str) -> dict:
        """
        Generate a patch suggestion for a known CVE.
        Returns recommended remediation steps — does not apply any changes.
        """
        log_info(f"[Coding] Generating patch suggestion | CVE={cve_id} | component={affected_component}")

        prompt = f"""Generate a security patch suggestion for:
CVE ID: {cve_id}
Affected component: {affected_component}

Provide remediation steps that are:
  - Specific and actionable
  - Ordered by priority
  - Safe to implement in production

Respond with JSON only:
{{
  "cve_id":           "{cve_id}",
  "severity":         "CRITICAL/HIGH/MEDIUM/LOW",
  "steps":            ["step1", "step2", "step3"],
  "commands":         ["safe shell command 1", "safe shell command 2"],
  "revert_steps":     ["how to undo if needed"],
  "estimated_effort": "minutes/hours/days",
  "safe":             true
}}"""

        response = self._call_llm(prompt)

        if response:
            try:
                raw = response.replace("```json", "").replace("```", "").strip()
                if "{" in raw:
                    raw = raw[raw.index("{") : raw.rindex("}") + 1]
                parsed = json.loads(raw)

                # Safety check all commands
                for cmd in parsed.get("commands", []):
                    safe, reason = self._is_code_safe(cmd)
                    if not safe:
                        parsed["commands"] = []
                        parsed["safety_warning"] = f"Commands removed: {reason}"
                        break

                parsed["generated_at"] = time.time()
                self._generated_scripts.append(parsed)
                log_allowed(f"[Coding] Patch suggestion generated | CVE={cve_id}")
                return parsed

            except Exception as e:
                log_error(f"[Coding] Patch suggestion parse error: {e}")

        return {
            "cve_id":           cve_id,
            "steps":            [f"Review {cve_id} advisory", "Apply vendor patch", "Verify fix"],
            "generated_at":     time.time(),
            "fallback":         True,
        }


    def handle_query(self, question: str, context: dict = None) -> dict:
        """
        Handle a direct question from another agent via ask_agent().

        Called by Suggestion Engine (through Sentinel's ask_agent()) when
        Research Agent has identified a CVE and patch steps are needed.
        Routes to generate_patch_suggestion() with CVE ID and component
        extracted from context (or parsed from the question text).

        Args:
            question : natural language question, should mention CVE ID
            context  : dict may include — cve_id, affected_component, thread_id

        Returns:
            dict — generate_patch_suggestion() result: steps, commands,
                   revert_steps, estimated_effort
        """
        import re
        context = context or {}
        log_info(
            f"[Coding] handle_query() | "
            f"thread={context.get('thread_id', '?')} | from=SuggestionEngine"
        )

        # Prefer cve_id from context — Research Agent already identified it
        # Fall back to regex parsing from the question text
        cve_id = context.get("cve_id", "")
        if not cve_id:
            cve_match = re.search(r"CVE-\d{4}-\d+", question, re.IGNORECASE)
            cve_id    = cve_match.group(0) if cve_match else "UNKNOWN-CVE"

        # affected_component: prefer context value, else use agent_id or default
        affected_component = (
            context.get("affected_component")
            or context.get("agent_id")
            or "NFTCipher System"
        )

        log_info(f"[Coding] handle_query() | CVE={cve_id} | component={affected_component}")

        # generate_patch_suggestion() calls LLM to produce remediation steps
        result = self.generate_patch_suggestion(cve_id, affected_component)

        log_info(
            f"[Coding] handle_query() answered | "
            f"steps={len(result.get('steps', []))} | "
            f"commands={len(result.get('commands', []))}"
        )
        return result

    # ── STATUS ────────────────────────────────────────────
    def get_status(self) -> dict:
        base = super().get_status()

        firewall_rules = [s for s in self._generated_scripts if s.get("type") == "firewall_rule"]
        ir_scripts     = [s for s in self._generated_scripts if s.get("type") == "incident_response"]

        base.update({
            "scripts_generated": len(self._generated_scripts),
            "firewall_rules":    len(firewall_rules),
            "ir_scripts":        len(ir_scripts),
            "safe_checked":      all(s.get("safe_checked", False) for s in self._generated_scripts),
            "cache_status":      self.fast_cache.get_status(),
        })
        return base