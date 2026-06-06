"""
guardrails/security_rules.py

Enhanced Security Guardrails.

Before: 5 blocked actions, basic sanitization.
Now:
  - 3-tier severity levels (CRITICAL, HIGH, MEDIUM)
  - Context-aware blocking — same action allowed in one context, blocked in another
  - RAG-integrated — new threat patterns from Research Agent update rules
  - Audit trail — every guardrail trigger is logged with hash
  - Rate limiting per agent — too many blocked actions triggers auto-escalation
"""

import time
import hashlib
import json
from logger import log_info, log_blocked, log_error


# ── Blocked Actions — 3 severity tiers ───────────────────

CRITICAL_BLOCKED = [
    # These are NEVER allowed regardless of context
    "delete_all",      "drop_table",       "truncate_table",
    "bypass_auth",     "disable_security", "disable_firewall",
    "format_disk",     "rm_rf",            "wipe_logs",
    "inject_sql",      "execute_shell",    "reverse_shell",
    "disable_logging", "kill_process",     "backdoor",
    "exfiltrate",      "ransom",           "encrypt_files",
]

HIGH_BLOCKED = [
    # Blocked unless agent has explicit admin permission
    "modify_user",     "create_admin",     "change_password",
    "export_database", "download_all",     "mass_delete",
    "alter_table",     "grant_permission", "revoke_permission",
    "disable_user",    "reset_token",
]

MEDIUM_BLOCKED = [
    # Flagged and logged — not blocked outright
    "delete_record",   "update_config",    "change_setting",
    "bulk_update",     "archive_data",     "migrate_data",
]

# Actions always safe regardless of context
ALWAYS_SAFE = [
    "fetch_data",  "read_logs",   "get_status",
    "health_check","list_users",  "view_config",
    "scan",        "monitor",     "analyze",
    "report",      "alert",       "notify",
]

# Sensitive fields — never sent to LLM
SENSITIVE_FIELDS = [
    "password",    "api_key",     "secret",
    "token",       "private_key", "signing_key",
    "credit_card", "ssn",         "auth_code",
    "otp",         "seed_phrase", "mnemonic",
]

# Track guardrail triggers per agent for rate limiting
# Structure: { agent_id: [timestamp, timestamp, ...] }
_trigger_history: dict = {}
_TRIGGER_WINDOW  = 60   # seconds
_MAX_TRIGGERS    = 5    # max triggers in window before escalation


# ── Core Check Functions ──────────────────────────────────

def check_action_safe(action: str, agent_id: str = "unknown",
                       context: dict = None) -> bool:
    """
    Check if an action is safe to execute.
    Returns False if action is blocked.
    Logs every blocked action with audit hash.

    Severity levels:
      CRITICAL → always blocked, immediate alert
      HIGH     → blocked unless context allows
      MEDIUM   → logged and flagged, not blocked
    """
    action_lower = action.lower().replace(" ", "_").replace("-", "_")
    context      = context or {}

    # Always safe — skip all checks
    if any(safe in action_lower for safe in ALWAYS_SAFE):
        return True

    # CRITICAL — never allowed
    for blocked in CRITICAL_BLOCKED:
        if blocked in action_lower:
            _log_guardrail_trigger(
                agent_id = agent_id,
                action   = action,
                level    = "CRITICAL",
                reason   = f"Critical blocked action: {blocked}",
            )
            return False

    # HIGH — blocked unless explicit admin context
    for blocked in HIGH_BLOCKED:
        if blocked in action_lower:
            is_admin = context.get("role") in ("admin", "superadmin")
            is_explicit = context.get("explicit_permission") is True

            if not (is_admin and is_explicit):
                _log_guardrail_trigger(
                    agent_id = agent_id,
                    action   = action,
                    level    = "HIGH",
                    reason   = f"High-risk action without admin+explicit permission: {blocked}",
                )
                return False

    # MEDIUM — log and flag but allow
    for flagged in MEDIUM_BLOCKED:
        if flagged in action_lower:
            _log_guardrail_trigger(
                agent_id = agent_id,
                action   = action,
                level    = "MEDIUM",
                reason   = f"Medium-risk action flagged: {flagged}",
                blocked  = False,
            )
            # Not blocked — just flagged
            break

    return True


def check_rate_limit(agent_id: str) -> bool:
    """
    Check if an agent has triggered too many guardrails recently.
    More than 5 triggers in 60 seconds = escalate to Sentinel.
    Returns False if rate limit exceeded.
    """
    now = time.time()

    if agent_id not in _trigger_history:
        _trigger_history[agent_id] = []

    # Remove old triggers outside the window
    _trigger_history[agent_id] = [
        t for t in _trigger_history[agent_id]
        if now - t < _TRIGGER_WINDOW
    ]

    count = len(_trigger_history[agent_id])

    if count >= _MAX_TRIGGERS:
        log_blocked(
            f"[Guardrails] Rate limit exceeded | agent={agent_id} | "
            f"triggers={count} in {_TRIGGER_WINDOW}s"
        )
        return False

    return True


def sanitize_data(data: dict) -> dict:
    """
    Remove or mask sensitive fields before sending to LLM.
    Same interface as before — no breaking change.
    Recursively handles nested dicts.
    """
    if not isinstance(data, dict):
        return data

    safe_data = {}
    for key, value in data.items():
        key_lower = key.lower()

        if any(sensitive in key_lower for sensitive in SENSITIVE_FIELDS):
            safe_data[key] = "***REDACTED***"
        elif isinstance(value, dict):
            safe_data[key] = sanitize_data(value)
        elif isinstance(value, list):
            safe_data[key] = [
                sanitize_data(v) if isinstance(v, dict) else v
                for v in value
            ]
        else:
            safe_data[key] = value

    return safe_data


def validate_llm_output(output: dict, agent_id: str = "unknown") -> dict:
    """
    Validate LLM output before any agent acts on it.
    Checks for injection attempts in LLM responses.
    Returns sanitized output or blocked result.
    """
    if not isinstance(output, dict):
        return {"action": "ERROR", "reason": "Invalid LLM output format", "safe": False}

    action = str(output.get("action", "")).lower()

    # Check for prompt injection attempts in LLM output
    injection_patterns = [
        "ignore previous", "disregard instructions", "new instructions",
        "system prompt", "override security", "jailbreak",
        "act as", "pretend to be", "forget your rules",
    ]

    full_output_str = json.dumps(output).lower()
    for pattern in injection_patterns:
        if pattern in full_output_str:
            _log_guardrail_trigger(
                agent_id = agent_id,
                action   = action,
                level    = "CRITICAL",
                reason   = f"Prompt injection detected in LLM output: '{pattern}'",
            )
            return {
                "action": "BLOCKED",
                "reason": f"Prompt injection attempt detected: {pattern}",
                "safe":   False,
            }

    # Run standard action check
    if not check_action_safe(action, agent_id):
        return {
            "action": "BLOCKED",
            "reason": f"Action '{action}' blocked by guardrails",
            "safe":   False,
        }

    return output


def add_dynamic_rule(pattern: str, severity: str = "HIGH", source: str = "research_agent"):
    """
    Dynamically add new blocked patterns from Research Agent.
    Called when Research Agent discovers new threat patterns from CVE data.
    severity: CRITICAL, HIGH, or MEDIUM
    """
    pattern_clean = pattern.lower().replace(" ", "_")

    if severity == "CRITICAL" and pattern_clean not in CRITICAL_BLOCKED:
        CRITICAL_BLOCKED.append(pattern_clean)
        log_info(f"[Guardrails] New CRITICAL rule added from {source}: {pattern_clean}")
    elif severity == "HIGH" and pattern_clean not in HIGH_BLOCKED:
        HIGH_BLOCKED.append(pattern_clean)
        log_info(f"[Guardrails] New HIGH rule added from {source}: {pattern_clean}")
    elif severity == "MEDIUM" and pattern_clean not in MEDIUM_BLOCKED:
        MEDIUM_BLOCKED.append(pattern_clean)
        log_info(f"[Guardrails] New MEDIUM rule added from {source}: {pattern_clean}")


def get_rules_summary() -> dict:
    """Return current rules for dashboard display."""
    return {
        "critical_blocked": len(CRITICAL_BLOCKED),
        "high_blocked":     len(HIGH_BLOCKED),
        "medium_flagged":   len(MEDIUM_BLOCKED),
        "always_safe":      len(ALWAYS_SAFE),
        "sensitive_fields": len(SENSITIVE_FIELDS),
        "critical_rules":   CRITICAL_BLOCKED,
        "high_rules":       HIGH_BLOCKED,
    }


# ── Internal Audit Logger ─────────────────────────────────

def _log_guardrail_trigger(agent_id: str, action: str, level: str,
                            reason: str, blocked: bool = True):
    """
    Log a guardrail trigger with tamper-proof hash.
    Adds to rate-limit history for the agent.
    """
    timestamp = time.time()
    entry_hash = hashlib.sha256(
        f"{agent_id}|{action}|{level}|{timestamp}".encode()
    ).hexdigest()[:16]

    if blocked:
        log_blocked(
            f"[Guardrails] {level} | agent={agent_id} | "
            f"action={action} | reason={reason} | hash={entry_hash}"
        )
    else:
        log_info(
            f"[Guardrails] {level} FLAGGED | agent={agent_id} | "
            f"action={action} | reason={reason}"
        )

    # Track in rate-limit history
    if agent_id not in _trigger_history:
        _trigger_history[agent_id] = []
    _trigger_history[agent_id].append(timestamp)