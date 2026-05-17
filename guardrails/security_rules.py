"""
Guardrails - Prevents wrong decisions by the LLM
Security rules are defined here
"""

# These actions will never be allowed
BLOCKED_ACTIONS = [
    "delete_all",
    "drop_table",
    "bypass_auth",
    "disable_security",
    "hack"
]

# Sensitive data that will not be given to the LLM
SENSITIVE_FIELDS = [
    "password",
    "api_key",
    "secret",
    "token"
]

def check_action_safe(action: str) -> bool:
    """
    Checks whether the LLM's decision is safe or not
    """
    action_lower = action.lower()
    for blocked in BLOCKED_ACTIONS:
        if blocked in action_lower:
            print(f"🚫 GUARDRAIL: Blocked action detected → {action}")
            return False
    return True

def sanitize_data(data: dict) -> dict:
    """
    Remove sensitive fields before sending data to the LLM
    """
    safe_data = {}
    for key, value in data.items():
        if key.lower() not in SENSITIVE_FIELDS:
            safe_data[key] = value
        else:
            safe_data[key] = "***HIDDEN***"
    return safe_data