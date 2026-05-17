"""
Agent Memory
Each agent remembers its own history
"""
import time
from collections import deque

class AgentMemory:
    def __init__(self, agent_id: str, max_size: int = 50):
        self.agent_id = agent_id
        self.history = deque(maxlen=max_size)
        self.failed_attempts = 0

    def add(self, action: str, result: str, success: bool):
        """Remember a new action"""
        self.history.append({
            "action": action,
            "result": result,
            "success": success,
            "timestamp": time.time()
        })
        if not success:
            self.failed_attempts += 1

    def get_context(self) -> str:
        """Provide context of the last 5 actions for the LLM"""
        recent = list(self.history)[-5:]
        if not recent:
            return "No previous actions."
        lines = []
        for h in recent:
            status = "SUCCESS" if h["success"] else "FAILED"
            lines.append(f"- {h['action']} → {status}")
        return "\n".join(lines)

    def is_suspicious(self) -> bool:
        """More than 3 failures — suspicious!"""
        return self.failed_attempts >= 3