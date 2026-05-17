"""
MessageBus — Central Agent Communication System
one agnet can send msg to another agent from here
"""
import time
import threading
from collections import defaultdict, deque
from logger import log_info, log_threat, log_error


class Message:
    """Ek message ka structure"""
    def __init__(self, sender_id: str, recipient_id: str, msg_type: str, payload: dict):
        self.sender_id    = sender_id
        self.recipient_id = recipient_id   # "ALL" = broadcast sab ko
        self.msg_type     = msg_type       # "ALERT", "BLOCK", "INFO", "THREAT"
        self.payload      = payload
        self.timestamp    = time.time()
        self.message_id   = f"{sender_id}-{int(self.timestamp)}"

    def to_dict(self) -> dict:
        return {
            "message_id":   self.message_id,
            "sender_id":    self.sender_id,
            "recipient_id": self.recipient_id,
            "msg_type":     self.msg_type,
            "payload":      self.payload,
            "timestamp":    self.timestamp
        }


class MessageBus:
    """
    Central message system — singleton pattern.
    Sab agents yahi se message lete aur bhejte hain.
    """
    _instance = None
    _lock     = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        # Agent ke inbox — har agent ke messages yahan store hote hain
        self._inboxes: dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        # Broadcast messages — "ALL" ke liye
        self._broadcast_box: deque = deque(maxlen=200)
        # Message history — sab messages ka record
        self._history: deque = deque(maxlen=500)
        # Subscribers — agent ID → callback function
        self._subscribers: dict[str, list] = defaultdict(list)
        self._bus_lock    = threading.Lock()
        self._initialized = True
        log_info("[MessageBus] Initialized — Agent communication ready")

    # ──────────────────────────────────────────────────────
    # PUBLISH — Message bhejo
    # ──────────────────────────────────────────────────────
    def publish(self, sender_id: str, recipient_id: str,
                msg_type: str, payload: dict) -> Message:
        """
        any agent can send msg from this
        recipient_id = "ALL" →  agents broadcasts
        """
        msg = Message(sender_id, recipient_id, msg_type, payload)

        with self._bus_lock:
            self._history.append(msg)

            if recipient_id == "ALL":
                self._broadcast_box.append(msg)
                log_info(f"[MessageBus] BROADCAST | {sender_id} → ALL | {msg_type}")
            else:
                self._inboxes[recipient_id].append(msg)
                log_info(f"[MessageBus] MESSAGE | {sender_id} → {recipient_id} | {msg_type}")

        # Callback subscribers ko notify karo
        self._notify_subscribers(recipient_id, msg)

        return msg

    # ──────────────────────────────────────────────────────
    # SUBSCRIBE — Message receive karne ke liye register karo
    # ──────────────────────────────────────────────────────
    def subscribe(self, agent_id: str, callback):
        """
        Agent register one callback
        
        """
        with self._bus_lock:
            self._subscribers[agent_id].append(callback)
        log_info(f"[MessageBus] {agent_id} subscribed for messages")

    def _notify_subscribers(self, recipient_id: str, msg: Message):
        """Subscribers ko notify karo — thread-safe"""
        targets = list(self._subscribers.get(recipient_id, []))
        if recipient_id == "ALL":
            # Sab subscribers ko notify karo
            for agent_id, callbacks in self._subscribers.items():
                for cb in callbacks:
                    try:
                        cb(msg)
                    except Exception as e:
                        log_error(f"[MessageBus] Callback error for {agent_id}: {e}")
            return

        for cb in targets:
            try:
                cb(msg)
            except Exception as e:
                log_error(f"[MessageBus] Callback error for {recipient_id}: {e}")

    # ──────────────────────────────────────────────────────
    # READ — Messages parho
    # ──────────────────────────────────────────────────────
    def get_inbox(self, agent_id: str) -> list:
        """Agent inbox —  messages"""
        with self._bus_lock:
            messages = list(self._inboxes[agent_id])
            self._inboxes[agent_id].clear()   # Parh liye, clear karo
        return [m.to_dict() for m in messages]

    def get_broadcasts(self, limit: int = 20) -> list:
        """all broadcast messages"""
        with self._bus_lock:
            recent = list(self._broadcast_box)[-limit:]
        return [m.to_dict() for m in recent]

    def get_history(self, limit: int = 50) -> list:
        """ message history"""
        with self._bus_lock:
            recent = list(self._history)[-limit:]
        return [m.to_dict() for m in recent]

    def get_stats(self) -> dict:
        """MessageBus stats"""
        with self._bus_lock:
            return {
                "total_messages":    len(self._history),
                "broadcast_count":   len(self._broadcast_box),
                "active_agents":     list(self._inboxes.keys()),
                "subscriber_count":  sum(len(v) for v in self._subscribers.values()),
            }


# Global instance — ek hi MessageBus poore system mein
message_bus = MessageBus()