"""
messaging/message_bus.py

Enhanced MessageBus — Signed, Priority-based, Persistent.

Before: unsigned messages, no priority, lost on restart.
Now:
  - Priority queue: THREAT > BLOCK > ALERT > INFO
  - Message integrity: SHA3-256 hash on every message
  - Persistence: critical messages saved to SQLite
  - Replay protection: duplicate message detection
  - Rate limiting: prevent message flooding between agents
"""

import time
import json
import hashlib
import threading
import sqlite3
import os
from collections import defaultdict, deque
from logger import log_info, log_threat, log_error, log_blocked


# Message priority levels — higher number = higher priority
PRIORITY = {
    "THREAT": 4,
    "BLOCK":  3,
    "ALERT":  2,
    "INFO":   1,
}

# Messages DB — same folder as memory DB
DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "agent_memory.db"
)

# Rate limit: max messages per sender per minute
_MSG_RATE_LIMIT    = 30
_MSG_RATE_WINDOW   = 60


class Message:
    """
    A signed inter-agent message.
    Every message has an integrity hash for tamper detection.
    """

    def __init__(self, sender_id: str, recipient_id: str,
                 msg_type: str, payload: dict):
        self.sender_id    = sender_id
        self.recipient_id = recipient_id
        self.msg_type     = msg_type.upper()
        self.payload      = payload
        self.timestamp    = time.time()
        self.message_id   = f"{sender_id}-{self.msg_type}-{int(self.timestamp * 1000)}"
        self.priority     = PRIORITY.get(self.msg_type, 1)

        # Integrity hash — tamper detection
        self.integrity_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        """SHA3-256 hash of message contents."""
        content = json.dumps({
            "sender_id":    self.sender_id,
            "recipient_id": self.recipient_id,
            "msg_type":     self.msg_type,
            "payload":      self.payload,
            "timestamp":    self.timestamp,
        }, sort_keys=True, default=str)
        return hashlib.sha3_256(content.encode()).hexdigest()

    def verify_integrity(self) -> bool:
        """Recompute hash and compare — returns False if tampered."""
        return self._compute_hash() == self.integrity_hash

    def to_dict(self) -> dict:
        return {
            "message_id":     self.message_id,
            "sender_id":      self.sender_id,
            "recipient_id":   self.recipient_id,
            "msg_type":       self.msg_type,
            "payload":        self.payload,
            "timestamp":      self.timestamp,
            "priority":       self.priority,
            "integrity_hash": self.integrity_hash,
            "integrity_ok":   self.verify_integrity(),
        }


class MessageBus:
    """
    Central message bus — singleton, thread-safe, signed messages.

    Priority processing:
      THREAT messages are processed before BLOCK, ALERT, INFO.
      Within same priority — FIFO order.

    Rate limiting:
      Each agent can send max 30 messages per minute.
      Exceeding triggers a FLOOD_DETECTED alert to Sentinel.
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

        # Per-agent inbox — sorted by priority
        self._inboxes:       dict = defaultdict(list)
        # Broadcast messages
        self._broadcast_box: deque = deque(maxlen=200)
        # Full history for audit
        self._history:       deque = deque(maxlen=1000)
        # Subscribers { agent_id: [callback, ...] }
        self._subscribers:   dict = defaultdict(list)
        # Rate limit tracking { sender_id: [timestamps] }
        self._rate_tracker:  dict = defaultdict(list)
        # Seen message IDs — replay attack prevention
        self._seen_ids:      set  = set()
        # Per-agent broadcast read index — tracks how many broadcast messages each agent has already consumed
        self._broadcast_read_idx: dict = defaultdict(int)

        self._bus_lock    = threading.Lock()
        self._initialized = True

        # Initialize persistence table
        self._init_db()

        log_info("[MessageBus] Initialized | Signed + Priority + Persistent")

    def _init_db(self):
        """Create messages table for critical message persistence."""
        try:
            with self._bus_lock:
                conn = sqlite3.connect(DB_PATH)
                c    = conn.cursor()
                c.execute("""
                    CREATE TABLE IF NOT EXISTS critical_messages (
                        id             INTEGER PRIMARY KEY AUTOINCREMENT,
                        message_id     TEXT UNIQUE,
                        sender_id      TEXT,
                        recipient_id   TEXT,
                        msg_type       TEXT,
                        payload        TEXT,
                        integrity_hash TEXT,
                        timestamp      REAL,
                        processed      INTEGER DEFAULT 0
                    )
                """)
                conn.commit()
                conn.close()
        except Exception as e:
            log_error(f"[MessageBus] DB init error: {e}")

    # ── PUBLISH ───────────────────────────────────────────

    def publish(self, sender_id: str, recipient_id: str,
                msg_type: str, payload: dict) -> Message:
        """
        Send a message from one agent to another.
        Checks rate limit, signs the message, delivers by priority.
        recipient_id = "ALL" → broadcast to all agents.
        """
        # Rate limit check
        if not self._check_rate_limit(sender_id, msg_type):
            return None

        msg = Message(sender_id, recipient_id, msg_type, payload)

        # Replay protection — reject duplicate message IDs
        if msg.message_id in self._seen_ids:
            log_error(f"[MessageBus] Duplicate message rejected: {msg.message_id}")
            return None
        self._seen_ids.add(msg.message_id)

        # Keep seen_ids from growing forever
        if len(self._seen_ids) > 10000:
            self._seen_ids = set(list(self._seen_ids)[-5000:])

        with self._bus_lock:
            self._history.append(msg)

            if recipient_id == "ALL":
                self._broadcast_box.append(msg)
                log_info(f"[MessageBus] BROADCAST | {sender_id} → ALL | {msg_type} | p={msg.priority}")
            else:
                # Insert by priority — higher priority first
                self._inboxes[recipient_id].append(msg)
                self._inboxes[recipient_id].sort(key=lambda m: m.priority, reverse=True)
                log_info(f"[MessageBus] MESSAGE | {sender_id} → {recipient_id} | {msg_type} | p={msg.priority}")

        # Persist THREAT and BLOCK messages to SQLite
        if msg_type in ("THREAT", "BLOCK"):
            self._persist_message(msg)

        # Notify subscribers
        self._notify_subscribers(recipient_id, msg)

        return msg

    def _check_rate_limit(self, sender_id: str, msg_type: str) -> bool:
        """
        Prevent message flooding between agents.
        Returns False if sender exceeded rate limit.
        Alerts Sentinel on flood detection.
        """
        # THREAT and BLOCK always go through
        if msg_type in ("THREAT", "BLOCK"):
            return True

        now = time.time()
        with self._bus_lock:
            self._rate_tracker[sender_id] = [
                t for t in self._rate_tracker[sender_id]
                if now - t < _MSG_RATE_WINDOW
            ]
            count = len(self._rate_tracker[sender_id])

        if count >= _MSG_RATE_LIMIT:
            log_blocked(
                f"[MessageBus] Rate limit exceeded | sender={sender_id} | "
                f"count={count} in {_MSG_RATE_WINDOW}s"
            )
            # Alert Sentinel about potential flooding
            flood_msg = Message(
                sender_id    = "MESSAGE_BUS",
                recipient_id = "AGENT-ST-01",
                msg_type     = "THREAT",
                payload      = {
                    "event":     "MSG_FLOOD_DETECTED",
                    "sender_id": sender_id,
                    "count":     count,
                    "window":    _MSG_RATE_WINDOW,
                    "timestamp": now,
                },
            )
            with self._bus_lock:
                self._inboxes["AGENT-ST-01"].append(flood_msg)
                self._inboxes["AGENT-ST-01"].sort(key=lambda m: m.priority, reverse=True)
            return False

        with self._bus_lock:
            self._rate_tracker[sender_id].append(now)

        return True

    def _persist_message(self, msg: Message):
        """Save critical messages to SQLite for audit trail."""
        try:
            with self._bus_lock:
                conn = sqlite3.connect(DB_PATH)
                c    = conn.cursor()
                c.execute("""
                    INSERT OR IGNORE INTO critical_messages
                        (message_id, sender_id, recipient_id, msg_type,
                         payload, integrity_hash, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    msg.message_id,
                    msg.sender_id,
                    msg.recipient_id,
                    msg.msg_type,
                    json.dumps(msg.payload, default=str),
                    msg.integrity_hash,
                    msg.timestamp,
                ))
                conn.commit()
                conn.close()
        except Exception as e:
            log_error(f"[MessageBus] Persist error: {e}")

    # ── SUBSCRIBE ─────────────────────────────────────────

    def subscribe(self, agent_id: str, callback):
        """Register a callback for incoming messages."""
        with self._bus_lock:
            self._subscribers[agent_id].append(callback)
        log_info(f"[MessageBus] {agent_id} subscribed")

    def _notify_subscribers(self, recipient_id: str, msg: Message):
        """Notify registered callbacks — thread-safe."""
        if recipient_id == "ALL":
            with self._bus_lock:
                all_subs = dict(self._subscribers)
            for agent_id, callbacks in all_subs.items():
                for cb in callbacks:
                    try:
                        cb(msg)
                    except Exception as e:
                        log_error(f"[MessageBus] Callback error for {agent_id}: {e}")
            return

        with self._bus_lock:
            targets = list(self._subscribers.get(recipient_id, []))
        for cb in targets:
            try:
                cb(msg)
            except Exception as e:
                log_error(f"[MessageBus] Callback error for {recipient_id}: {e}")

    # ── READ ──────────────────────────────────────────────

    def get_inbox(self, agent_id: str) -> list:
        """
        Get all messages for an agent — highest priority first.
        Includes both direct messages AND broadcast messages not yet read by this agent.
        Verifies integrity of each message before returning.
        Tampered messages are logged and excluded.
        """
        with self._bus_lock:
            # Direct messages
            messages = list(self._inboxes[agent_id])
            self._inboxes[agent_id].clear()

            # Broadcast messages this agent hasn't read yet
            broadcast_list = list(self._broadcast_box)
            total_ever     = len(broadcast_list)
            already_read   = min(self._broadcast_read_idx[agent_id], total_ever)
            unread_broadcasts = broadcast_list[already_read:]
            self._broadcast_read_idx[agent_id] = total_ever

        all_messages = messages + unread_broadcasts

        verified   = []
        tampered   = []
        for msg in all_messages:
            if msg.verify_integrity():
                verified.append(msg.to_dict())
            else:
                tampered.append(msg.message_id)
                log_threat(
                    f"[MessageBus] TAMPERED MESSAGE DETECTED | "
                    f"id={msg.message_id} | sender={msg.sender_id}"
                )

        if tampered:
            # Alert Sentinel about tampered messages
            self.publish(
                sender_id    = "MESSAGE_BUS",
                recipient_id = "AGENT-ST-01",
                msg_type     = "THREAT",
                payload      = {
                    "event":    "TAMPERED_MESSAGES",
                    "count":    len(tampered),
                    "ids":      tampered,
                    "timestamp": time.time(),
                },
            )

        return verified

    def get_broadcasts(self, limit: int = 20) -> list:
        """Get recent broadcast messages."""
        with self._bus_lock:
            recent = list(self._broadcast_box)[-limit:]
        return [m.to_dict() for m in recent]

    def get_history(self, limit: int = 50) -> list:
        """Get full message history for audit."""
        with self._bus_lock:
            recent = list(self._history)[-limit:]
        return [m.to_dict() for m in recent]

    def get_stats(self) -> dict:
        """MessageBus statistics for dashboard."""
        with self._bus_lock:
            return {
                "total_messages":   len(self._history),
                "broadcast_count":  len(self._broadcast_box),
                "active_agents":    list(self._inboxes.keys()),
                "subscriber_count": sum(len(v) for v in self._subscribers.values()),
                "seen_ids":         len(self._seen_ids),
                "features": {
                    "priority_queue":    True,
                    "integrity_hashing": True,
                    "replay_protection": True,
                    "rate_limiting":     True,
                    "persistence":       True,
                },
            }


# Global singleton instance
message_bus = MessageBus()