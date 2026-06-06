"""
rag/vectorless_store.py

Vectorless fast cache using Redis.
Used alongside VectorStore — different purpose, different speed.

VectorStore (ChromaDB):
  - Semantic similarity search
  - Stores full documents
  - Slightly slower (vector math needed)
  - Best for: "find CVEs similar to this attack pattern"

VectorlessStore (Redis):
  - Exact key lookup, pattern matching
  - Sub-millisecond response
  - Best for: IP blacklists, known phishing domains, active threat rules
  - Also stores: agent state, session data, real-time counters

If Redis is not running, falls back to in-memory dict.
Install: pip install redis
Start:   redis-server (Linux) or download from redis.io (Windows)
"""

import time
import json
from logger import log_info, log_error
from config.settings import REDIS_HOST, REDIS_PORT, REDIS_PASSWORD, REDIS_DB, REDIS_ENABLED

# Try to connect to Redis
_REDIS_AVAILABLE = False
_redis_client    = None

if REDIS_ENABLED:
    try:
        import redis
        _redis_client = redis.Redis(
            host     = REDIS_HOST,
            port     = REDIS_PORT,
            password = REDIS_PASSWORD or None,
            db       = REDIS_DB,
            decode_responses = True,
        )
        # Test connection
        _redis_client.ping()
        _REDIS_AVAILABLE = True
        log_info(f"[VectorlessStore] Redis connected | {REDIS_HOST}:{REDIS_PORT}")
    except Exception as e:
        log_error(f"[VectorlessStore] Redis not available: {e} — using in-memory fallback")


class VectorlessStore:
    """
    Fast key-value store for real-time threat data.

    Namespace convention (use these prefixes for organization):
      blacklist:ip:{ip}          — blocked IP addresses
      blacklist:domain:{domain}  — known phishing/malicious domains
      threat:active:{id}         — currently active threats
      agent:state:{agent_id}     — agent runtime state
      counter:{agent_id}:{type}  — request counters
      rule:{rule_id}             — active security rules

    All keys support TTL (time-to-live) for automatic expiry.
    """

    def __init__(self):
        self._memory: dict  = {}   # fallback in-memory store
        self._expiry: dict  = {}   # TTL tracking for in-memory mode
        self._mode          = "redis" if _REDIS_AVAILABLE else "memory"
        log_info(f"[VectorlessStore] Initialized | mode={self._mode}")

    # ── Core Operations ───────────────────────────────────

    def set(self, key: str, value, ttl_seconds: int = None) -> bool:
        """
        Store a value. Optionally set TTL for automatic expiry.
        value can be str, dict, list, int, float — auto-serialized.
        """
        serialized = json.dumps(value) if not isinstance(value, str) else value

        if _REDIS_AVAILABLE:
            try:
                if ttl_seconds:
                    _redis_client.setex(key, ttl_seconds, serialized)
                else:
                    _redis_client.set(key, serialized)
                return True
            except Exception as e:
                log_error(f"[VectorlessStore] set error: {e}")

        # In-memory fallback
        self._memory[key] = serialized
        if ttl_seconds:
            self._expiry[key] = time.time() + ttl_seconds
        return True

    def get(self, key: str):
        """
        Retrieve a value by key.
        Returns None if key does not exist or has expired.
        """
        if _REDIS_AVAILABLE:
            try:
                val = _redis_client.get(key)
                if val is None:
                    return None
                try:
                    return json.loads(val)
                except Exception:
                    return val
            except Exception as e:
                log_error(f"[VectorlessStore] get error: {e}")

        # In-memory fallback with TTL check
        if key not in self._memory:
            return None
        if key in self._expiry and time.time() > self._expiry[key]:
            del self._memory[key]
            del self._expiry[key]
            return None
        try:
            return json.loads(self._memory[key])
        except Exception:
            return self._memory[key]

    def delete(self, key: str) -> bool:
        """Remove a key from the store."""
        if _REDIS_AVAILABLE:
            try:
                _redis_client.delete(key)
                return True
            except Exception as e:
                log_error(f"[VectorlessStore] delete error: {e}")

        self._memory.pop(key, None)
        self._expiry.pop(key, None)
        return True

    def exists(self, key: str) -> bool:
        """Check if a key exists without retrieving its value."""
        if _REDIS_AVAILABLE:
            try:
                return bool(_redis_client.exists(key))
            except Exception:
                pass
        return key in self._memory

    def keys_with_prefix(self, prefix: str) -> list:
        """Get all keys matching a prefix — useful for namespace queries."""
        if _REDIS_AVAILABLE:
            try:
                return [k for k in _redis_client.scan_iter(f"{prefix}*")]
            except Exception as e:
                log_error(f"[VectorlessStore] keys_with_prefix error: {e}")

        return [k for k in self._memory.keys() if k.startswith(prefix)]

    def increment(self, key: str, amount: int = 1) -> int:
        """
        Atomic counter increment — useful for request counting.
        Returns new value after increment.
        """
        if _REDIS_AVAILABLE:
            try:
                return _redis_client.incrby(key, amount)
            except Exception as e:
                log_error(f"[VectorlessStore] increment error: {e}")

        current = int(self._memory.get(key, "0"))
        new_val = current + amount
        self._memory[key] = str(new_val)
        return new_val

    # ── Security-Specific Operations ──────────────────────

    def blacklist_ip(self, ip: str, reason: str = "", ttl_hours: int = 24):
        """Add an IP to the blacklist. Auto-expires after ttl_hours."""
        key = f"blacklist:ip:{ip}"
        self.set(key, {"ip": ip, "reason": reason, "added_at": time.time()},
                 ttl_seconds=ttl_hours * 3600)
        log_info(f"[VectorlessStore] IP blacklisted: {ip} | reason={reason} | ttl={ttl_hours}h")

    def is_blacklisted_ip(self, ip: str) -> bool:
        """Check if an IP is currently blacklisted."""
        return self.exists(f"blacklist:ip:{ip}")

    def blacklist_domain(self, domain: str, reason: str = "", ttl_hours: int = 48):
        """Add a domain to the phishing/malicious domain blacklist."""
        key = f"blacklist:domain:{domain.lower()}"
        self.set(key, {"domain": domain, "reason": reason, "added_at": time.time()},
                 ttl_seconds=ttl_hours * 3600)
        log_info(f"[VectorlessStore] Domain blacklisted: {domain}")

    def is_blacklisted_domain(self, domain: str) -> bool:
        """Check if a domain is in the blacklist."""
        return self.exists(f"blacklist:domain:{domain.lower()}")

    def set_active_threat(self, threat_id: str, threat_data: dict, ttl_minutes: int = 60):
        """Register an active threat — auto-expires after ttl_minutes."""
        key = f"threat:active:{threat_id}"
        self.set(key, threat_data, ttl_seconds=ttl_minutes * 60)

    def get_active_threats(self) -> list:
        """Get all currently active threats."""
        keys   = self.keys_with_prefix("threat:active:")
        result = []
        for key in keys:
            val = self.get(key)
            if val:
                result.append(val)
        return result

    def increment_request_count(self, agent_id: str) -> int:
        """Track request count per agent — used for rate limiting."""
        key = f"counter:{agent_id}:requests"
        return self.increment(key)

    def get_request_count(self, agent_id: str) -> int:
        """Get current request count for an agent."""
        return self.get(f"counter:{agent_id}:requests") or 0

    def reset_request_count(self, agent_id: str):
        """Reset request counter for an agent."""
        self.delete(f"counter:{agent_id}:requests")

    def store_agent_state(self, agent_id: str, state: dict):
        """Save agent runtime state — persists across cycles."""
        self.set(f"agent:state:{agent_id}", state)

    def get_agent_state(self, agent_id: str) -> dict:
        """Retrieve saved agent state."""
        return self.get(f"agent:state:{agent_id}") or {}

    # ── Status ────────────────────────────────────────────

    def get_status(self) -> dict:
        blacklisted_ips     = len(self.keys_with_prefix("blacklist:ip:"))
        blacklisted_domains = len(self.keys_with_prefix("blacklist:domain:"))
        active_threats      = len(self.keys_with_prefix("threat:active:"))

        return {
            "mode":                self._mode,
            "redis_available":     _REDIS_AVAILABLE,
            "blacklisted_ips":     blacklisted_ips,
            "blacklisted_domains": blacklisted_domains,
            "active_threats":      active_threats,
            "memory_keys":         len(self._memory) if not _REDIS_AVAILABLE else None,
        }
