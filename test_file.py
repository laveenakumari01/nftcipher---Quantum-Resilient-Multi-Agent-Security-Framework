"""
NFTCipher Autonomous Agents
Full Test Suite: All 5 Agents
Week 1: Data-Access, Cloud-API
Week 2: Arbiter
Week 3: Sentinel, Adversary
"""
import time
from agents.data_access_agent import DataAccessAgent
from agents.cloud_api_agent import CloudAPIAgent
from agents.arbiter_agent import ArbiterAgent
from agents.sentinel_agent import SentinelAgent
from agents.adversary_agent import AdversaryAgent
from logger import log_info, log_threat, log_error


def run_tests():
    log_info("=" * 60)
    log_info("   NFTCIPHER — FULL AGENT TEST SUITE STARTED")
    log_info("=" * 60)

    print("=" * 60)
    print("   NFTCIPHER — FULL AGENT TEST SUITE")
    print("=" * 60)

    # ── DATA-ACCESS AGENT TESTS ──
    print("\n🗄️  DATA-ACCESS AGENT TESTS")
    print("-" * 40)
    log_info("Starting Data-Access Agent Tests")
    da = DataAccessAgent()

    # Test 1 — Valid token
    print("\nTest 1 — Valid token:")
    result = da.fetch_data(
        token="valid_mock_token_123",
        table="users",
        query="get all users"
    )
    print(f"→ {result['status']}")

    # Test 2 — Invalid token
    print("\nTest 2 — Invalid token:")
    result = da.fetch_data(
        token="bad",
        table="users",
        query="get all"
    )
    print(f"→ {result['status']} | {result['reason']}")

    # Test 3 — Suspicious query
    print("\nTest 3 — Suspicious query (delete):")
    result = da.fetch_data(
        token="valid_mock_token_123",
        table="users",
        query="delete all users"
    )
    print(f"→ {result['status']}")

    # ── CLOUD-API AGENT TESTS ──
    print("\n☁️  CLOUD-API AGENT TESTS")
    print("-" * 40)
    log_info("Starting Cloud-API Agent Tests")
    ca = CloudAPIAgent()

    # Test 4 — Valid cloud service
    print("\nTest 4 — Valid cloud service:")
    result = ca.call_service(
        token="valid_mock_token_123",
        service="aws_s3",
        action="list_buckets"
    )
    print(f"→ {result['status']}")

    # Test 5 — Invalid service
    print("\nTest 5 — Invalid service:")
    result = ca.call_service(
        token="valid_mock_token_123",
        service="unknown_service",
        action="hack"
    )
    print(f"→ {result['status']} | {result['reason']}")

    print("\n📊 Agent Status")
    print(f"Data-Access: {da.get_status()}")
    print(f"Cloud-API:   {ca.get_status()}")

    # ── ARBITER AGENT TESTS ──
    print("\n\n⚖️  ARBITER AGENT TESTS")
    print("-" * 40)
    log_info("Starting Arbiter Agent Tests")
    arbiter = ArbiterAgent()
    time.sleep(3)

    # Test 6 — Valid agent with permission
    print("\nTest 6 — Valid agent with permission:")
    result = arbiter.arbitrate(
        token="valid_mock_token_123",
        agent_id="AGENT-DA-01",
        action="read_database"
    )
    print(f"→ Decision: {result['decision']} | Reason: {result['reason']}")
    time.sleep(5)

    # Test 7 — Agent with no permission
    print("\nTest 7 — Agent with no permission:")
    result = arbiter.arbitrate(
        token="valid_mock_token_123",
        agent_id="AGENT-DA-01",
        action="call_cloud"
    )
    print(f"→ Decision: {result['decision']} | Reason: {result['reason']}")
    time.sleep(5)

    # Test 8 — Invalid token
    print("\nTest 8 — Invalid token:")
    result = arbiter.arbitrate(
        token="bad",
        agent_id="AGENT-DA-01",
        action="read_database"
    )
    print(f"→ Decision: {result['decision']} | Reason: {result['reason']}")
    time.sleep(5)

    # Test 9 — Suspicious action
    print("\nTest 9 — Suspicious action (delete):")
    result = arbiter.arbitrate(
        token="valid_mock_token_123",
        agent_id="AGENT-DA-01",
        action="delete all database records"
    )
    print(f"→ Decision: {result['decision']} | Reason: {result['reason']}")
    time.sleep(5)

    print(f"\n📊 Arbiter Status: {arbiter.get_status()}")

    # ── SENTINEL AGENT TESTS ──
    print("\n\n👁️  SENTINEL AGENT TESTS")
    print("-" * 40)
    log_info("Starting Sentinel Agent Tests")
    sentinel = SentinelAgent()
    time.sleep(3)

    # Test 10 — Normal agent behavior
    print("\nTest 10 — Normal agent behavior:")
    result = sentinel.analyze_behavior(
        token="valid_mock_token_123",      # token added for security
        agent_id="AGENT-DA-01",
        action="fetch_users",
        metadata={"data_size": 100}
    )
    print(f"→ Threat: {result['is_threat']} | Level: {result['threat_level']}")
    time.sleep(5)

    # Test 11 — Suspicious: too many requests
    print("\nTest 11 — Suspicious: too many requests:")
    for i in range(22):
        sentinel.monitored_agents.setdefault("AGENT-ROGUE-01", {
            "request_count": 0,
            "actions": [],
            "first_seen": time.time()
        })
        sentinel.monitored_agents["AGENT-ROGUE-01"]["request_count"] += 1
        sentinel.monitored_agents["AGENT-ROGUE-01"]["actions"].append("fetch_data")

    result = sentinel.analyze_behavior(
        token="valid_mock_token_123",      # token added for security
        agent_id="AGENT-ROGUE-01",
        action="fetch_data",
        metadata={"data_size": 5000}
    )
    print(f"→ Threat: {result['is_threat']} | Level: {result['threat_level']} | Flags: {result['flags']}")
    time.sleep(5)

    # If threat detected — Arbiter blocks the agent
    if result['is_threat']:
        arbiter.block_agent("AGENT-ROGUE-01", "Sentinel flagged suspicious behavior")
        print(f"🚫 Arbiter blocked AGENT-ROGUE-01 on Sentinel request!")
        log_threat("AGENT-ROGUE-01 blocked by Arbiter on Sentinel request")

    print(f"\n📊 Sentinel Threat Report: {sentinel.get_threat_report()}")

    # ── ADVERSARY AGENT TESTS ──
    print("\n\n💀 ADVERSARY AGENT TESTS")
    print("-" * 40)
    log_info("Starting Adversary Agent Tests")
    adversary = AdversaryAgent()
    time.sleep(3)

    # Test 12 — Token Hijacking
    print("\nTest 12 — Token Hijacking Attack:")
    result = adversary.simulate_token_hijacking(
        stolen_token="stolen_token_xyz",
        target="database"
    )
    print(f"→ Attack: {result['attack_type']} | Blocked: {not result['success']}")
    print(f"→ Defense: {result['defense']}")
    time.sleep(5)

    # Test 13 — Harvest Now Decrypt Later
    print("\nTest 13 — Harvest Now Decrypt Later:")
    result = adversary.simulate_harvest_now_decrypt_later("encrypted_agent_data")
    print(f"→ Attack: {result['attack_type']} | Blocked: {not result['success']}")
    print(f"→ Defense: {result['defense']}")
    time.sleep(5)

    # Test 14 — Brute Force
    print("\nTest 14 — Brute Force Attack:")
    result = adversary.simulate_brute_force("AGENT-DA-01", attempts=5)
    print(f"→ Attack: {result['attack_type']} | Attempts: {result['attempts']} | Blocked: {not result['success']}")
    time.sleep(5)

    # Test 15 — API Flooding
    print("\nTest 15 — API Flooding:")
    result = adversary.simulate_api_flooding("/agent/fetch", request_count=50)
    print(f"→ Attack: {result['attack_type']} | Requests: {result['requests_sent']} | Blocked: {not result['success']}")
    time.sleep(5)

    # Test 16 — Privilege Escalation
    print("\nTest 16 — Privilege Escalation:")
    result = adversary.simulate_privilege_escalation("AGENT-DA-01", "aws_s3_admin")
    print(f"→ Attack: {result['attack_type']} | Blocked: {not result['success']}")

    print(f"\n📊 Attack Report: {adversary.get_attack_report()}")

    # ── FINAL STATUS ──
    print("\n\n📊 ALL AGENTS FINAL STATUS")
    print("=" * 60)
    print(f"Data-Access: {da.get_status()}")
    print(f"Cloud-API:   {ca.get_status()}")
    print(f"Arbiter:     {arbiter.get_status()}")
    print(f"Sentinel:    {sentinel.get_status()}")
    print(f"Adversary:   {adversary.get_status()}")
    print("\n✅ All Tests Complete!")

    log_info("All tests completed successfully")


if __name__ == "__main__":
    run_tests()