/**
 * ============================================================
 *  agentApi.js —  Frontend API Layer
 * ============================================================
 *
 *  PROJECT AGENTS:
 *  ┌─────────────────┬──────────────┬───────────────────────────────────────┐
 *  │ Agent ID        │ Role         │ Key Methods                           │
 *  ├─────────────────┼──────────────┼───────────────────────────────────────┤
 *  │ AGENT-ST-01     │ Sentinel     │ analyzeBehavior, getThreatReport      │
 *  │ AGENT-AR-01     │ Arbiter      │ arbitrate, blockAgent, getRiskScore   │
 *  │ AGENT-DA-01     │ Data Access  │ fetchData (users/logs/permissions)    │
 *  │ AGENT-CA-01     │ Cloud API    │ callService (aws_s3/ec2/lambda)       │
 *  │ AGENT-AD-01     │ Adversary    │ simulateAttack (5 attack types)       │
 *  └─────────────────┴──────────────┴───────────────────────────────────────┘
 *
 */

// ──────────────────────────────────────────────
//  CONFIG — Yahan se sab kuch control hota hai
// ──────────────────────────────────────────────
const MOCK_MODE     = false;
const BACKEND_URL   = "http://localhost:8000";
const REQUEST_TIMEOUT = 15000;  // 15 seconds


// ──────────────────────────────────────────────
//  TOKEN HELPER — get JWT from localStorage 
// ──────────────────────────────────────────────
function _getAuthHeaders() {
  const token = localStorage.getItem("access_token") || "";
  return {
    "Content-Type":  "application/json",
    "Authorization": `Bearer ${token}`,
  };
}


// ──────────────────────────────────────────────
//  MOCK DATA
// ──────────────────────────────────────────────

const MOCK_PERMISSIONS = {
  "AGENT-DA-01": ["read_database", "fetch_users", "fetch_logs"],
  "AGENT-CA-01": ["call_cloud", "aws_s3", "aws_ec2", "aws_lambda"],
  "AGENT-AR-01": ["arbitrate", "allow", "deny"],
  "AGENT-ST-01": ["monitor", "scan_logs", "flag_threat"],
  "AGENT-AD-01": ["simulate_attack"],
};

const MOCK_CLOUD = {
  aws_s3:     { status: "online", buckets:   ["nftcipher-data", "nftcipher-logs"] },
  aws_ec2:    { status: "online", instances: ["i-001", "i-002"] },
  aws_lambda: { status: "online", functions: ["auth-func", "data-func"] },
};

const MOCK_DATABASE = {
  users:       [{ id: 1, name: "Agent DR01", role: "data_reader" }, { id: 2, name: "Agent AC01", role: "api_caller" }],
  logs:        [{ id: 1, action: "login", status: "success" }, { id: 2, action: "fetch_data", status: "success" }],
  permissions: [{ agent_id: "AGENT-DA-01", permission: "read_database" }, { agent_id: "AGENT-CA-01", permission: "call_cloud" }],
};

const BLOCKED_ACTIONS = ["delete_all", "drop_table", "bypass_auth", "disable_security", "hack"];

const MOCK_PQC_COMPARISON = {
  classical: { algorithm: "RSA-2048", quantum_safe: false, resilience_to_shors: "10.9%", handshake_time: "12ms", description: "Vulnerable to Shor's Algorithm" },
  pqc:       { algorithm: "CRYSTALS-Kyber + Dilithium", quantum_safe: true, resilience_to_shors: "99.99%", handshake_time: "0.8ms", description: "Lattice-based — immune to quantum attacks" },
};

const MOCK_AGENTS_STATE = {
  "AGENT-ST-01": { agent_id: "AGENT-ST-01", role: "Sentinel",     status: "ACTIVE", total_threats: 0, monitored_agents: 0 },
  "AGENT-AR-01": { agent_id: "AGENT-AR-01", role: "Arbiter",      status: "ACTIVE", blocked_agents: [], total_requests: 0 },
  "AGENT-DA-01": { agent_id: "AGENT-DA-01", role: "Data Access",  status: "ACTIVE", failed_attempts: 0 },
  "AGENT-CA-01": { agent_id: "AGENT-CA-01", role: "Cloud API",    status: "ACTIVE", failed_attempts: 0 },
  "AGENT-AD-01": { agent_id: "AGENT-AD-01", role: "Adversary",    status: "ACTIVE", total_attacks_simulated: 0 },
};

let _runtimeState = {
  sentinelThreats:      [],
  monitoredAgents:      {},
  arbiterBlocked:       [],
  arbiterRequestCounts: {},
  adversaryAttackLog:   [],
};


// ──────────────────────────────────────────────
//  HELPER FUNCTIONS
// ──────────────────────────────────────────────

function _validateToken(token) {
  return token && token.length >= 10;
}

function _isActionSafe(action) {
  const lower = action.toLowerCase();
  return !BLOCKED_ACTIONS.some(blocked => lower.includes(blocked));
}

function _calculateRiskScore(agentId, action) {
  let risk = 0.0;
  if (_runtimeState.arbiterBlocked.includes(agentId)) return 1.0;
  const suspiciousKeywords = ["delete", "drop", "hack", "bypass", "admin", "root"];
  for (const kw of suspiciousKeywords) {
    if (action.toLowerCase().includes(kw)) risk += 0.4;
  }
  const count = _runtimeState.arbiterRequestCounts[agentId] || 0;
  if (count > 10) risk += 0.5;
  _runtimeState.arbiterRequestCounts[agentId] = count + 1;
  return Math.min(risk, 1.0);
}

function _generateMockToken(agentId) {
  const payload = `${agentId}:${Date.now()}`;
  const hash = [...payload].reduce((h, c) => (Math.imul(31, h) + c.charCodeAt(0)) | 0, 0);
  return Math.abs(hash).toString(16).padStart(10, "0") + Date.now().toString(16);
}

// ── MAIN FETCH HELPER — Authorization header included ──
async function _apiFetch(endpoint, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);
  try {
    const res = await fetch(`${BACKEND_URL}${endpoint}`, {
      signal: controller.signal,
      ...options,
      headers: {
        ..._getAuthHeaders(),
        ...(options.headers || {}),
      },
    });
    clearTimeout(timer);
    // 401 = token expired — clear karo
    if (res.status === 401) {
      localStorage.removeItem("access_token");
      throw new Error("Session expired — please login again");
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    return await res.json();
  } catch (err) {
    clearTimeout(timer);
    if (err.name === "AbortError") throw new Error("Request timeout — backend unreachable");
    throw err;
  }
}

function _mockDelay(ms = 300) {
  return new Promise(r => setTimeout(r, ms));
}


// ══════════════════════════════════════════════
//  1. QUANTUM TOKEN  (pqc_simulation.py)
// ══════════════════════════════════════════════

export async function generateQuantumToken(agentId) {
  if (MOCK_MODE) {
    await _mockDelay();
    return { agent_id: agentId, token: _generateMockToken(agentId), algorithm: "CRYSTALS-Kyber + Dilithium", quantum_safe: true };
  }
  return _apiFetch("/quantum/token", {
    method: "POST",
    body: JSON.stringify({ agent_id: agentId }),
  });
}

export async function getPQCComparison() {
  if (MOCK_MODE) {
    await _mockDelay();
    return MOCK_PQC_COMPARISON;
  }
  return _apiFetch("/quantum/compare");
}


// ══════════════════════════════════════════════
//  2. SENTINEL AGENT  (sentinel_agent.py)
// ══════════════════════════════════════════════

export async function analyzeBehavior(token, agentId, action, metadata = {}) {
  if (MOCK_MODE) {
    await _mockDelay(800);
    if (!_validateToken(token)) {
      return { agent_id: agentId, is_threat: false, threat_level: "UNKNOWN", flags: [], reason: "Sentinel authentication failed", status: "DENIED" };
    }
    const flags = [];
    const agentData = _runtimeState.monitoredAgents[agentId] || { request_count: 0, actions: [] };
    agentData.request_count += 1;
    agentData.actions.push(action);
    _runtimeState.monitoredAgents[agentId] = agentData;
    if (agentData.request_count > 20) flags.push("HIGH_REQUEST_COUNT");
    if (agentData.actions.filter(a => a === action).length > 5) flags.push("REPEATED_ACTION");
    if ((metadata.data_size || 0) > 1000) flags.push("LARGE_DATA_EXPORT");
    const is_threat = flags.length > 0;
    const threat_level = is_threat && flags.length > 2 ? "HIGH" : is_threat ? "MEDIUM" : "LOW";
    if (is_threat) _runtimeState.sentinelThreats.push({ agentId, action, flags, threat_level, timestamp: Date.now() });
    return { agent_id: agentId, action, is_threat, threat_level, flags, request_count: agentData.request_count, timestamp: Date.now() };
  }
  return _apiFetch("/sentinel/analyze", {
    method: "POST",
    body: JSON.stringify({ token, agent_id: agentId, action, metadata }),
  });
}

export async function getThreatReport() {
  if (MOCK_MODE) {
    await _mockDelay();
    const threats = _runtimeState.sentinelThreats;
    return {
      total_threats: threats.length,
      monitored_agents: Object.keys(_runtimeState.monitoredAgents).length,
      recent_threats: threats.slice(-5),
      threat_levels: {
        HIGH:   threats.filter(t => t.threat_level === "HIGH").length,
        MEDIUM: threats.filter(t => t.threat_level === "MEDIUM").length,
        LOW:    threats.filter(t => t.threat_level === "LOW").length,
      },
    };
  }
  return _apiFetch("/sentinel/report");
}

export async function getSentinelStatus() {
  if (MOCK_MODE) {
    await _mockDelay();
    return { ...MOCK_AGENTS_STATE["AGENT-ST-01"], total_threats: _runtimeState.sentinelThreats.length, monitored_agents: Object.keys(_runtimeState.monitoredAgents).length };
  }
  return _apiFetch("/sentinel/status");
}


// ══════════════════════════════════════════════
//  3. ARBITER AGENT  (arbiter_agent.py)
// ══════════════════════════════════════════════

export async function arbitrate(token, agentId, action) {
  if (MOCK_MODE) {
    await _mockDelay(600);
    if (!_validateToken(token)) return { decision: "DENY", reason: "Invalid or expired token", risk_score: 1.0, agent_id: agentId };
    if (!_isActionSafe(action)) return { decision: "DENY", reason: "Security guardrail triggered — unsafe action", risk_score: 0.9, agent_id: agentId };
    const risk_score = _calculateRiskScore(agentId, action);
    if (risk_score >= 0.9) { _runtimeState.arbiterBlocked.push(agentId); return { decision: "DENY", reason: `Risk score too high: ${risk_score.toFixed(2)}`, risk_score, agent_id: agentId }; }
    const perms = MOCK_PERMISSIONS[agentId] || [];
    const hasPerm = perms.some(p => action.toLowerCase().includes(p));
    if (!hasPerm) return { decision: "DENY", reason: `Agent [${agentId}] has no permission for [${action}]`, risk_score, agent_id: agentId };
    return { decision: "ALLOW", reason: "All checks passed — token valid, permission granted, risk acceptable", risk_score, agent_id: agentId };
  }
  return _apiFetch("/arbiter/arbitrate", {
    method: "POST",
    body: JSON.stringify({ token, agent_id: agentId, action }),
  });
}

export async function blockAgent(agentId, reason = "Manually blocked via dashboard") {
  if (MOCK_MODE) {
    await _mockDelay();
    if (!_runtimeState.arbiterBlocked.includes(agentId)) _runtimeState.arbiterBlocked.push(agentId);
    return { status: "BLOCKED", agent_id: agentId, reason };
  }
  return _apiFetch("/arbiter/block", {
    method: "POST",
    body: JSON.stringify({ agent_id: agentId, reason }),
  });
}

export async function getArbiterStatus() {
  if (MOCK_MODE) {
    await _mockDelay();
    return { ...MOCK_AGENTS_STATE["AGENT-AR-01"], blocked_agents: _runtimeState.arbiterBlocked, total_requests: Object.values(_runtimeState.arbiterRequestCounts).reduce((a, b) => a + b, 0) };
  }
  return _apiFetch("/arbiter/status");
}


// ══════════════════════════════════════════════
//  4. DATA ACCESS AGENT  (data_access_agent.py)
// ══════════════════════════════════════════════

export async function fetchData(token, table, query) {
  if (MOCK_MODE) {
    await _mockDelay(500);
    if (!_validateToken(token)) return { status: "DENIED", reason: "Authentication failed" };
    const lower = query.toLowerCase();
    if (["delete", "drop", "truncate", "modify", "update", "insert"].some(kw => lower.includes(kw))) return { status: "DENIED", reason: "LLM denied — unsafe query" };
    const data = MOCK_DATABASE[table] || [];
    return { status: "SUCCESS", agent: "AGENT-DA-01", table, data, ml_check: "🟢 SAFE", source: "MOCK_DB" };
  }
  return _apiFetch("/data/fetch", {
    method: "POST",
    body: JSON.stringify({ token, table, query }),
  });
}

export async function getDataAgentStatus() {
  if (MOCK_MODE) { await _mockDelay(); return MOCK_AGENTS_STATE["AGENT-DA-01"]; }
  return _apiFetch("/data/status");
}


// ══════════════════════════════════════════════
//  5. CLOUD API AGENT  (cloud_api_agent.py)
// ══════════════════════════════════════════════

export async function callCloudService(token, service, action) {
  if (MOCK_MODE) {
    await _mockDelay(600);
    if (!_validateToken(token)) return { status: "DENIED", reason: "Authentication failed" };
    const allowed = ["aws_s3", "aws_ec2", "aws_lambda"];
    if (!allowed.includes(service)) return { status: "DENIED", reason: `Service '${service}' is not allowed` };
    return { status: "SUCCESS", agent: "AGENT-CA-01", service, action, result: MOCK_CLOUD[service], ml_check: "🟢 SAFE", source: "BACKEND_VERIFIED" };
  }
  return _apiFetch("/cloud/call", {
    method: "POST",
    body: JSON.stringify({ token, service, action }),
  });
}

export async function getCloudAgentStatus() {
  if (MOCK_MODE) { await _mockDelay(); return MOCK_AGENTS_STATE["AGENT-CA-01"]; }
  return _apiFetch("/cloud/status");
}


// ══════════════════════════════════════════════
//  6. ADVERSARY AGENT  (adversary_agent.py)
// ══════════════════════════════════════════════

export async function simulateTokenHijacking(stolenToken, target) {
  if (MOCK_MODE) {
    await _mockDelay(700);
    const result = { attack_type: "Token Hijacking", mitre_id: "T1528", target, success: false, description: "Attacker stole a valid JWT token and attempted to reuse it", defense: "PQC-signed tokens cannot be replayed — Arbiter detects anomaly", timestamp: Date.now() };
    _runtimeState.adversaryAttackLog.push(result);
    return result;
  }
  return _apiFetch("/adversary/token-hijacking", {
    method: "POST",
    body: JSON.stringify({ stolen_token: stolenToken, target }),
  });
}

export async function simulateHarvestDecrypt(dataTarget) {
  if (MOCK_MODE) {
    await _mockDelay(700);
    const result = { attack_type: "Harvest Now Decrypt Later", mitre_id: "T1600", target: dataTarget, success: false, description: "Attacker harvests encrypted data now to decrypt with quantum computer later", defense: "CRYSTALS-Kyber PQC encryption is quantum-resistant — data is safe", timestamp: Date.now() };
    _runtimeState.adversaryAttackLog.push(result);
    return result;
  }
  return _apiFetch("/adversary/harvest-decrypt", {
    method: "POST",
    body: JSON.stringify({ data_target: dataTarget }),
  });
}

export async function simulateBruteForce(targetAgent, attempts = 5) {
  if (MOCK_MODE) {
    await _mockDelay(700);
    const result = { attack_type: "Brute Force", mitre_id: "T1110", target: targetAgent, attempts, success: false, description: `Attacker tried ${attempts} different tokens rapidly`, defense: `Auto-blocked after 3 failed attempts — all ${attempts} attempts failed`, timestamp: Date.now() };
    _runtimeState.adversaryAttackLog.push(result);
    return result;
  }
  return _apiFetch("/adversary/brute-force", {
    method: "POST",
    body: JSON.stringify({ target_agent: targetAgent, attempts }),
  });
}

export async function simulateApiFlooding(targetEndpoint, requestCount = 20) {
  if (MOCK_MODE) {
    await _mockDelay(700);
    const result = { attack_type: "API Flooding", mitre_id: "T1499", target: targetEndpoint, requests_sent: requestCount, success: false, description: `Attacker sent ${requestCount} rapid requests to overwhelm ${targetEndpoint}`, defense: "Arbiter detected high request rate — risk score exceeded threshold", timestamp: Date.now() };
    _runtimeState.adversaryAttackLog.push(result);
    return result;
  }
  return _apiFetch("/adversary/api-flooding", {
    method: "POST",
    body: JSON.stringify({ target_endpoint: targetEndpoint, request_count: requestCount }),
  });
}

export async function simulatePrivilegeEscalation(agentId, targetResource) {
  if (MOCK_MODE) {
    await _mockDelay(700);
    const result = { attack_type: "Privilege Escalation", mitre_id: "T1068", agent_id: agentId, target_resource: targetResource, success: false, description: `Agent [${agentId}] tried to access [${targetResource}] without permission`, defense: "Arbiter Permission Matrix check failed — access denied", timestamp: Date.now() };
    _runtimeState.adversaryAttackLog.push(result);
    return result;
  }
  return _apiFetch("/adversary/privilege-escalation", {
    method: "POST",
    body: JSON.stringify({ agent_id: agentId, target_resource: targetResource }),
  });
}

export async function getAttackReport() {
  if (MOCK_MODE) {
    await _mockDelay();
    const log = _runtimeState.adversaryAttackLog;
    return { total_attacks: log.length, successful_attacks: log.filter(a => a.success).length, blocked_attacks: log.filter(a => !a.success).length, detection_rate: log.length ? "100%" : "N/A", attacks: log };
  }
  return _apiFetch("/adversary/report");
}

export async function getAdversaryStatus() {
  if (MOCK_MODE) { await _mockDelay(); return { ...MOCK_AGENTS_STATE["AGENT-AD-01"], total_attacks_simulated: _runtimeState.adversaryAttackLog.length }; }
  return _apiFetch("/adversary/status");
}


// ══════════════════════════════════════════════
//  7. ALL AGENTS + MEMORY
// ══════════════════════════════════════════════

export async function getAllAgentsStatus() {
  if (MOCK_MODE) { await _mockDelay(); return MOCK_AGENTS_STATE; }
  return _apiFetch("/agents/all");
}

export async function getAgentStatus(agentId) {
  if (MOCK_MODE) { await _mockDelay(); return MOCK_AGENTS_STATE[agentId] || null; }
  return _apiFetch(`/agents/${agentId}/status`);
}

export async function getAgentMemory(agentId) {
  if (MOCK_MODE) { await _mockDelay(); return { agent_id: agentId, failed_attempts: 0, history: "No history in mock mode", backend: "mock" }; }
  return _apiFetch(`/memory/${agentId}`);
}

export async function getLogs(limit = 50) {
  if (MOCK_MODE) { await _mockDelay(); return []; }
  return _apiFetch(`/logs?limit=${limit}`);
}