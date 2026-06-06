/**
 * ============================================================
 *  agent_api.js —  Frontend API Layer  (UPDATED)
 * ============================================================
 *
 *  ALL 10 AGENTS:
 *  ┌──────────────────────┬──────────────────┬───────────────────────────────────────┐
 *  │ Agent ID             │ Role             │ Key Methods                           │
 *  ├──────────────────────┼──────────────────┼───────────────────────────────────────┤
 *  │ AGENT-ST-01          │ Sentinel         │ analyzeBehavior, getThreatReport      │
 *  │ AGENT-AR-01          │ Arbiter          │ arbitrate, blockAgent                 │
 *  │ AGENT-DA-01          │ Data Access      │ fetchData                             │
 *  │ AGENT-CA-01          │ Cloud API        │ callCloudService                      │
 *  │ AGENT-AD-01          │ Adversary        │ simulateAttack (5 types)              │
 *  │ AGENT-CR-01          │ Cryptographer    │ getCryptographerStatus, issueKeys     │
 *  │ AGENT-RS-01          │ Research         │ getResearchStatus, searchCVE          │
 *  │ AGENT-CD-01          │ Coding           │ getCodingStatus, generateFirewallRule │
 *  │ AGENT-VS-01          │ Vision           │ getVisionStatus, getVisionThreats     │
 *  │ AGENT-TD-01          │ Threat Detection │ getThreatDetectionStatus              │
 *  └──────────────────────┴──────────────────┴───────────────────────────────────────┘
 *
 */

// ──────────────────────────────────────────────
//  CONFIG
// ──────────────────────────────────────────────
const MOCK_MODE       = false;
const BACKEND_URL     = "http://localhost:8000";
const REQUEST_TIMEOUT = 15000; // 15 seconds


// ──────────────────────────────────────────────
//  TOKEN HELPER
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

// Mock data for new 5 agents
const MOCK_NEW_AGENTS = {
  cryptographer: {
    agent_id: "AGENT-CR-01", role: "Cryptographer", status: "ACTIVE",
    pqc_mode: "KYBER-768", keys_issued: 142, tokens_active: 38,
    rotation_timer: "14m 22s", algorithm: "CRYSTALS-Kyber-768 + Dilithium3",
  },
  research: {
    agent_id: "AGENT-RS-01", role: "Research", status: "ACTIVE",
    cve_db_size: 2847, last_query: "SQL injection bypass",
    rag_status: "ONLINE", vector_db: "ChromaDB",
  },
  coding: {
    agent_id: "AGENT-CD-01", role: "Coding", status: "ACTIVE",
    scripts_generated: 23, last_rule: "BLOCK ip 192.168.1.45",
    safety_checks_passed: 23, safety_checks_failed: 0,
  },
  vision: {
    agent_id: "AGENT-VS-01", role: "Vision", status: "ACTIVE",
    mode: "SIMULATED", locations: 4, detections: 2,
    active_threats: [],
  },
  threat_detection: {
    agent_id: "AGENT-TD-01", role: "ThreatDetection", status: "ACTIVE",
    phishing_checks: 891, malware_scans: 412, network_anomalies: 7,
  },
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

// Main fetch helper — Authorization header included
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
//  1. QUANTUM TOKEN  (/quantum/*)
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
  if (MOCK_MODE) { await _mockDelay(); return MOCK_PQC_COMPARISON; }
  return _apiFetch("/quantum/compare");
}

/**
 * NEW — Real PQC mode check (no auth required)
 * Returns: { real_pqc: bool, mode: "real"|"simulation", algorithm: str }
 */
export async function getPQCRealStatus() {
  return _apiFetch("/pqc/real-status");
}


// ══════════════════════════════════════════════
//  2. SENTINEL AGENT  (/sentinel/*)
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
//  3. ARBITER AGENT  (/arbiter/*)
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
//  4. DATA ACCESS AGENT  (/data/*)
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
//  5. CLOUD API AGENT  (/cloud/*)
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
//  6. ADVERSARY AGENT  (/adversary/*)
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

/**
 * Original 5 agents ka status — /agents/all
 */
export async function getAllAgentsStatus() {
  if (MOCK_MODE) { await _mockDelay(); return MOCK_AGENTS_STATE; }
  return _apiFetch("/agents/all");
}

/**
 * NEW — Saare 10 agents ka full status ek call mein
 * Returns: { sentinel, arbiter, data_access, cloud_api, adversary,
 *            cryptographer, research, coding, vision, threat_detection, orchestrator }
 */
export async function getAllAgentsFullStatus() {
  if (MOCK_MODE) {
    await _mockDelay();
    return {
      sentinel:         MOCK_AGENTS_STATE["AGENT-ST-01"],
      arbiter:          MOCK_AGENTS_STATE["AGENT-AR-01"],
      data_access:      MOCK_AGENTS_STATE["AGENT-DA-01"],
      cloud_api:        MOCK_AGENTS_STATE["AGENT-CA-01"],
      adversary:        MOCK_AGENTS_STATE["AGENT-AD-01"],
      ...MOCK_NEW_AGENTS,
    };
  }
  return _apiFetch("/agents/all-status");
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


// ══════════════════════════════════════════════
//  8. CRYPTOGRAPHER AGENT  (/cryptographer/*)   [NEW]
// ══════════════════════════════════════════════

/**
 * Cryptographer Agent ka status — PQC mode, keys issued, tokens active
 * Returns: { agent_id, pqc_mode, keys_issued, tokens_active, rotation_timer, status }
 */
export async function getCryptographerStatus() {
  if (MOCK_MODE) { await _mockDelay(); return MOCK_NEW_AGENTS.cryptographer; }
  return _apiFetch("/cryptographer/status");
}

/**
 * Kisi agent ke liye naya Kyber768 + Dilithium3 keypair generate karo
 * Requires: admin role
 * Returns: { agent_id, public_key, algorithm, issued_at }
 */
export async function issueKeys(agentId) {
  if (MOCK_MODE) {
    await _mockDelay(500);
    return { agent_id: agentId, public_key: "mock_pk_" + agentId, algorithm: "KYBER-768", issued_at: Date.now() };
  }
  return _apiFetch(`/cryptographer/issue-keys/${agentId}`, { method: "POST" });
}

/**
 * Agent ke liye PQC-signed token issue karo
 * Requires: admin role
 * Returns: { agent_id, token, algorithm, expires_at }
 */
export async function issueToken(agentId) {
  if (MOCK_MODE) {
    await _mockDelay(500);
    return { agent_id: agentId, token: _generateMockToken(agentId), algorithm: "CRYSTALS-Kyber + Dilithium", expires_at: Date.now() + 3600000 };
  }
  return _apiFetch(`/cryptographer/issue-token/${agentId}`, { method: "POST" });
}

/**
 * Token verify karo — valid hai ya nahi
 * Returns: { valid: bool, agent_id, reason }
 */
export async function verifyToken(token) {
  if (MOCK_MODE) {
    await _mockDelay(300);
    return { valid: _validateToken(token), agent_id: "unknown", reason: token ? "Token valid" : "Token missing" };
  }
  return _apiFetch("/cryptographer/verify-token", {
    method: "POST",
    body: JSON.stringify({ token }),
  });
}

/**
 * Message sign karo
 * Returns: { signed_message, signature, algorithm }
 */
export async function signMessage(message, agentId) {
  if (MOCK_MODE) {
    await _mockDelay(300);
    return { signed_message: message, signature: "mock_sig_" + Date.now(), algorithm: "Dilithium3", agent_id: agentId };
  }
  return _apiFetch("/cryptographer/sign-message", {
    method: "POST",
    body: JSON.stringify({ message, agent_id: agentId }),
  });
}


// ══════════════════════════════════════════════
//  9. RESEARCH AGENT  (/research/*)   [NEW]
// ══════════════════════════════════════════════

/**
 * Research Agent ka status — VectorDB size, RAG mode, last query
 * Returns: { agent_id, cve_db_size, last_query, rag_status, vector_db, status }
 */
export async function getResearchStatus() {
  if (MOCK_MODE) { await _mockDelay(); return MOCK_NEW_AGENTS.research; }
  return _apiFetch("/research/status");
}

/**
 * RAG-powered CVE/threat search — VectorDB se retrieve + LLM context
 * @param {string} query - threat ya vulnerability description
 * @param {number} topK  - kitne results chahiye (default 3)
 * Returns: { results: [...], query, source: "RAG+LLM" }
 */
export async function searchCVE(query, topK = 3) {
  if (MOCK_MODE) {
    await _mockDelay(800);
    return {
      query,
      results: [
        { cve_id: "CVE-2024-1234", score: 0.92, summary: "Mock CVE related to: " + query },
        { cve_id: "CVE-2024-5678", score: 0.85, summary: "Another related vulnerability" },
      ],
      source: "MOCK_RAG",
    };
  }
  return _apiFetch("/research/search", {
    method: "POST",
    body: JSON.stringify({ query, top_k: topK }),
  });
}

/**
 * Research Agent ki search history
 * Returns: { history: [...], count }
 */
export async function getResearchHistory() {
  if (MOCK_MODE) {
    await _mockDelay();
    return { history: [{ query: "SQL injection", timestamp: Date.now() - 60000 }], count: 1 };
  }
  return _apiFetch("/research/history");
}

/**
 * VectorDB mein naya threat intel add karo
 * @param {string} content - CVE ya threat description
 * @param {object} metadata - { cve_id, severity, source }
 */
export async function addThreatIntel(content, metadata = {}) {
  if (MOCK_MODE) {
    await _mockDelay(400);
    return { status: "added", id: "mock_" + Date.now() };
  }
  return _apiFetch("/research/add-intel", {
    method: "POST",
    body: JSON.stringify({ content, metadata }),
  });
}


// ══════════════════════════════════════════════
//  10. CODING AGENT  (/coding/*)   [NEW]
// ══════════════════════════════════════════════

/**
 * Coding Agent ka status — scripts generated, last rule, safety checks
 * Returns: { agent_id, scripts_generated, last_rule, safety_checks_passed, status }
 */
export async function getCodingStatus() {
  if (MOCK_MODE) { await _mockDelay(); return MOCK_NEW_AGENTS.coding; }
  return _apiFetch("/coding/status");
}

/**
 * Fetch all auto-generated firewall rules from CodingAgent.
 * Returns: { firewall_rules: [...], total_rules, total_scripts, safe_checked, auto_seeded }
 *
 * Note: The backend auto-seeds baseline rules on first call if _generated_scripts
 * is empty (e.g. after a restart). Run a threat simulation to generate live rules.
 */
export async function getFirewallRules() {
  if (MOCK_MODE) {
    await _mockDelay(400);
    return {
      firewall_rules: [
        {
          rule_id: "mock001abc",
          type: "firewall_rule",
          rule: "iptables -I INPUT -s 192.168.1.100 -j DROP -m comment --comment 'NFTCipher-BRUTE_FORCE'",
          revert: "iptables -D INPUT -s 192.168.1.100 -j DROP",
          explanation: "Block all traffic from 192.168.1.100 detected as BRUTE_FORCE",
          threat: { ip: "192.168.1.100", attack_type: "BRUTE_FORCE", score: 0.87 },
          generated_at: Date.now() / 1000 - 120,
          applied: true,
          safe_checked: true,
        },
      ],
      total_rules: 1,
      total_scripts: 3,
      safe_checked: 1,
    };
  }
  return _apiFetch("/coding/rules");
}

/**
 * Generate an iptables firewall rule for a given threat.
 * @param {object} data - { ip, attack_type, port (optional), score (optional) }
 * Note: Agent only generates — does not apply. Arbiter decides application.
 * Returns: { rule, ip, attack_type, generated_at }
 */
export async function generateFirewallRule(data) {
  if (MOCK_MODE) {
    await _mockDelay(600);
    return {
      rule: `iptables -A INPUT -s ${data.ip || "0.0.0.0"} -j DROP`,
      ip: data.ip,
      attack_type: data.attack_type,
      generated_at: Date.now(),
      source: "MOCK_CODING_AGENT",
    };
  }
  return _apiFetch("/coding/firewall-rule", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

/**
 * Incident response script generate karo
 * @param {object} data - { incident_type, severity, affected_system }
 */
export async function generateIncidentResponse(data) {
  if (MOCK_MODE) {
    await _mockDelay(600);
    return { script: "# Mock incident response script", steps: ["Isolate system", "Collect logs", "Notify team"], source: "MOCK" };
  }
  return _apiFetch("/coding/incident-response", {
    method: "POST",
    body: JSON.stringify(data),
  });
}


// ══════════════════════════════════════════════
//  11. VISION AGENT  (/vision/*)   [NEW]
// ══════════════════════════════════════════════

/**
 * Vision Agent ka status — mode, locations monitored, total detections
 * Returns: { agent_id, mode: "real"|"simulated", locations, detections, status }
 */
export async function getVisionStatus() {
  if (MOCK_MODE) { await _mockDelay(); return MOCK_NEW_AGENTS.vision; }
  return _apiFetch("/vision/status");
}

/**
 * Active physical threats from Vision Agent
 * Returns: { active_threats: [...], total_detections }
 * Threat format: { type, location, severity, detected_at }
 */
export async function getVisionThreats() {
  if (MOCK_MODE) {
    await _mockDelay();
    return {
      active_threats: [
        { type: "tailgating", location: "Main Entrance", severity: "HIGH", detected_at: Date.now() - 120000 },
        { type: "after_hours_access", location: "Server Room", severity: "MEDIUM", detected_at: Date.now() - 300000 },
      ],
      total_detections: 2,
    };
  }
  return _apiFetch("/vision/active-threats");
}

/**
 * Physical security event analyze karo
 * @param {string} description - Camera scene ya event description
 * @param {string} location    - Location name
 */
export async function analyzePhysicalEvent(description, location) {
  if (MOCK_MODE) {
    await _mockDelay(700);
    return { threat_detected: false, threat_type: null, severity: "LOW", description, location, source: "MOCK_VISION" };
  }
  return _apiFetch("/vision/analyze", {
    method: "POST",
    body: JSON.stringify({ description, location }),
  });
}


// ══════════════════════════════════════════════
//  12. THREAT DETECTION AGENT  (/threat-detection/*)   [NEW]
// ══════════════════════════════════════════════

/**
 * Threat Detection Agent ka status — phishing, malware, network anomaly counts
 * Returns: { agent_id, phishing_checks, malware_scans, network_anomalies, status }
 */
export async function getThreatDetectionStatus() {
  if (MOCK_MODE) { await _mockDelay(); return MOCK_NEW_AGENTS.threat_detection; }
  return _apiFetch("/threat-detection/status");
}

/**
 * URL phishing check — rule-based + regex + LLM analysis
 * @param {string} url - Check karna wala URL
 * Returns: { is_phishing: bool, confidence, reason, url }
 */
export async function checkPhishing(url) {
  if (MOCK_MODE) {
    await _mockDelay(500);
    const suspicious = url.includes("login") || url.includes("verify") || url.includes("secure");
    return { is_phishing: suspicious, confidence: suspicious ? 0.87 : 0.12, reason: suspicious ? "Suspicious keywords detected" : "No phishing indicators", url, source: "MOCK" };
  }
  return _apiFetch("/threat-detection/phishing", {
    method: "POST",
    body: JSON.stringify({ url }),
  });
}

/**
 * File/content malware scan
 * @param {string} content - File content ya description
 * Returns: { is_malware: bool, confidence, threat_type, content }
 */
export async function scanMalware(content) {
  if (MOCK_MODE) {
    await _mockDelay(500);
    return { is_malware: false, confidence: 0.05, threat_type: null, content: content?.slice(0, 50), source: "MOCK" };
  }
  return _apiFetch("/threat-detection/malware", {
    method: "POST",
    body: JSON.stringify({ content }),
  });
}

/**
 * Network traffic anomaly check
 * @param {object} data - { source_ip, dest_ip, port, bytes_transferred, protocol }
 * Returns: { is_anomaly: bool, anomaly_type, confidence, data }
 */
export async function checkNetworkAnomaly(data) {
  if (MOCK_MODE) {
    await _mockDelay(500);
    return { is_anomaly: false, anomaly_type: null, confidence: 0.08, data, source: "MOCK" };
  }
  return _apiFetch("/threat-detection/network", {
    method: "POST",
    body: JSON.stringify(data),
  });
}


// ══════════════════════════════════════════════
//  13. ORCHESTRATOR  (/orchestrator/*)   [NEW]
// ══════════════════════════════════════════════

/**
 * LangGraph orchestrator ka status — graph compiled, cycle count, last verdict
 * Returns: { graph_compiled: bool, total_cycles, last_verdict, cycle_history: [...] }
 */
export async function getOrchestratorStatus() {
  if (MOCK_MODE) {
    await _mockDelay();
    return { graph_compiled: true, total_cycles: 47, last_verdict: "NO_THREAT", cycle_history: [], status: "ACTIVE" };
  }
  return _apiFetch("/orchestrator/status");
}

/**
 * Manually ek full security cycle trigger karo
 * Requires: admin role
 * Cycle order: research → sentinel → threat_det → vision → verify → arbiter → cryptographer → coding → complete
 * @param {string} trigger  - "manual" ya event type
 * @param {object} payload  - Extra context (optional)
 * Returns: { cycle_id, verdict, actions_taken, duration_ms }
 */
export async function runOrchestratorCycle(trigger = "manual", payload = {}) {
  if (MOCK_MODE) {
    await _mockDelay(1200);
    return { cycle_id: "mock_cycle_" + Date.now(), verdict: "NO_THREAT", actions_taken: [], duration_ms: 1200, trigger };
  }
  return _apiFetch("/orchestrator/run-cycle", {
    method: "POST",
    body: JSON.stringify({ trigger, payload }),
  });
}


// ══════════════════════════════════════════════
//  14. SUGGESTION ENGINE  (/suggestions/*)   [NEW]
// ══════════════════════════════════════════════

/**
 * AI-generated security suggestions — most recent first
 * @param {number} limit - Kitni suggestions chahiye (default 50)
 * Returns: { suggestions: [...], count, timestamp }
 * Suggestion format: { threat_summary, root_cause, immediate_actions,
 *                      longterm_fix, risk_assessment, cves: [...] }
 */
export async function getSuggestions(limit = 50) {
  if (MOCK_MODE) {
    await _mockDelay();
    return {
      suggestions: [
        {
          id: "mock_sug_1",
          threat_summary: "SQL Injection attempt detected on /data/fetch",
          root_cause: "Unparameterized query in Data Access Agent",
          immediate_actions: ["Block IP 192.168.1.45", "Rotate DB credentials"],
          longterm_fix: "Use parameterized queries, add input validation layer",
          risk_assessment: "HIGH — data exfiltration possible",
          cves: ["CVE-2024-1234"],
          timestamp: Date.now() - 60000,
        },
      ],
      count: 1,
      timestamp: Date.now(),
    };
  }
  return _apiFetch(`/suggestions?limit=${limit}`);
}

/**
 * Ek specific suggestion — thread_id se
 */
export async function getSuggestionById(threadId) {
  if (MOCK_MODE) { await _mockDelay(); return null; }
  return _apiFetch(`/suggestions/${threadId}`);
}

/**
 * Suggestion engine ka summary stats
 * Returns: { total, high_risk, pending_actions, resolved }
 */
export async function getSuggestionStats() {
  if (MOCK_MODE) {
    await _mockDelay();
    return { total: 1, high_risk: 1, pending_actions: 2, resolved: 0 };
  }
  return _apiFetch("/suggestions/stats/summary");
}


// ══════════════════════════════════════════════
//  15. VERIFICATION ENGINE  (/security/*)   [NEW]
// ══════════════════════════════════════════════

/**
 * Verification Engine ka stats — voter accuracy, false positive rate
 * Returns: { confirmed_threats, false_positives, total_verified,
 *            accuracy, consensus_method, action_thresholds }
 */
export async function getVerificationStats() {
  if (MOCK_MODE) {
    await _mockDelay();
    return {
      confirmed_threats: 48,
      false_positives:   12,
      total_verified:    60,
      accuracy:          "80.0%",
      verifier_active:   true,
      consensus_method:  "2-of-3 vote (LLM 35% + ML 45% + Rules 20%)",
      action_thresholds: {
        AUTO_BLOCK: "score >= 0.80",
        ALERT:      "score >= 0.50",
        WATCHLIST:  "score >= 0.25",
        IGNORE:     "score < 0.25",
      },
    };
  }
  return _apiFetch("/security/verification-stats");
}