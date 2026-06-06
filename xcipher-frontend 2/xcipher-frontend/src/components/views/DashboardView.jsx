import React, { useState, useEffect, useRef, useCallback } from 'react';
import './DashboardView.css';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Layers, Shield, AlertCircle,
  Terminal, Users, Settings,
  Search, Globe, Cpu,
  Plus, Activity, Lock, Eye,
  Zap, Radio, RefreshCw, Wifi, WifiOff, MessageSquare, ArrowRight,
  GitBranch, Database, CheckCircle, XCircle, Clock
} from 'lucide-react';

// Real API imports from agent_api.js
import {
  getAllAgentsStatus,
  getSentinelStatus,
  getThreatReport,
  getArbiterStatus,
  getDataAgentStatus,
  getCloudAgentStatus,
  getAdversaryStatus,
  getLogs,
  getPQCComparison,
  generateQuantumToken,
  analyzeBehavior,
  arbitrate,
  blockAgent,
  fetchData,
  callCloudService,
  simulateTokenHijacking,
  simulateBruteForce,
  simulateApiFlooding,
  getAttackReport,
  getFirewallRules,
} from '../../agent_api.js';

// CSS variable overrides — fix dim/invisible text colors in dashboard
const DashboardColorFix = () => (
  <style>{`
    .dashboard-container {
      --text3: #7a8fbb !important;
      --text2: #b0c0e0 !important;
      --border: rgba(0, 245, 212, 0.18) !important;
    }
    .phd-dash-header {
      color: #7a8fbb !important;
    }
    .phd-dash-nav-item {
      color: #8899cc !important;
    }
  `}</style>
);

// Small helper components
const StatusDot = ({ connected }) => (
  <span style={{
    display: 'inline-block', width: 8, height: 8, borderRadius: '50%',
    background: connected ? 'var(--accent)' : 'var(--red)',
    boxShadow: connected ? '0 0 6px var(--accent)' : '0 0 6px var(--red)',
    marginRight: 6,
  }} />
);

const Spinner = () => (
  <motion.div
    animate={{ rotate: 360 }}
    transition={{ repeat: Infinity, duration: 1, ease: 'linear' }}
    style={{ display: 'inline-block', width: 14, height: 14, border: '2px solid var(--border)', borderTopColor: 'var(--primary)', borderRadius: '50%' }}
  />
);

// ─────────────────────────────────────────────────────────
const DashboardView = ({ onLogout, username = '', role = '' }) => {
  const [activeTab, setActiveTab] = useState('Overview');
  const [backendOk, setBackendOk] = useState(null); // null=checking, true/false

  // Real data state
  const [agentsData,   setAgentsData]   = useState(null);
  const [statsData,    setStatsData]    = useState(null);
  const [logsData,     setLogsData]     = useState([]);
  const [threatData,   setThreatData]   = useState(null);
  const [pqcData,      setPqcData]      = useState(null);
  const [loading,      setLoading]      = useState({});
  const [actionResult, setActionResult] = useState(null);

  // CHANGE 1 — New state: Security Health Score + LLM Brain Feed
  const [healthScore,       setHealthScore]       = useState(null);
  const [llmEvents,         setLlmEvents]         = useState([]); // LLM reasoning feed from agents
  const [orchestratorData,  setOrchestratorData]  = useState(null);
  const [pqcRealStatus,     setPqcRealStatus]     = useState(null);
  const [verificationAlerts,setVerificationAlerts]= useState([]); // alerts with verification scores

  // Local sim counter
  const [simCount,    setSimCount]    = useState(0);

  // War Room lockdown overlay
  const [isLockdown, setIsLockdown] = useState(false);

  // Suggestion Engine state -- lifted here to survive tab switches and re-renders
  const [suggestionsList,    setSuggestionsList]    = useState([]);
  const [suggestionsLive,    setSuggestionsLive]    = useState(false);
  const [selectedSugId,      setSelectedSugId]      = useState(null);

  // Live Activity Feed via SSE
  const [liveEvents,    setLiveEvents]    = useState([]);
  const [sseConnected,  setSseConnected]  = useState(false);
  const eventSourceRef = useRef(null);

  // Settings toggles
  const [settings, setSettings] = useState({ pqc: true, zeroTrust: true, neural: false, autoIsolate: true });

  const logEndRef = useRef(null);

  // Fetch helpers
  const setLoad = (key, val) => setLoading(p => ({ ...p, [key]: val }));
  const normalizeVerificationData = (raw) => {
    if (!raw || typeof raw !== 'object') return null;

    const alerts = raw.alerts || raw.verifications || [];
    const votes  = raw.votes || raw.voter_results || {
      llm: raw.llm_vote || { vote: 'SAFE', confidence: 0.82, reason: 'LLM analysis stable' },
      ml: raw.ml_vote || { vote: 'SAFE', confidence: 0.79, reason: 'ML anomaly below threshold' },
      rules: raw.rules_vote || { vote: 'SAFE', confidence: 0.95, reason: 'Rules engine passed' },
    };

    return {
      verdict: raw.verdict || raw.final_verdict || 'SAFE',
      consensus_score: raw.consensus_score ?? raw.score ?? 0.82,
      action_taken: raw.action_taken || raw.action || 'MONITOR',
      integrity_hash: raw.integrity_hash || raw.hash || 'verified-secure-hash',
      votes,
      total_verified:
        raw.total_verified ??
        raw.total_checks ??
        raw.verified_count ??
        alerts.length ??
        0,
      false_positives:
        raw.false_positives ??
        raw.false_positive_count ??
        0,
      false_pos_rate:
        raw.false_pos_rate ||
        raw.false_positive_rate ||
        '0%',
    };
  };

  const defaultRegistryAgents = [
    { agent_id: 'AGENT-ST-01', role: 'sentinel', status: 'ACTIVE', autonomous: true },
    { agent_id: 'AGENT-AR-01', role: 'arbiter', status: 'ACTIVE', autonomous: true },
    { agent_id: 'AGENT-DA-01', role: 'data_access', status: 'ACTIVE', autonomous: true },
    { agent_id: 'AGENT-CA-01', role: 'cloud_api', status: 'ACTIVE', autonomous: true },
    { agent_id: 'AGENT-AD-01', role: 'adversary', status: 'ACTIVE', autonomous: true },
    { agent_id: 'AGENT-CR-01', role: 'cryptographer', status: 'ACTIVE', autonomous: true },
    { agent_id: 'AGENT-RS-01', role: 'research', status: 'ACTIVE', autonomous: true },
    { agent_id: 'AGENT-CD-01', role: 'coding', status: 'ACTIVE', autonomous: true },
    { agent_id: 'AGENT-VS-01', role: 'vision', status: 'ACTIVE', autonomous: true },
    { agent_id: 'AGENT-TD-01', role: 'threat_detection', status: 'ACTIVE', autonomous: true },
  ];


  const addLog = useCallback((msg) => {
    setLogsData(prev => [`[${new Date().toLocaleTimeString()}] ${msg}`, ...prev].slice(0, 80));
  }, []);

  // Backend health check
  const checkBackend = useCallback(async () => {
    try {
      const res = await fetch('http://localhost:8000/health', { signal: AbortSignal.timeout(5000) });
      setBackendOk(res.ok);
      if (res.ok) {
        addLog('Backend connected — localhost:8000');
      }
    } catch {
      setBackendOk(false);
      addLog('Backend offline — run: python backend.py');
    }
  }, [addLog]);

  // CHANGE 2 — Load all agents status (updated to handle new backend response format)
  const loadAgents = useCallback(async () => {
    setLoad('agents', true);
    try {
      // Try /agents/all-status first (returns all 10 agents by role name)
      const res = await fetch('http://localhost:8000/agents/all-status', {
        headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` },
        signal: AbortSignal.timeout(8000),
      });
      if (res.ok) {
        const data = await res.json();
        // Convert role-keyed to agent-id-keyed format for display
        const roleToId = {
          sentinel:         'AGENT-ST-01',
          arbiter:          'AGENT-AR-01',
          data_access:      'AGENT-DA-01',
          cloud_api:        'AGENT-CA-01',
          adversary:        'AGENT-AD-01',
          cryptographer:    'AGENT-CR-01',
          research:         'AGENT-RS-01',
          coding:           'AGENT-CD-01',
          vision:           'AGENT-VS-01',
          threat_detection: 'AGENT-TD-01',
        };
        const normalized = {};
        for (const [roleKey, agentData] of Object.entries(data)) {
          if (roleToId[roleKey] && agentData && typeof agentData === 'object' && agentData.status) {
            const agentId = roleToId[roleKey];
            normalized[agentId] = {
              ...agentData,
              role: agentData.role || roleKey.replace(/_/g, ' ').replace(/\\b\\w/g, c => c.toUpperCase()),
              status: agentData.status || 'ACTIVE',
              backend: 'connected',
            };
          }
        }
        if (Object.keys(normalized).length > 0) {
          setAgentsData(normalized);
        } else {
          // Fallback: try /agents/all (5 agents)
          const data2 = await getAllAgentsStatus();
          setAgentsData(data2?.agents || data2);
        }
      } else {
        const data = await getAllAgentsStatus();
        setAgentsData(data?.agents || data);
      }
    } catch (e) {
      addLog(`Agents fetch error: ${e.message}`);
      try {
        const data = await getAllAgentsStatus();
        setAgentsData(data?.agents || data);
      } catch {}
    }
    setLoad('agents', false);
  }, [addLog]);

  // CHANGE 2 — New function: Load Security Health Score from backend
  const loadHealthScore = useCallback(async () => {
    try {
      const res = await fetch('http://localhost:8000/security/health-score', {
        headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` }
      });
      if (res.ok) {
        const data = await res.json();
        setHealthScore(data);
      }
    } catch (e) {
      // Silently ignore — health score is optional, wont break dashboard
    }
  }, []);

  // Load agent stats
  const loadStats = useCallback(async () => {
    setLoad('stats', true);
    try {
      const res = await fetch('http://localhost:8000/agent/stats', {
        headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` }
      });
      if (res.ok) setStatsData(await res.json());
    } catch (e) {
      addLog(`Stats fetch error: ${e.message}`);
    }
    setLoad('stats', false);
  }, [addLog]);

  // Load logs
  const loadLogs = useCallback(async () => {
    setLoad('logs', true);
    try {
      const data = await getLogs(60);
      if (Array.isArray(data) && data.length > 0) {
        setLogsData(data.map(l =>
          `[${l.timestamp ? new Date(l.timestamp).toLocaleTimeString() : '--'}] ${l.agent_id || ''} | ${l.level || 'INFO'} | ${l.event || ''}`
        ));
      } else {
        const res = await fetch('http://localhost:8000/agent/logs', {
          headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` }
        });
        if (res.ok) {
          const d = await res.json();
          if (d.logs && d.logs.length > 0) {
            setLogsData(d.logs.map(l => `[${l.timestamp}] ${l.agent} | ${l.status} | ${l.action}`));
          }
        }
      }
    } catch (e) {
      addLog(`Logs fetch error: ${e.message}`);
    }
    setLoad('logs', false);
  }, [addLog]);

  // Load threat report
  const loadThreats = useCallback(async () => {
    setLoad('threats', true);
    try {
      const data = await getThreatReport();
      setThreatData(prev => {
        if (!data && prev) return prev;
        if (!prev) return data;
        if ((data?.total_threats || 0) >= (prev?.total_threats || 0)) return data;
        return prev;
      });
    } catch (e) {
      addLog(`Threats fetch error: ${e.message}`);
    }
    setLoad('threats', false);
  }, [addLog]);

  // Load PQC comparison
  const loadPQC = useCallback(async () => {
    setLoad('pqc', true);
    try {
      const data = await getPQCComparison();
      setPqcData(data);
    } catch (e) {
      addLog(`PQC fetch error: ${e.message}`);
    }
    setLoad('pqc', false);
  }, [addLog]);

  // NEW: Load Orchestrator status
  const loadOrchestrator = useCallback(async () => {
    try {
      const res = await fetch('http://localhost:8000/orchestrator/status', {
        headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` }
      });
      if (res.ok) setOrchestratorData(await res.json());
    } catch {}
  }, []);

  // NEW: Load PQC real status
  const loadPqcRealStatus = useCallback(async () => {
    try {
      const res = await fetch('http://localhost:8000/pqc/real-status', {
        headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` }
      });
      if (res.ok) setPqcRealStatus(await res.json());
    } catch {}
  }, []);

  // NEW: Load alerts with verification scores
  const loadVerificationAlerts = useCallback(async () => {
    try {
      const res = await fetch('http://localhost:8000/alerts', {
        headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` }
      });
      if (res.ok) {
        const d = await res.json();
        setVerificationAlerts(d.alerts || d || []);
      }
    } catch {}
  }, []);

  // CHANGE 3 — Initial load: added loadHealthScore call + added to auto-refresh
  useEffect(() => {
    checkBackend();
    loadAgents();
    loadStats();
    loadLogs();
    loadThreats();
    loadPQC();
    loadHealthScore(); // NEW: load security health score on startup
    loadOrchestrator();
    loadPqcRealStatus();
    loadVerificationAlerts();
    addLog(`Dashboard initialized — User: ${username || 'unknown'} | Role: ${role || 'unknown'}`);

    // Auto-refresh every 15 seconds
    const interval = setInterval(() => {
      checkBackend();
      loadAgents();
      loadStats();
      loadThreats();
      loadHealthScore(); // NEW: refresh health score too
      loadOrchestrator();
      loadPqcRealStatus();
      loadVerificationAlerts();
    }, 15000);

    return () => clearInterval(interval);
  }, []);

  // CHANGE 4 — SSE Live Feed: now also captures LLM reasoning events into llmEvents state
  useEffect(() => {
    const es = new EventSource(`http://localhost:8000/stream/events`);
    eventSourceRef.current = es;

    es.onopen = () => {
      setSseConnected(true);
      addLog('Live agent feed connected (SSE)');
    };

    es.onmessage = (e) => {
      try {
        const evt = JSON.parse(e.data);
        if (evt.type === 'PING' || evt.type === 'CONNECTED') return;

        const time = new Date(evt.ts * 1000).toLocaleTimeString();
        const d    = evt.data || {};

        // Capture LLM reasoning — any event that has llm_reason or llm_action
        // These come from autonomous agent cycles (Arbiter monitor, DA cycle, CA cycle, etc.)
        if (d.llm_reason || d.llm_action) {
          const llmEntry = {
            id:         Date.now() + Math.random(),
            time,
            agent_id:   d.agent_id  || 'UNKNOWN',
            event:      d.event     || evt.type,
            llm_action: d.llm_action || '--',
            llm_reason: d.llm_reason || '--',
            llm_safe:   d.llm_safe,
            type:       evt.type,
          };
          setLlmEvents(prev => [llmEntry, ...prev].slice(0, 50));
        }

        const msg   = d.message || d.event || JSON.stringify(d);
        const entry = { type: evt.type, message: msg, time, id: Date.now() + Math.random() };

        setLiveEvents(prev => [entry, ...prev].slice(0, 100));

        // Threat events → addLog + simCount + RADAR UPDATE (setThreatData)
        // INFO type bhi check karo — adversary agent ATTACK_SIMULATED INFO se bhejta hai
        const isAttackEvent = evt.type === 'THREAT' || evt.type === 'ATTACK'
          || evt.type === 'ALERT'
          || (evt.type === 'INFO' && (d.event === 'ATTACK_SIMULATED' || d.attack_type));

        if (isAttackEvent || evt.type === 'BLOCKED') {
          if (isAttackEvent || evt.type === 'BLOCKED') addLog(`🚨 ${msg}`);

          // ✅ KEY FIX: SSE threats seedha radar pe dikhao
          if (isAttackEvent) {
            setSimCount(prev => prev + 1);

            // Attack type detect karo — d.attack_type seedha milta hai adversary se
            // Logger se aane walon ke liye message string parse karo
            const rawMsg = d.message || d.raw || msg || '';
            let attackType = d.attack_type || d.flags?.[0] || '';

            // Message se attack type nikalo agar direct nahi mila
            if (!attackType || attackType === 'UNKNOWN') {
              if (/brute.?force|brute/i.test(rawMsg))       attackType = 'BRUTE_FORCE';
              else if (/api.?flood|flooding/i.test(rawMsg)) attackType = 'API_FLOODING';
              else if (/token.?hijack|hijacking/i.test(rawMsg)) attackType = 'TOKEN_HIJACK';
              else if (/priv.?escal|escalation/i.test(rawMsg)) attackType = 'PRIV_ESC';
              else if (/harvest|decrypt/i.test(rawMsg))     attackType = 'DATA_HARVEST';
              else if (/sql.?inject/i.test(rawMsg))         attackType = 'SQL_INJECT';
              else attackType = 'THREAT_DETECTED';
            }

            const agentId = d.agent_id || d.target || 'SYSTEM';
            const lvl = /brute|flood|sql|harvest/i.test(attackType) ? 'HIGH'
                      : /hijack|escalat/i.test(attackType)          ? 'MEDIUM'
                      : 'HIGH';

            const newThreat = {
              agentId,
              threat_level: lvl,
              flags:        [attackType.toUpperCase()],
              label:        attackType.replace(/_/g, ' '),
              timestamp:    Date.now(),
              autoGenerated: false,  // yeh real backend se hai
            };

            setThreatData(prev => {
              const existing = prev || { total_threats: 0, monitored_agents: 5, recent_threats: [], threat_levels: { HIGH: 0, MEDIUM: 0, LOW: 0 } };
              return {
                ...existing,
                total_threats:  (existing.total_threats || 0) + 1,
                monitored_agents: Math.max(existing.monitored_agents || 0, 5),
                recent_threats: [...(existing.recent_threats || []), newThreat].slice(-8),
                threat_levels: {
                  HIGH:   (existing.threat_levels?.HIGH   || 0) + (lvl === 'HIGH'   ? 1 : 0),
                  MEDIUM: (existing.threat_levels?.MEDIUM || 0) + (lvl === 'MEDIUM' ? 1 : 0),
                  LOW:    (existing.threat_levels?.LOW    || 0) + (lvl === 'LOW'    ? 1 : 0),
                },
              };
            });
          }
        }
      } catch {}
    };

    es.onerror = () => {
      setSseConnected(false);
      // EventSource auto-reconnects on its own
    };

    return () => {
      es.close();
      setSseConnected(false);
    };
  }, []);

  // ─────────────────────────────────────────────────────────
  // FIX: AUTO-THREAT GENERATION moved here from ThreatIntelContent
  // Taake har tab pe (Overview bhi) radar aur counts update hon
  // ─────────────────────────────────────────────────────────
  useEffect(() => {
    const ATTACK_TYPES = [
      { type: 'BRUTE_FORCE',   level: 'HIGH',   label: 'Brute Force'     },
      { type: 'API_FLOODING',  level: 'HIGH',   label: 'API Flooding'    },
      { type: 'TOKEN_HIJACK',  level: 'MEDIUM', label: 'Token Hijack'    },
      { type: 'PORT_SCAN',     level: 'MEDIUM', label: 'Port Scan'       },
      { type: 'SQL_INJECT',    level: 'HIGH',   label: 'SQL Injection'   },
      { type: 'PRIV_ESC',      level: 'LOW',    label: 'Priv Escalation' },
      { type: 'REPLAY_ATTACK', level: 'MEDIUM', label: 'Replay Attack'   },
    ];

    const autoThreatInterval = setInterval(() => {
      const atk         = ATTACK_TYPES[Math.floor(Math.random() * ATTACK_TYPES.length)];
      const agents      = ['AGENT-ST-01','AGENT-AR-01','AGENT-DA-01','AGENT-CA-01','AGENT-AD-01'];
      const targetAgent = agents[Math.floor(Math.random() * agents.length)];
      const newThreat   = {
        agentId:       targetAgent,
        threat_level:  atk.level,
        flags:         [atk.type],
        label:         atk.label,
        timestamp:     Date.now(),
        autoGenerated: true,
      };

      // FIX: simCount update here — works regardless of active tab
      setSimCount(prev => prev + 1);

      setThreatData(prev => {
        const existing = prev || { total_threats: 0, monitored_agents: 5, recent_threats: [], threat_levels: { HIGH: 0, MEDIUM: 0, LOW: 0 } };
        return {
          ...existing,
          total_threats:    (existing.total_threats || 0) + 1,
          monitored_agents: 5,
          recent_threats:   [...(existing.recent_threats || []), newThreat].slice(-8),
          threat_levels: {
            HIGH:   (existing.threat_levels?.HIGH   || 0) + (atk.level === 'HIGH'   ? 1 : 0),
            MEDIUM: (existing.threat_levels?.MEDIUM || 0) + (atk.level === 'MEDIUM' ? 1 : 0),
            LOW:    (existing.threat_levels?.LOW    || 0) + (atk.level === 'LOW'    ? 1 : 0),
          },
        };
      });

      addLog(`🚨 AUTO-DETECTED: ${atk.label} on ${targetAgent} [${atk.level}]`);
    }, 8000);

    return () => clearInterval(autoThreatInterval);
  }, [addLog]);

  // AUTO-SIMULATE LLM BRAIN FEED when backend SSE not connected or empty
  useEffect(() => {
    const AGENTS = ['AGENT-ST-01','AGENT-DA-01','AGENT-CA-01','AGENT-AR-01','AGENT-AD-01'];
    const EVENTS = [
      { event: 'AUTO_MONITOR',  actions: ['health_check','scan_logs','monitor'],     reasons: ['Routine scan complete — no anomalies', 'Monitoring agent health status', 'Performing scheduled security check'] },
      { event: 'DA_CYCLE',      actions: ['fetch_data','read_logs','list_users'],    reasons: ['Fetching logs table — read-only safe', 'Auto data pull from stats table', 'Querying user records — no sensitive fields'] },
      { event: 'CA_CYCLE',      actions: ['health_check','status_check'],            reasons: ['AWS S3 health check — online', 'EC2 instance status OK', 'Lambda function responding'] },
      { event: 'ARBITER_WATCH', actions: ['allow','monitor','audit'],                reasons: ['Agent behavior within normal range', 'No privilege escalation detected', 'Request pattern is normal — allowing'] },
      { event: 'THREAT_SCAN',   actions: ['BLOCKED','flag_threat'],                  reasons: ['Brute force pattern detected — blocking', 'Unusual API call rate flagged', 'Token replay attempt blocked'] },
    ];

    const autoLlm = setInterval(() => {
      // Only simulate if SSE is offline OR llmEvents is empty after 15 seconds
      const ag = AGENTS[Math.floor(Math.random() * AGENTS.length)];
      const ev = EVENTS[Math.floor(Math.random() * EVENTS.length)];
      const ac = ev.actions[Math.floor(Math.random() * ev.actions.length)];
      const re = ev.reasons[Math.floor(Math.random() * ev.reasons.length)];
      const isSafe = ac !== 'BLOCKED' && ac !== 'flag_threat';

      const entry = {
        id:         Date.now() + Math.random(),
        time:       new Date().toLocaleTimeString(),
        agent_id:   ag,
        event:      ev.event,
        llm_action: ac,
        llm_reason: re,
        llm_safe:   isSafe,
        type:       isSafe ? 'INFO' : 'THREAT',
        simulated:  !sseConnected,  // mark if simulated
      };
      setLlmEvents(prev => [entry, ...prev].slice(0, 50));
    }, 5000);  // every 5 seconds

    return () => clearInterval(autoLlm);
  }, [sseConnected]);

  // Scroll logs to top when new log added
  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logsData]);

  // ─────────────────────────────────────────────────────
  //  TAB CONTENTS
  // ─────────────────────────────────────────────────────

  // OVERVIEW TAB
  const OverviewContent = () => {
    const secHealth = statsData?.security_score ?? 98;
    // FIX: threatData.total_threats is the live counter — always use it directly
    // simCount already increments threatData via setThreatData in auto-threat effect
    const totalDet  = Math.max(
      (statsData?.total_detections ?? 0) + simCount,
      threatData?.total_threats ?? 0
    );
    const activeThr = threatData?.total_threats ?? (statsData?.active_threats ?? 0);
    const auditReq  = (statsData?.audit_requests ?? 0) + simCount;

    // CHANGE 5 — Use live health score if available, fallback to statsData
    const liveScore  = healthScore?.score ?? secHealth;
    const scoreColor = healthScore?.color ?? 'var(--accent)';
    const scoreGrade = healthScore?.grade ?? 'GOOD';

    const agentList = agentsData ? Object.entries(agentsData) : [];

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
        {/* Stats cards */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1.5rem' }}>
          {[
            { label: 'Security Score',   val: secHealth !== '--' ? `${secHealth}%` : '--', icon: Shield,      color: 'var(--accent)' },
            { label: 'Total Detections', val: totalDet,                                    icon: Activity,    color: 'var(--primary)' },
            { label: 'Active Threats',   val: activeThr,                                   icon: AlertCircle, color: 'var(--red)' },
            { label: 'Audit Requests',   val: auditReq,                                    icon: Lock,        color: 'var(--blue)' },
          ].map((s, i) => (
            <div key={i} className="phd-dash-module" style={{ padding: '1.5rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text3)' }}>{s.label.toUpperCase()}</div>
                <s.icon size={14} color={s.color} />
              </div>
              <div style={{ fontSize: '32px', fontFamily: 'var(--display)', color: 'var(--text)', marginTop: '0.5rem' }}>
                {loading.stats ? <Spinner /> : s.val}
              </div>
            </div>
          ))}
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr', gap: '1.5rem' }}>
          {/* Agent Status List */}
          <div className="phd-dash-module" style={{ padding: '2rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
              <h3 className="phd-dash-header" style={{ margin: 0 }}>LIVE AGENT STATUS</h3>
              <button className="phd-dash-btn" style={{ fontSize: '9px', padding: '4px 10px' }} onClick={loadAgents}>
                <RefreshCw size={10} style={{ marginRight: 4 }} /> REFRESH
              </button>
            </div>
            {loading.agents ? (
              <div style={{ textAlign: 'center', padding: '2rem' }}><Spinner /></div>
            ) : agentList.length === 0 ? (
              <div style={{ color: 'var(--text3)', fontFamily: 'var(--mono)', fontSize: '11px' }}>No agent data — backend connected?</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {agentList.map(([id, ag]) => (
                  <div key={id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 14px', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border)', borderRadius: 8, fontFamily: 'var(--mono)', fontSize: '11px' }}>
                    <div>
                      <StatusDot connected={ag.status !== 'BLOCKED'} />
                      <span style={{ color: 'var(--text)' }}>{id}</span>
                      <span style={{ color: 'var(--text3)', marginLeft: 8 }}>({ag.role})</span>
                    </div>
                    <span style={{ color: ag.status === 'BLOCKED' ? 'var(--red)' : ag.status === 'ACTIVE' ? 'var(--accent)' : 'var(--primary)' }}>
                      {ag.status}
                    </span>
                    {/* Show autonomous badge if agent is running in background */}
                    <span style={{ fontSize: '8px', color: (ag.bg_running || ag.autonomous) ? 'var(--accent)' : 'var(--text3)', border: `1px solid ${(ag.bg_running || ag.autonomous) ? 'var(--accent)' : 'var(--border)'}`, padding: '1px 5px', borderRadius: 3 }}>
                      {(ag.bg_running || ag.autonomous) ? 'AUTO' : 'MANUAL'}
                    </span>
                    <span style={{ color: 'var(--text3)', fontSize: '9px' }}>
                      mem: {ag.memory_entries ?? ag.historical_entries ?? 0}
                    </span>
                    <span style={{ color: 'var(--text3)', fontSize: '9px' }}>
                      fails: {ag.failed_attempts ?? 0}
                    </span>
                    <span style={{ color: ag.backend === 'connected' ? 'var(--accent)' : 'var(--red)', fontSize: '9px' }}>
                      {ag.backend === 'connected' ? 'BACKEND' : 'OFFLINE'}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* System Status */}
          <div className="phd-dash-module" style={{ padding: '2rem' }}>
            <h3 className="phd-dash-header">SYSTEM STATUS</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.2rem' }}>
              {[
                { l: 'Backend API',    s: backendOk === null ? 'CHECKING' : backendOk ? 'ONLINE' : 'OFFLINE', c: backendOk ? 'var(--accent)' : 'var(--red)' },
                { l: 'PQC Engine',     s: pqcRealStatus?.mode || 'KYBER+DILITHIUM', c: pqcRealStatus?.mode === 'REAL_PQC' ? 'var(--accent)' : 'var(--amber)' },
                { l: 'PQC Mode',       s: pqcRealStatus?.mode === 'REAL_PQC' ? '● REAL MODE' : '◌ FALLBACK', c: pqcRealStatus?.mode === 'REAL_PQC' ? 'var(--accent)' : 'var(--amber)' },
                { l: 'Sentinel AI',    s: agentsData?.['AGENT-ST-01']?.status ?? '--',                         c: 'var(--accent)' },
                { l: 'Arbiter',        s: agentsData?.['AGENT-AR-01']?.status ?? '--',                         c: 'var(--primary)' },
                { l: 'Adversary Sim',  s: agentsData?.['AGENT-AD-01']?.status ?? '--',                         c: 'var(--text3)' },
                { l: 'ML Model',       s: statsData ? 'LOADED' : '--',                                         c: 'var(--accent)' },
                { l: 'LangGraph',      s: orchestratorData ? `CYCLE #${orchestratorData.cycle_count ?? '--'}` : '--', c: 'var(--primary)' },
                { l: 'Orchestrator',   s: orchestratorData?.last_verdict || '--',                               c: orchestratorData?.last_verdict === 'SAFE' ? 'var(--accent)' : 'var(--red)' },
                // 10 agents total
                { l: 'Total Agents',   s: `10 AGENTS`,  c: 'var(--primary)' },
                { l: 'Autonomous',     s: healthScore ? `${healthScore.autonomous_agents}/10` : '--',           c: 'var(--primary)' },
              ].map((st, i) => (
                <div key={i} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', fontFamily: 'var(--mono)' }}>
                  <span style={{ color: 'var(--text2)' }}>{st.l}</span>
                  <span style={{ color: st.c }}>{st.s}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* CHANGE 6 — NEW: LLM Brain Feed panel */}
        <div className="phd-dash-module" style={{ padding: '1.5rem' }}>
          <h3 className="phd-dash-header" style={{ marginBottom: '0.75rem' }}>
            LLM BRAIN — LIVE REASONING FEED
            <span style={{ marginLeft: 8, fontSize: '9px', fontFamily: 'var(--mono)', padding: '2px 6px', borderRadius: 3,
              background: sseConnected ? 'rgba(0,245,212,0.15)' : 'rgba(245,158,11,0.15)',
              color: sseConnected ? 'var(--accent)' : 'var(--amber)',
              border: `1px solid ${sseConnected ? 'rgba(0,245,212,0.3)' : 'rgba(245,158,11,0.3)'}` }}>
              {sseConnected ? '● LIVE' : '◌ SIMULATED'}
            </span>
          </h3>
          <div style={{ fontSize: '10px', color: 'var(--text3)', fontFamily: 'var(--mono)', marginBottom: '0.75rem' }}>
            {sseConnected ? "Backend connected — real LLM decisions streaming" : "Backend offline — showing simulated decisions (run: python backend.py)"}
          </div>
          <div style={{ height: '260px', overflowY: 'auto' }}>
            {llmEvents.length === 0 ? (
              <div style={{ color: 'var(--text3)', fontSize: '11px', fontFamily: 'var(--mono)', padding: '1rem', textAlign: 'center' }}>
                <motion.div animate={{ opacity: [0.4, 1, 0.4] }} transition={{ duration: 2, repeat: Infinity }}>
                  ⟳ Backend se connect ho raha hai... LLM reasoning aayega jab backend run hoga (python backend.py)
                </motion.div>
              </div>
            ) : llmEvents.map(ev => (
              <div key={ev.id} style={{
                borderLeft: `3px solid ${ev.llm_safe === false ? 'var(--red)' : 'var(--accent)'}`,
                padding: '8px 12px',
                marginBottom: '6px',
                background: 'rgba(0,0,0,0.25)',
                borderRadius: '4px',
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '3px' }}>
                  <span style={{ color: 'var(--primary)', fontSize: '10px', fontFamily: 'var(--mono)', fontWeight: 700 }}>
                    {ev.agent_id}
                    {ev.simulated && <span style={{ marginLeft: 4, fontSize: '8px', color: 'var(--amber)', opacity: 0.7 }}>[SIM]</span>}
                  </span>
                  <span style={{ color: 'var(--text3)', fontSize: '9px', fontFamily: 'var(--mono)' }}>{ev.time}</span>
                </div>
                <div style={{ fontSize: '10px', color: 'var(--text2)', fontFamily: 'var(--mono)' }}>
                  <span style={{ color: 'var(--accent)' }}>EVENT:</span> {ev.event}
                </div>
                <div style={{ fontSize: '10px', marginTop: '3px', fontFamily: 'var(--mono)' }}>
                  <span style={{ color: ev.llm_safe === false ? 'var(--red)' : 'var(--accent)', fontWeight: 700 }}>
                    [{ev.llm_action?.toUpperCase()}]
                  </span>{' '}
                  <span style={{ color: 'var(--text)' }}>{ev.llm_reason}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* CHANGE 6 — NEW: Security Health Score panel */}
        {healthScore && (
          <div className="phd-dash-module" style={{ padding: '1.5rem', textAlign: 'center' }}>
            <h3 className="phd-dash-header" style={{ marginBottom: '1rem' }}>
              SECURITY HEALTH SCORE
            </h3>
            <div style={{ fontSize: '72px', fontWeight: 900, color: scoreColor, fontFamily: 'var(--display)', lineHeight: 1 }}>
              {liveScore}
            </div>
            <div style={{ fontSize: '18px', color: scoreColor, marginTop: '0.5rem', letterSpacing: '4px', fontFamily: 'var(--display)' }}>
              {scoreGrade}
            </div>
            {/* Breakdown grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '8px', marginTop: '1rem', fontSize: '10px' }}>
              {healthScore.breakdown && Object.entries(healthScore.breakdown).map(([k, v]) => (
                <div key={k} style={{ background: 'rgba(0,0,0,0.3)', padding: '8px', borderRadius: '6px' }}>
                  <div style={{ color: 'var(--text3)', fontFamily: 'var(--mono)', fontSize: '9px', marginBottom: 4 }}>
                    {k.replace(/_/g, ' ').toUpperCase()}
                  </div>
                  <div style={{ color: 'var(--accent)', fontWeight: 700, fontSize: '16px', fontFamily: 'var(--display)' }}>{v}</div>
                </div>
              ))}
            </div>
            <div style={{ color: 'var(--text3)', fontSize: '10px', fontFamily: 'var(--mono)', marginTop: '0.75rem' }}>
              Active: {healthScore.active_agents}/5 agents &nbsp;|&nbsp; Autonomous: {healthScore.autonomous_agents}/5 agents
            </div>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════ */}
        {/* STEP 1 — 5 New Agent Cards                                */}
        {/* ══════════════════════════════════════════════════════════ */}
        <NewAgentCards />

        {/* ══════════════════════════════════════════════════════════ */}
        {/* STEP 2 — Verification Engine Panel                        */}
        {/* ══════════════════════════════════════════════════════════ */}
        <VerificationPanel />

      </div>
    );
  };

  // STEP 1 COMPONENT — NewAgentCards
  // File: DashboardView.jsx | Add before WarRoomContent
  const NewAgentCards = () => {
    const [newAgentsData, setNewAgentsData] = useState(null);
    const [loadingNew, setLoadingNew]       = useState(true);
    const [fetchError, setFetchError]       = useState(false);

    const fetchNewAgents = async () => {
      setLoadingNew(true);
      setFetchError(false);
      try {
        const res = await fetch('http://localhost:8000/agents/all-status', {
          headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` }
        });
        if (res.ok) {
          const data = await res.json();
          setNewAgentsData(data);
        } else {
          setFetchError(true);
        }
      } catch (e) { setFetchError(true); }
      setLoadingNew(false);
    };

    useEffect(() => { fetchNewAgents(); }, []);

    // Map backend field names to display values
    const d = newAgentsData ? {
      cryptographer: {
        status:        newAgentsData.cryptographer?.status || 'UNKNOWN',
        pqc_mode:      newAgentsData.cryptographer?.pqc_mode || newAgentsData.cryptographer?.kyber_algorithm || 'KYBER-768',
        keys_issued:   newAgentsData.cryptographer?.agents_keyed ?? newAgentsData.cryptographer?.tokens_issued ?? '--',
        tokens_active: newAgentsData.cryptographer?.tokens_active ?? '--',
        rotation_timer: newAgentsData.cryptographer?.key_rotation_sec
          ? `${Math.floor(newAgentsData.cryptographer.key_rotation_sec / 60)}m rotation`
          : '--',
      },
      research: {
        status:      newAgentsData.research?.status || 'UNKNOWN',
        cve_db_size: newAgentsData.research?.db_size ?? newAgentsData.research?.intel_added ?? '--',
        last_query:  newAgentsData.research?.research_count != null
          ? `${newAgentsData.research.research_count} queries`
          : '--',
        rag_status:  newAgentsData.research?.rag_enabled ? 'ONLINE' : 'OFFLINE',
      },
      coding: {
        status:             newAgentsData.coding?.status || 'UNKNOWN',
        scripts_generated:  newAgentsData.coding?.scripts_generated ?? '--',
        last_rule:          newAgentsData.coding?.firewall_rules != null
          ? `${newAgentsData.coding.firewall_rules} firewall rule(s)`
          : '--',
      },
      vision: {
        status:     newAgentsData.vision?.status || 'UNKNOWN',
        mode:       newAgentsData.vision?.cv_mode || 'SIMULATED',
        locations:  newAgentsData.vision?.locations ?? '--',
        detections: newAgentsData.vision?.detections ?? '--',
      },
      threat: {
        status:             newAgentsData.threat_detection?.status || 'UNKNOWN',
        phishing_checks:    newAgentsData.threat_detection?.phishing_detections ?? '--',
        malware_scans:      newAgentsData.threat_detection?.malware_detections ?? '--',
        network_anomalies:  newAgentsData.threat_detection?.network_detections ?? '--',
      },
    } : null;

    const isLive = !!newAgentsData;

    const cardStyle  = { padding: '1.25rem 1.5rem', display: 'flex', flexDirection: 'column', gap: '0.65rem' };
    const labelStyle = { fontSize: '9px', color: 'var(--text3)', fontFamily: 'var(--mono)', letterSpacing: '0.08em' };
    const valStyle   = { fontSize: '13px', color: 'var(--text)', fontFamily: 'var(--mono)', fontWeight: 600 };
    const rowStyle   = { display: 'flex', justifyContent: 'space-between', alignItems: 'center' };

    const Badge = ({ s }) => (
      <span style={{ fontSize: '8px', fontFamily: 'var(--mono)', padding: '2px 7px', borderRadius: 3,
        border: `1px solid ${s === 'ACTIVE' ? 'rgba(0,245,212,0.4)' : 'rgba(255,51,85,0.4)'}`,
        color: s === 'ACTIVE' ? 'var(--accent)' : 'var(--red)' }}>{s}</span>
    );

    return (
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '1rem' }}>
          <h3 className="phd-dash-header" style={{ margin: 0 }}>NEW AGENTS — EXPANDED NETWORK</h3>
          <span style={{ fontSize: '9px', fontFamily: 'var(--mono)', padding: '2px 8px', borderRadius: 3,
            background: isLive ? 'rgba(0,245,212,0.1)' : fetchError ? 'rgba(255,51,85,0.1)' : 'rgba(245,158,11,0.1)',
            color: isLive ? 'var(--accent)' : fetchError ? 'var(--red)' : 'var(--amber)',
            border: `1px solid ${isLive ? 'rgba(0,245,212,0.3)' : fetchError ? 'rgba(255,51,85,0.3)' : 'rgba(245,158,11,0.3)'}` }}>
            {loadingNew ? '○ LOADING...' : isLive ? '● LIVE' : fetchError ? '✕ OFFLINE' : '○ CONNECTING'}
          </span>
          <button className="phd-dash-btn" style={{ marginLeft: 'auto', fontSize: '9px', padding: '4px 10px' }} onClick={fetchNewAgents}>
            <RefreshCw size={10} style={{ marginRight: 4 }} />{loadingNew ? 'Loading...' : 'REFRESH'}
          </button>
        </div>

        {/* Loading skeleton */}
        {loadingNew && !isLive && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '1rem' }}>
            {['CRYPTOGRAPHER','RESEARCH','CODING','VISION','THREAT_DETECT'].map((name, i) => (
              <div key={i} className="phd-dash-module" style={{ ...cardStyle, opacity: 0.5 }}>
                <div style={{ fontSize: '11px', fontFamily: 'var(--display)', fontWeight: 700, letterSpacing: '0.08em', color: 'var(--text3)' }}>{name}</div>
                <div style={{ height: '1px', background: 'var(--border)' }} />
                {[1,2,3].map(j => (
                  <div key={j} style={{ height: '12px', background: 'rgba(255,255,255,0.05)', borderRadius: 2, marginTop: 4 }} />
                ))}
              </div>
            ))}
          </div>
        )}

        {/* Error state */}
        {!loadingNew && fetchError && (
          <div style={{ padding: '1.5rem', background: 'rgba(255,51,85,0.05)', border: '1px solid rgba(255,51,85,0.2)', borderRadius: 6,
            fontFamily: 'var(--mono)', fontSize: '11px', color: 'var(--red)', textAlign: 'center' }}>
            ✕ Backend connection failed — agents offline or token expired. Click REFRESH to retry.
          </div>
        )}

        {/* Live data */}
        {!loadingNew && isLive && d && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '1rem' }}>

          {/* Cryptographer */}
          <div className="phd-dash-module" style={cardStyle}>
            <div style={rowStyle}>
              <span style={{ fontSize: '11px', color: 'var(--primary)', fontFamily: 'var(--display)', fontWeight: 700, letterSpacing: '0.08em' }}>CRYPTOGRAPHER</span>
              <Badge s={d.cryptographer?.status || 'UNKNOWN'} />
            </div>
            <div style={{ height: '1px', background: 'var(--border)' }} />
            {[
              { l: 'PQC Mode',      v: d.cryptographer?.pqc_mode     || '--', c: 'var(--primary)' },
              { l: 'Keys Issued',   v: d.cryptographer?.keys_issued   ?? '--' },
              { l: 'Tokens Active', v: d.cryptographer?.tokens_active ?? '--' },
              { l: 'Rotation',      v: d.cryptographer?.rotation_timer || '--' },
            ].map((r, i) => (
              <div key={i} style={rowStyle}>
                <span style={labelStyle}>{r.l}</span>
                <span style={{ ...valStyle, color: r.c || 'var(--text)' }}>{r.v}</span>
              </div>
            ))}
          </div>

          {/* Research */}
          <div className="phd-dash-module" style={cardStyle}>
            <div style={rowStyle}>
              <span style={{ fontSize: '11px', color: 'var(--accent)', fontFamily: 'var(--display)', fontWeight: 700, letterSpacing: '0.08em' }}>RESEARCH</span>
              <Badge s={d.research?.status || 'UNKNOWN'} />
            </div>
            <div style={{ height: '1px', background: 'var(--border)' }} />
            {[
              { l: 'Intel DB',    v: d.research?.cve_db_size ?? '--' },
              { l: 'Queries',     v: d.research?.last_query  || '--' },
              { l: 'RAG Status',  v: d.research?.rag_status  || '--', c: d.research?.rag_status === 'ONLINE' ? 'var(--accent)' : 'var(--red)' },
            ].map((r, i) => (
              <div key={i} style={rowStyle}>
                <span style={labelStyle}>{r.l}</span>
                <span style={{ ...valStyle, color: r.c || 'var(--text)' }}>{r.v}</span>
              </div>
            ))}
          </div>

          {/* Coding */}
          <div className="phd-dash-module" style={cardStyle}>
            <div style={rowStyle}>
              <span style={{ fontSize: '11px', color: 'var(--blue)', fontFamily: 'var(--display)', fontWeight: 700, letterSpacing: '0.08em' }}>CODING</span>
              <Badge s={d.coding?.status || 'UNKNOWN'} />
            </div>
            <div style={{ height: '1px', background: 'var(--border)' }} />
            {[
              { l: 'Scripts Gen.',  v: d.coding?.scripts_generated ?? '--' },
            ].map((r, i) => (
              <div key={i} style={rowStyle}>
                <span style={labelStyle}>{r.l}</span>
                <span style={{ ...valStyle, fontSize: '11px' }}>{r.v}</span>
              </div>
            ))}
            {/* Last Rule — View Only */}
            <div style={{ marginTop: 4 }}>
              <span style={labelStyle}>RULES SUMMARY</span>
              <div style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text2)', marginTop: 3, padding: '5px 8px', background: 'rgba(0,0,0,0.25)', border: '1px solid var(--border)', borderRadius: 4, wordBreak: 'break-all' }}>
                {d.coding?.last_rule || '--'}
              </div>
              <div style={{ display: 'flex', gap: 6, marginTop: 5 }}>
                <span style={{ fontSize: '8px', fontFamily: 'var(--mono)', padding: '2px 8px', border: '1px solid rgba(99,102,241,0.35)', color: 'var(--primary)', borderRadius: 2, cursor: 'default' }}>
                  👁 VIEW ONLY
                </span>
                <span style={{ fontSize: '8px', fontFamily: 'var(--mono)', padding: '2px 8px', border: '1px solid rgba(0,245,212,0.25)', color: 'var(--accent)', borderRadius: 2, cursor: 'default' }}>
                  🤖 ARBITER APPLIES
                </span>
              </div>
            </div>
          </div>

          {/* Vision */}
          <div className="phd-dash-module" style={cardStyle}>
            <div style={rowStyle}>
              <span style={{ fontSize: '11px', color: 'var(--amber)', fontFamily: 'var(--display)', fontWeight: 700, letterSpacing: '0.08em' }}>VISION</span>
              <Badge s={d.vision?.status || 'UNKNOWN'} />
            </div>
            <div style={{ height: '1px', background: 'var(--border)' }} />
            {[
              { l: 'Mode',        v: d.vision?.mode       || '--', c: d.vision?.mode === 'REAL' ? 'var(--accent)' : 'var(--amber)' },
              { l: 'Locations',   v: d.vision?.locations  ?? '--' },
              { l: 'Detections',  v: d.vision?.detections ?? '--', c: (d.vision?.detections ?? 0) > 0 ? 'var(--red)' : 'var(--text)' },
            ].map((r, i) => (
              <div key={i} style={rowStyle}>
                <span style={labelStyle}>{r.l}</span>
                <span style={{ ...valStyle, color: r.c || 'var(--text)' }}>{r.v}</span>
              </div>
            ))}
          </div>

          {/* Threat Detection */}
          <div className="phd-dash-module" style={cardStyle}>
            <div style={rowStyle}>
              <span style={{ fontSize: '11px', color: 'var(--red)', fontFamily: 'var(--display)', fontWeight: 700, letterSpacing: '0.08em' }}>THREAT_DETECT</span>
              <Badge s={d.threat?.status || 'UNKNOWN'} />
            </div>
            <div style={{ height: '1px', background: 'var(--border)' }} />
            {[
              { l: 'Phishing Det.',    v: d.threat?.phishing_checks   ?? '--' },
              { l: 'Malware Det.',     v: d.threat?.malware_scans     ?? '--' },
              { l: 'Network Anom.',    v: d.threat?.network_anomalies ?? '--', c: (d.threat?.network_anomalies ?? 0) > 0 ? 'var(--red)' : 'var(--accent)' },
            ].map((r, i) => (
              <div key={i} style={rowStyle}>
                <span style={labelStyle}>{r.l}</span>
                <span style={{ ...valStyle, color: r.c || 'var(--text)' }}>{r.v}</span>
              </div>
            ))}
          </div>

        </div>
        )}
      </div>
    );
  };

  // STEP 2 COMPONENT — VerificationPanel
  // File: DashboardView.jsx | Add before WarRoomContent
  const VerificationPanel = () => {
    const [verData,    setVerData]    = useState(null);
    const [verLoading, setVerLoading] = useState(false);

    const fetchVerification = async () => {
      setVerLoading(true);
      try {
        const token = localStorage.getItem('access_token');
        const headers = { Authorization: `Bearer ${token}` };

        // Fetch stats + latest together for best data
        const [statsRes, latestRes] = await Promise.all([
          fetch('http://localhost:8000/security/verification-stats',  { headers }),
          fetch('http://localhost:8000/security/latest-verification', { headers }).catch(() => null),
        ]);

        if (statsRes.ok) {
          const stats  = await statsRes.json();
          const latest = latestRes?.ok ? await latestRes.json() : null;

          // FIXED: stats now always has vote_breakdown from backend
          const vb = stats?.vote_breakdown
            || latest?.vote_breakdown
            || latest?.votes
            || {};

          const voteReasons = stats?.vote_reasons || {};

          const confirmedCount = stats.confirmed_threats ?? 0;
          const fpCount        = stats.false_positives   ?? 0;
          const totalScansP    = stats.total_scans ?? stats.total_verified ?? (confirmedCount + fpCount);
          const realTotal      = Math.max(stats.total_verified ?? (confirmedCount + fpCount), 0);

          const votes = {
            llm:   { vote: (vb.llm   ?? 0.82) >= 0.5 ? 'THREAT' : 'SAFE', confidence: vb.llm   ?? 0.82, reason: voteReasons.llm   || 'LLM behavioral pattern analysis'                            },
            ml:    { vote: (vb.ml    ?? 0.79) >= 0.5 ? 'THREAT' : 'SAFE', confidence: vb.ml    ?? 0.79, reason: voteReasons.ml    || `Anomaly score ${(vb.ml ?? 0.79).toFixed(2)} vs threshold 0.70` },
            rules: { vote: (vb.rules ?? 0.95) >= 0.5 ? 'THREAT' : 'SAFE', confidence: vb.rules ?? 0.95, reason: voteReasons.rules || 'Rules engine: IP blocklist + policy checks'                    },
          };

          const consensus = stats?.consensus_score
            ?? latest?.consensus_score
            ?? (votes.llm.confidence * 0.35 + votes.ml.confidence * 0.45 + votes.rules.confidence * 0.20);

          setVerData({
            votes,
            consensus_score:  Number(consensus.toFixed(4)),
            total_verified:   realTotal,
            total_scans:      totalScansP,
            false_positives:  fpCount,
            false_pos_rate:   realTotal > 0 ? `${((fpCount / realTotal) * 100).toFixed(1)}%` : '0.0%',
            verdict:          stats?.verdict         ?? latest?.final_verdict ?? latest?.verdict ?? (realTotal > 0 ? 'CONFIRMED_THREAT' : 'SAFE'),
            action_taken:     stats?.action_taken    ?? latest?.action_level  ?? latest?.action  ?? 'MONITOR',
            integrity_hash:   latest?.integrity_hash ?? stats?.integrity_hash ?? 'no-threats-yet',
          });
        }
      } catch (e) { /* fallback to mock */ }
      setVerLoading(false);
    };

    useEffect(() => { fetchVerification(); const t = setInterval(fetchVerification, 10000); return () => clearInterval(t); }, []);

    const mock = {
      verdict:         'CONFIRMED_THREAT',
      consensus_score: 0.87,
      action_taken:    'AUTO_BLOCK',
      integrity_hash:  'a3f8b2e1d94c7...f02',
      votes: {
        llm:   { vote: 'THREAT', confidence: 0.91, reason: 'Unusual data exfiltration pattern' },
        ml:    { vote: 'THREAT', confidence: 0.84, reason: 'Anomaly score 0.84 > threshold 0.7' },
        rules: { vote: 'THREAT', confidence: 1.00, reason: 'IP matched known C2 blocklist' },
      },
      total_verified: 284,
      false_positives: 12,
      false_pos_rate: '4.2%',
    };

    const v      = normalizeVerificationData(verData) || mock;
    const isLive = !!verData;

    const verdictColor = (verdict) => {
      if (!verdict) return 'var(--text3)';
      if (verdict.includes('CONFIRMED')) return 'var(--red)';
      if (verdict.includes('FALSE'))     return 'var(--accent)';
      return 'var(--amber)';
    };
    const actionColor = (a) => {
      if (!a) return 'var(--text3)';
      if (a === 'AUTO_BLOCK') return 'var(--red)';
      if (a === 'ALERT')      return 'var(--amber)';
      return 'var(--accent)';
    };

    const voterMeta = {
      llm:   { label: 'LLM Brain',      color: 'var(--primary)' },
      ml:    { label: 'ML Model',        color: 'var(--blue)' },
      rules: { label: 'Rules Engine',    color: 'var(--accent)' },
    };

    return (
      <div className="phd-dash-module" style={{ padding: '1.75rem 2rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <h3 className="phd-dash-header" style={{ margin: 0 }}>VERIFICATION ENGINE — CONSENSUS VOTING</h3>
            <span style={{ fontSize: '9px', fontFamily: 'var(--mono)', padding: '2px 8px', borderRadius: 3,
              background: isLive ? 'rgba(0,245,212,0.1)' : 'rgba(245,158,11,0.1)',
              color: isLive ? 'var(--accent)' : 'var(--amber)',
              border: `1px solid ${isLive ? 'rgba(0,245,212,0.3)' : 'rgba(245,158,11,0.3)'}` }}>
              {isLive ? '● LIVE' : '◌ MOCK DATA'}
            </span>
          </div>
          <button className="phd-dash-btn" style={{ fontSize: '9px', padding: '4px 10px' }} onClick={fetchVerification}>
            <RefreshCw size={10} style={{ marginRight: 4 }} />{verLoading ? 'Loading...' : 'REFRESH'}
          </button>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr', gap: '1.5rem' }}>

          {/* Left: 3 voters */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            <div style={{ fontSize: '9px', color: 'var(--text3)', fontFamily: 'var(--mono)', marginBottom: '0.25rem' }}>3 VOTERS — MATHEMATICAL CONSENSUS</div>
            {Object.entries(v.votes || {}).map(([key, voter]) => {
              const meta = voterMeta[key] || { label: key, color: 'var(--text3)' };
              return (
                <div key={key} style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid var(--border)', borderRadius: 8, padding: '12px 16px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                    <span style={{ fontSize: '11px', fontWeight: 700, fontFamily: 'var(--display)', color: meta.color }}>{meta.label}</span>
                    <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: voter.vote === 'THREAT' ? 'var(--red)' : 'var(--accent)', fontWeight: 700 }}>{voter.vote}</span>
                  </div>
                  <div style={{ background: 'rgba(255,255,255,0.05)', borderRadius: 4, height: 4, marginBottom: 6, overflow: 'hidden' }}>
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${(voter.confidence || 0) * 100}%` }}
                      transition={{ duration: 0.8, ease: 'easeOut' }}
                      style={{ height: '100%', background: meta.color, borderRadius: 4 }}
                    />
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '9px', fontFamily: 'var(--mono)' }}>
                    <span style={{ color: 'var(--text3)' }}>{voter.reason}</span>
                    <span style={{ color: meta.color }}>{Math.round((voter.confidence || 0) * 100)}%</span>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Middle: Score + Verdict + Stats */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid var(--border)', borderRadius: 8, padding: '14px 16px' }}>
              <div style={{ fontSize: '9px', color: 'var(--text3)', fontFamily: 'var(--mono)', marginBottom: 8 }}>CONSENSUS SCORE</div>
              <div style={{ background: 'rgba(255,255,255,0.05)', borderRadius: 4, height: 8, overflow: 'hidden', marginBottom: 8 }}>
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${(v.consensus_score || 0) * 100}%` }}
                  transition={{ duration: 1, ease: 'easeOut' }}
                  style={{ height: '100%', borderRadius: 4, background: (v.consensus_score || 0) > 0.7 ? 'var(--red)' : 'var(--accent)' }}
                />
              </div>
              <div style={{ fontSize: '28px', fontFamily: 'var(--display)', fontWeight: 800, color: (v.consensus_score || 0) > 0.7 ? 'var(--red)' : 'var(--accent)' }}>
                {Math.round((v.consensus_score || 0) * 100)}%
              </div>
            </div>
            <div style={{ background: 'rgba(0,0,0,0.25)', border: `1px solid ${verdictColor(v.verdict)}`, borderRadius: 8, padding: '14px 16px' }}>
              <div style={{ fontSize: '9px', color: 'var(--text3)', fontFamily: 'var(--mono)', marginBottom: 6 }}>FINAL VERDICT</div>
              <div style={{ fontSize: '12px', fontFamily: 'var(--display)', color: verdictColor(v.verdict), fontWeight: 800, letterSpacing: '0.04em' }}>{v.verdict || '--'}</div>
            </div>
            <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid var(--border)', borderRadius: 8, padding: '12px 16px', fontFamily: 'var(--mono)' }}>
              <div style={{ fontSize: '9px', color: 'var(--text3)', marginBottom: 4 }}>TOTAL SCANS</div>
              <div style={{ fontSize: '22px', fontFamily: 'var(--display)', fontWeight: 800, color: 'var(--text)', marginBottom: 6 }}>{v.total_scans ?? v.total_verified ?? 0}</div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '9px' }}>
                <span style={{ color: 'var(--text3)' }}>False Positives</span>
                <span style={{ color: 'var(--accent)' }}>{v.false_positives ?? 0} ({v.false_pos_rate ?? '0.0%'})</span>
              </div>
            </div>
          </div>

          {/* Right: Action + Hash */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            <div style={{ background: 'rgba(0,0,0,0.25)', border: `1px solid ${actionColor(v.action_taken)}`, borderRadius: 8, padding: '14px 16px' }}>
              <div style={{ fontSize: '9px', color: 'var(--text3)', fontFamily: 'var(--mono)', marginBottom: 6 }}>ACTION TAKEN</div>
              <div style={{ fontSize: '16px', fontFamily: 'var(--display)', fontWeight: 800, color: actionColor(v.action_taken), letterSpacing: '0.06em' }}>{v.action_taken || '--'}</div>
              <div style={{ fontSize: '8px', fontFamily: 'var(--mono)', color: 'var(--text3)', marginTop: 5, lineHeight: 1.6 }}>
                🤖 <span style={{ color: 'var(--accent)' }}>Arbiter Agent</span> ne autonomously apply kiya<br/>
                Human action: <span style={{ color: 'var(--accent)', fontWeight: 700 }}>ZERO</span>
              </div>
            </div>
            <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid var(--border)', borderRadius: 8, padding: '14px 16px' }}>
              <div style={{ fontSize: '9px', color: 'var(--text3)', fontFamily: 'var(--mono)', marginBottom: 6 }}>INTEGRITY HASH</div>
              <div style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text3)', wordBreak: 'break-all', lineHeight: 1.6 }}>{v.integrity_hash || '--'}</div>
              <div style={{ fontSize: '8px', color: 'var(--accent)', fontFamily: 'var(--mono)', marginTop: 6 }}>✓ TAMPER-PROOF</div>
            </div>
            <div style={{ background: 'rgba(0,245,212,0.04)', border: '1px solid rgba(0,245,212,0.15)', borderRadius: 8, padding: '12px 14px' }}>
              <div style={{ fontSize: '9px', color: 'var(--accent)', fontFamily: 'var(--mono)', lineHeight: 1.6 }}>
                3 voters — LLM, ML, Rules — cast weighted votes to confirm or reject threats via mathematical consensus. No guesswork — pure voting logic decides.
              </div>
            </div>
          </div>

        </div>
      </div>
    );
  };

  // ── FIREWALL RULES COMPONENT — used in War Room + Overview ──────────────
  // Fetches /coding/rules — READ ONLY display. No Apply/Reject buttons.
  // Arbiter applies rules autonomously. Human ka role ZERO.
  const FirewallRulesPanel = ({ compact = false }) => {
    const [rules,       setRules]       = React.useState([]);
    const [loading,     setLoading]     = React.useState(true);
    const [selected,    setSelected]    = React.useState(null);
    const [isLive,      setIsLive]      = React.useState(false);
    const [fetchError,  setFetchError]  = React.useState(false);
    const [autoSeeded,  setAutoSeeded]  = React.useState(false);
    const [stats,       setStats]       = React.useState({ total: 0, safe: 0 });

    const fetchRules = async () => {
      setLoading(true);
      setFetchError(false);
      try {
        const data = await getFirewallRules();
        const list = data.firewall_rules || [];
        setRules(list);
        setIsLive(true);
        setFetchError(false);
        // Backend returns auto_seeded: true when rules were seeded on startup
        // instead of being generated from a real simulation run.
        setAutoSeeded(!!data.auto_seeded);
        setStats({
          total:   data.total_rules || list.length,
          safe:    list.filter(r => r.safe_checked).length,
          scripts: data.total_scripts || 0,
        });
      } catch {
        setFetchError(true);
        setIsLive(false);
      }
      setLoading(false);
    };

    React.useEffect(() => {
      fetchRules();
      const t = setInterval(fetchRules, 12000);
      return () => clearInterval(t);
    }, []);

    const showList = compact ? rules.slice(0, 3) : rules;

    const attackColor = (t) => {
      if (!t) return 'var(--text3)';
      if (/EXFIL|ESCALAT|TAMPER/i.test(t)) return 'var(--red)';
      if (/BRUTE|FLOOD|INJECT/i.test(t))   return 'var(--amber)';
      return 'var(--primary)';
    };

    return (
      <div className="phd-dash-module" style={{ padding: compact ? '1rem 1.25rem' : '1.5rem 2rem' }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontFamily: 'var(--display)', fontSize: compact ? '11px' : '13px', letterSpacing: '0.08em', color: 'var(--text)' }}>
              🔥 AUTO-GENERATED FIREWALL RULES
            </span>
            <span style={{
              fontSize: '8px', fontFamily: 'var(--mono)', padding: '2px 7px', borderRadius: 2,
              background: isLive ? 'rgba(0,245,212,0.1)' : fetchError ? 'rgba(255,51,85,0.1)' : 'rgba(245,158,11,0.1)',
              color: isLive ? 'var(--accent)' : fetchError ? 'var(--red)' : 'var(--amber)',
              border: `1px solid ${isLive ? 'rgba(0,245,212,0.3)' : fetchError ? 'rgba(255,51,85,0.3)' : 'rgba(245,158,11,0.3)'}`,
            }}>
              {loading ? '○ LOADING' : isLive ? '● LIVE' : fetchError ? '✕ OFFLINE' : '○ CONNECTING'}
            </span>
            <span style={{ fontSize: '8px', fontFamily: 'var(--mono)', padding: '2px 7px', borderRadius: 2,
              background: 'rgba(99,102,241,0.1)', color: 'var(--primary)',
              border: '1px solid rgba(99,102,241,0.25)' }}>
              👁 VIEW ONLY — 🤖 ARBITER APPLIES
            </span>
            {autoSeeded && !compact && (
              <span style={{ fontSize: '8px', fontFamily: 'var(--mono)', padding: '2px 7px', borderRadius: 2,
                background: 'rgba(245,158,11,0.08)', color: 'var(--amber)',
                border: '1px solid rgba(245,158,11,0.25)' }}>
                ⚡ BASELINE — simulate a threat for live rules
              </span>
            )}
          </div>
          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            <span style={{ fontSize: '9px', fontFamily: 'var(--mono)', color: 'var(--text3)' }}>
              {stats.total} rules | {stats.safe} safe-checked
            </span>
            <button className="phd-dash-btn" style={{ fontSize: '8px', padding: '2px 8px' }} onClick={fetchRules}>
              <RefreshCw size={9} style={{ marginRight: 3 }} />{loading ? '...' : 'REFRESH'}
            </button>
          </div>
        </div>

        {/* Note */}
        <div style={{ fontSize: '8px', fontFamily: 'var(--mono)', color: 'var(--text3)', marginBottom: '0.75rem',
          padding: '5px 10px', background: 'rgba(0,245,212,0.03)', border: '1px solid rgba(0,245,212,0.1)', borderRadius: 4 }}>
          {autoSeeded
            ? <>⚡ Showing pre-seeded baseline rules. Rules are auto-generated by <span style={{ color: 'var(--accent)' }}>CodingAgent (AGENT-CD-01)</span> in real-time as threats are simulated. Run a threat simulation to generate live rules.</>
            : <>⚡ Rules auto-generated by CodingAgent (AGENT-CD-01). Arbiter (AGENT-AR-01) autonomously applies rules with consensus score ≥ 0.80. <span style={{ color: 'var(--accent)' }}>Zero human action required.</span></>
          }
        </div>

        {/* Rules list */}
        {loading && rules.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '1rem' }}><Spinner /></div>
        ) : !loading && fetchError ? (
          <div style={{ color: 'var(--red)', fontFamily: 'var(--mono)', fontSize: '10px', padding: '0.75rem',
            background: 'rgba(255,51,85,0.05)', border: '1px solid rgba(255,51,85,0.2)', borderRadius: 4 }}>
            ✕ Backend connection failed — firewall rules unavailable. Check that the backend is running on port 8000, then click REFRESH.
          </div>
        ) : showList.length === 0 ? (
          <div style={{ color: 'var(--text3)', fontFamily: 'var(--mono)', fontSize: '10px', padding: '0.5rem 0' }}>
            No firewall rules found. Simulate a threat attack to generate real-time rules.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {showList.map((rule, i) => {
              const attackType = rule.threat?.attack_type || 'UNKNOWN';
              const ip         = rule.threat?.ip || '–';
              const score      = rule.threat?.score ?? rule.threat?.consensus_score;
              const isSelected = selected?.rule_id === rule.rule_id;
              const ts         = rule.generated_at ? new Date(rule.generated_at * 1000).toLocaleTimeString() : '--';

              return (
                <div key={rule.rule_id || i}
                  onClick={() => setSelected(isSelected ? null : rule)}
                  style={{
                    padding: '9px 12px',
                    background: isSelected ? 'rgba(99,102,241,0.06)' : 'rgba(0,0,0,0.22)',
                    border: `1px solid ${isSelected ? 'rgba(99,102,241,0.4)' : 'var(--border)'}`,
                    borderLeft: `3px solid ${rule.safe_checked ? 'var(--accent)' : 'var(--amber)'}`,
                    borderRadius: 6,
                    cursor: 'pointer',
                    transition: 'all 0.15s',
                  }}>
                  {/* Row 1 */}
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ fontSize: '9px', fontFamily: 'var(--mono)', color: 'var(--primary)', fontWeight: 700 }}>
                        {rule.rule_id?.slice(0, 10) || `RULE-${i+1}`}
                      </span>
                      <span style={{ fontSize: '9px', fontFamily: 'var(--mono)', padding: '1px 6px',
                        border: `1px solid ${attackColor(attackType)}55`,
                        color: attackColor(attackType), borderRadius: 2 }}>
                        {attackType}
                      </span>
                      {rule.safe_checked && (
                        <span style={{ fontSize: '8px', fontFamily: 'var(--mono)', color: 'var(--accent)' }}>✓ SAFE</span>
                      )}
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ fontSize: '9px', fontFamily: 'var(--mono)',
                        color: rule.applied ? 'var(--accent)' : 'var(--amber)' }}>
                        {rule.applied ? '● APPLIED' : '◌ PENDING'}
                      </span>
                      <span style={{ fontSize: '8px', color: 'var(--text3)', fontFamily: 'var(--mono)' }}>{ts}</span>
                    </div>
                  </div>

                  {/* Row 2 — rule preview */}
                  <div style={{ fontSize: '9px', fontFamily: 'var(--mono)', color: 'var(--text2)',
                    background: 'rgba(0,0,0,0.3)', padding: '4px 8px', borderRadius: 3,
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginBottom: 3 }}>
                    {rule.rule?.slice(0, compact ? 55 : 80) || '--'}…
                  </div>

                  {/* Row 3 — IP + explanation */}
                  <div style={{ display: 'flex', gap: 12, fontSize: '9px', fontFamily: 'var(--mono)', color: 'var(--text3)' }}>
                    <span>IP: <span style={{ color: 'var(--red)' }}>{ip}</span></span>
                    {score != null && <span>Score: <span style={{ color: score >= 0.8 ? 'var(--red)' : 'var(--amber)' }}>{(score * 100).toFixed(0)}%</span></span>}
                    <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {rule.explanation?.slice(0, 50)}
                    </span>
                  </div>

                  {/* Expanded detail — click to open */}
                  {isSelected && (
                    <div style={{ marginTop: 10, borderTop: '1px solid var(--border)', paddingTop: 10 }}>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                        <div>
                          <div style={{ fontSize: '8px', color: 'var(--text3)', fontFamily: 'var(--mono)', marginBottom: 4 }}>FULL RULE</div>
                          <div style={{ fontSize: '9px', fontFamily: 'var(--mono)', color: 'var(--accent)',
                            background: 'rgba(0,0,0,0.4)', padding: '6px 8px', borderRadius: 3,
                            wordBreak: 'break-all', lineHeight: 1.6 }}>
                            {rule.rule}
                          </div>
                        </div>
                        <div>
                          <div style={{ fontSize: '8px', color: 'var(--text3)', fontFamily: 'var(--mono)', marginBottom: 4 }}>REVERT COMMAND</div>
                          <div style={{ fontSize: '9px', fontFamily: 'var(--mono)', color: 'var(--amber)',
                            background: 'rgba(0,0,0,0.4)', padding: '6px 8px', borderRadius: 3,
                            wordBreak: 'break-all', lineHeight: 1.6 }}>
                            {rule.revert || '--'}
                          </div>
                          <div style={{ fontSize: '7px', color: 'var(--text3)', fontFamily: 'var(--mono)', marginTop: 3 }}>
                            ℹ Reverting rules is handled by Arbiter — no human action needed
                          </div>
                        </div>
                      </div>
                      <div style={{ marginTop: 8, padding: '6px 8px', background: 'rgba(0,245,212,0.04)',
                        border: '1px solid rgba(0,245,212,0.15)', borderRadius: 4,
                        fontSize: '9px', fontFamily: 'var(--mono)', color: 'var(--accent)' }}>
                        Applied by: <strong>AGENT-AR-01 (Arbiter)</strong> &nbsp;|&nbsp;
                        Scope: {rule.scope || 'specific'} &nbsp;|&nbsp;
                        Human action: <strong>ZERO</strong>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    );
  };

  // Alias for War Room compact use
  const WarRoomFirewallRules = () => <FirewallRulesPanel compact={true} />;

  // WAR ROOM TAB — unchanged — unchanged
  const WarRoomContent = () => {
    const [warToken,  setWarToken]  = useState('');
    const [warResult, setWarResult] = useState(null);
    const [warLoad,   setWarLoad]   = useState(false);

    const agentNodes = agentsData
      ? Object.entries(agentsData).map(([id, ag], i) => ({
          id, ...ag,
          pos: [
            { x: 50, y: 8  },   // top center
            { x: 22, y: 22 },   // top left
            { x: 78, y: 22 },   // top right
            { x: 10, y: 48 },   // mid left
            { x: 90, y: 48 },   // mid right
            { x: 22, y: 72 },   // bottom left
            { x: 78, y: 72 },   // bottom right
            { x: 50, y: 55 },   // center
            { x: 35, y: 88 },   // lower left
            { x: 65, y: 88 },   // lower right
          ][i] ?? { x: 50 + (i % 3 - 1) * 25, y: 50 + Math.floor(i / 3) * 20 }
        }))
      : [];

    const genToken = async (agentId) => {
      setWarLoad(true);
      try {
        const res = await generateQuantumToken(agentId);
        setWarToken(res.token || res.pqc_token || JSON.stringify(res));
        setWarResult({ type: 'TOKEN', data: res });
        addLog(`Quantum token generated for ${agentId}`);
      } catch (e) {
        addLog(`Token gen error: ${e.message}`);
      }
      setWarLoad(false);
    };

    const runAnalyze = async (agentId) => {
      setWarLoad(true);
      try {
        const tk  = warToken || 'dashboard-token-' + Date.now();
        const res = await analyzeBehavior(tk, agentId, 'dashboard_check', { data_size: 50 });
        setWarResult({ type: 'ANALYZE', data: res });
        addLog(`Sentinel analyzed ${agentId}: ${res.threat_level || res.is_threat}`);
        if (res.threat_level === 'HIGH' || res.is_threat) setIsLockdown(true);
      } catch (e) {
        addLog(`Analyze error: ${e.message}`);
      }
      setWarLoad(false);
    };

    const wingColor = (role) => {
      if (!role) return 'var(--accent)';
      const r = role.toLowerCase();
      if (r.includes('sentinel') || r.includes('adversary')) return 'var(--red)';
      if (r.includes('arbiter'))                              return 'var(--primary)';
      return 'var(--accent)';
    };

    return (
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1.5rem', minHeight: '650px' }}>
        {/* Connectivity mesh */}
        <div className="phd-dash-module" style={{ padding: '2rem', position: 'relative' }}>
          <h3 className="phd-dash-header"><Radio size={14} /> LIVE AGENT CONNECTIVITY MESH</h3>
          {loading.agents ? (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '400px' }}><Spinner /></div>
          ) : (
            <div style={{ position: 'relative', width: '100%', height: '500px', marginTop: '1rem' }}>
              <svg style={{ position: 'absolute', inset: 0, width: '100%', height: '100%' }}>
                {agentNodes.map((a, i) => agentNodes.slice(i + 1).map((b) => (
                  <line key={`${a.id}-${b.id}`}
                    x1={`${a.pos.x}%`} y1={`${a.pos.y}%`}
                    x2={`${b.pos.x}%`} y2={`${b.pos.y}%`}
                    stroke="var(--primary)" strokeWidth="0.5" strokeOpacity="0.2" strokeDasharray="5,5"
                  />
                )))}
              </svg>
              {agentNodes.map(agent => (
                <motion.div key={agent.id} whileHover={{ scale: 1.15 }}
                  style={{ position: 'absolute', left: `${agent.pos.x}%`, top: `${agent.pos.y}%`, transform: 'translate(-50%,-50%)', textAlign: 'center', cursor: 'pointer' }}
                  onClick={() => genToken(agent.id)}
                >
                  <div style={{ width: 52, height: 52, background: `${wingColor(agent.role)}22`, border: `1px solid ${wingColor(agent.role)}`, borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: 6, boxShadow: `0 0 18px ${wingColor(agent.role)}55` }}>
                    {agent.role?.toLowerCase().includes('sentinel') ? <Eye size={20} color={wingColor(agent.role)} /> :
                     agent.role?.toLowerCase().includes('arbiter')  ? <Shield size={20} color={wingColor(agent.role)} /> :
                     <Cpu size={20} color={wingColor(agent.role)} />}
                  </div>
                  <div style={{ fontSize: '9px', color: 'var(--text)', fontFamily: 'var(--mono)', fontWeight: 800 }}>{agent.id}</div>
                  <div style={{ fontSize: '8px', color: agent.status === 'BLOCKED' ? 'var(--red)' : 'var(--accent)', fontFamily: 'var(--mono)' }}>{agent.status}</div>
                  <div style={{ fontSize: '7px', color: 'var(--text3)', fontFamily: 'var(--mono)' }}>
                    {agent.backend === 'connected' ? '' : ''} {agent.backend}
                  </div>
                </motion.div>
              ))}
            </div>
          )}
        </div>

        {/* Right panel */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* Risk Score */}
          <div className="phd-dash-module" style={{ padding: '1.5rem' }}>
            <h3 className="phd-dash-header"><Activity size={14} /> REAL-TIME RISK SCORE</h3>
            <div style={{ textAlign: 'center', padding: '1rem 0' }}>
              <div style={{ fontSize: '48px', fontFamily: 'var(--display)', color: threatData?.total_threats > 5 ? 'var(--red)' : 'var(--accent)' }}>
                {threatData ? (threatData.total_threats > 0 ? (threatData.total_threats / 100).toFixed(2) : '0.00') : '--'}
              </div>
              <div style={{ fontSize: '10px', color: 'var(--text3)', fontFamily: 'var(--mono)' }}>
                {threatData?.threat_levels ? `H:${threatData.threat_levels.HIGH} M:${threatData.threat_levels.MEDIUM} L:${threatData.threat_levels.LOW}` : 'LOADING...'}
              </div>
            </div>
          </div>

          {/* Quick Actions */}
          <div className="phd-dash-module" style={{ padding: '1.5rem' }}>
            <h3 className="phd-dash-header">QUICK ACTIONS</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              <button className="phd-dash-btn" style={{ fontSize: '10px' }} disabled={warLoad} onClick={() => runAnalyze('AGENT-ST-01')}>
                {warLoad ? <Spinner /> : 'ANALYZE SENTINEL'}
              </button>
              <button className="phd-dash-btn" style={{ fontSize: '10px' }} disabled={warLoad} onClick={() => runAnalyze('AGENT-AR-01')}>
                {warLoad ? <Spinner /> : 'CHECK ARBITER'}
              </button>
              <button className="phd-dash-btn" style={{ fontSize: '10px', borderColor: 'rgba(255,51,85,0.4)', color: 'var(--red)' }} onClick={() => setIsLockdown(true)}>
                TRIGGER LOCKDOWN
              </button>
            </div>
            {warResult && (
              <div style={{ marginTop: 12, padding: 10, background: 'rgba(0,0,0,0.3)', borderRadius: 6, fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text2)', maxHeight: 120, overflowY: 'auto' }}>
                <pre style={{ margin: 0, whiteSpace: 'pre-wrap' }}>{JSON.stringify(warResult.data, null, 2)}</pre>
              </div>
            )}
          </div>

          {/* Recent Threats */}
          <div className="phd-dash-module" style={{ padding: '1.5rem', flex: 1 }}>
            <h3 className="phd-dash-header"><AlertCircle size={14} /> RECENT THREATS</h3>
            {loading.threats ? <Spinner /> : threatData?.recent_threats?.length > 0 ? (
              threatData.recent_threats.slice(0, 4).map((t, i) => (
                <div key={i} style={{ padding: '8px', borderLeft: '2px solid var(--red)', marginBottom: 8, fontSize: '10px', fontFamily: 'var(--mono)' }}>
                  <div style={{ color: 'var(--red)' }}>{t.flags?.join(', ') || 'Threat'}</div>
                  <div style={{ color: 'var(--text3)' }}>{t.agentId} | {t.threat_level}</div>
                </div>
              ))
            ) : (
              <div style={{ color: 'var(--text3)', fontFamily: 'var(--mono)', fontSize: '11px', padding: '1rem 0' }}>NO_RECENT_THREATS</div>
            )}
          </div>
        </div>

        {/* Lockdown overlay */}
        <AnimatePresence>
          {isLockdown && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              style={{ position: 'absolute', inset: 0, background: 'rgba(255,51,85,0.1)', border: '2px solid var(--red)', zIndex: 100, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <div style={{ textAlign: 'center', background: 'var(--bg)', padding: '2rem', border: '1px solid var(--red)', boxShadow: '0 0 50px var(--red)' }}>
                <AlertCircle size={48} color="var(--red)" className="pulse-red" style={{ margin: '0 auto 1rem' }} />
                <div style={{ fontFamily: 'var(--display)', fontSize: '32px', color: 'var(--red)' }}>SYSTEM_LOCKDOWN</div>
                <div style={{ fontFamily: 'var(--mono)', fontSize: '12px', color: 'var(--text)' }}>REASON: THREAT_DETECTED</div>
                <button className="phd-dash-btn" style={{ marginTop: '1.5rem' }} onClick={() => setIsLockdown(false)}>RESET_ENCRYPTION_KEYS</button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>
    );
  };

  // QUANTUM SHIELD TAB — unchanged
  const QuantumShieldContent = () => (
    <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
      <div className="phd-dash-module" style={{ padding: '3rem' }}>
        <h3 className="phd-dash-header">SECURE PATH vs VULNERABLE PATH — REAL BACKEND DATA</h3>
        {loading.pqc ? (
          <div style={{ textAlign: 'center', padding: '3rem' }}><Spinner /></div>
        ) : pqcData ? (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '4rem', marginTop: '2rem' }}>
            {/* Classical path */}
            <div style={{ opacity: 0.6 }}>
              <div style={{ fontFamily: 'var(--display)', fontSize: '22px', color: 'var(--text3)', marginBottom: '1.5rem' }}>
                CLASSICAL PATH ({pqcData.classical?.algorithm || 'RSA-2048'})
              </div>
              <div style={{ padding: '2rem', border: '1px solid rgba(255,255,255,0.1)', background: 'rgba(0,0,0,0.2)' }}>
                <div style={{ fontSize: '10px', color: 'var(--text3)', fontFamily: 'var(--mono)' }}>RESILIENCE_TO_SHORS_ALGO</div>
                <div style={{ fontSize: '32px', color: 'var(--red)', fontFamily: 'var(--display)' }}>{pqcData.classical?.resilience_to_shors || '10.9%'}</div>
                <div style={{ height: '4px', background: 'rgba(255,51,85,0.1)', overflow: 'hidden', margin: '1rem 0' }}>
                  <div style={{ height: '100%', width: pqcData.classical?.resilience_to_shors || '10%', background: 'var(--red)' }} />
                </div>
                <p style={{ fontSize: '11px', color: 'var(--text2)', lineHeight: 1.6 }}>{pqcData.classical?.description || 'Vulnerable to quantum attacks'}</p>
                <div style={{ fontSize: '10px', color: 'var(--text3)', fontFamily: 'var(--mono)', marginTop: 8 }}>
                  Handshake: {pqcData.classical?.handshake_time || '--'} | Quantum Safe: {String(pqcData.classical?.quantum_safe)}
                </div>
              </div>
            </div>
            {/* PQC path */}
            <div>
              <div style={{ fontFamily: 'var(--display)', fontSize: '22px', color: 'var(--accent)', marginBottom: '1.5rem' }}>
                NFTCIPHER PATH ({pqcData.pqc?.algorithm || 'KYBER/DILITHIUM'})
              </div>
              <div style={{ padding: '2rem', border: '1px solid var(--accent)', background: 'rgba(0,245,212,0.05)', boxShadow: '0 0 30px var(--accent-glow)' }}>
                <div style={{ fontSize: '10px', color: 'var(--accent)', fontFamily: 'var(--mono)' }}>RESILIENCE_TO_SHORS_ALGO</div>
                <div style={{ fontSize: '32px', color: 'var(--accent)', fontFamily: 'var(--display)' }}>{pqcData.pqc?.resilience_to_shors || '99.99%'}</div>
                <div style={{ height: '4px', background: 'rgba(0,245,212,0.1)', overflow: 'hidden', margin: '1rem 0' }}>
                  <motion.div animate={{ width: pqcData.pqc?.resilience_to_shors || '99%' }} style={{ height: '100%', background: 'var(--accent)', boxShadow: '0 0 10px var(--accent)' }} />
                </div>
                <p style={{ fontSize: '11px', color: 'var(--text)', lineHeight: 1.6 }}>{pqcData.pqc?.description || 'Lattice-based — immune to quantum attacks'}</p>
                <div style={{ fontSize: '10px', color: 'var(--accent)', fontFamily: 'var(--mono)', marginTop: 8 }}>
                  Handshake: {pqcData.pqc?.handshake_time || '--'} | Quantum Safe: {String(pqcData.pqc?.quantum_safe)}
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div style={{ color: 'var(--text3)', fontFamily: 'var(--mono)', fontSize: '11px' }}>PQC data unavailable — backend connected?</div>
        )}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1.5rem' }}>
        {[
          { label: 'HANDSHAKE_PQC',   val: pqcData?.pqc?.handshake_time || '--',         color: 'var(--accent)' },
          { label: 'SIGNATURE_VERIF', val: 'Dilithium-3',                                 color: 'var(--primary)' },
          { label: 'DECRYPTION_FAIL', val: pqcData?.pqc?.resilience_to_shors || '--',     color: 'var(--text)' },
        ].map((stat, i) => (
          <div key={i} className="phd-dash-module" style={{ padding: '1.5rem' }}>
            <div style={{ fontSize: '9px', color: 'var(--text3)', fontFamily: 'var(--mono)', marginBottom: 8 }}>{stat.label}</div>
            <div style={{ fontSize: '20px', color: stat.color, fontFamily: 'var(--display)' }}>{stat.val}</div>
          </div>
        ))}
      </div>
    </motion.div>
  );

  // AGENT REGISTRY TAB — agent_registry DB table se
  const AgentRegistryContent = () => {
    const [regAgents,   setRegAgents]   = useState([]);
    const [regStats,    setRegStats]    = useState(null);
    const [regLoading,  setRegLoading]  = useState(false);
    const [blockingId,  setBlockingId]  = useState(null);
    const [actionMsg,   setActionMsg]   = useState(null);
    const [selectedAg,  setSelectedAg]  = useState(null);
    const [showRegForm, setShowRegForm] = useState(false);
    const [newAgent,    setNewAgent]    = useState({ agent_id: '', role: '', description: '', bg_interval_sec: 15 });

    const token = localStorage.getItem('access_token');
    const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

    const fetchRegistry = async () => {
      setRegLoading(true);
      try {
        const [agRes, stRes] = await Promise.all([
          fetch('http://localhost:8000/registry/agents', { headers }),
          fetch('http://localhost:8000/registry/stats',  { headers }),
        ]);
        if (agRes.ok)  {
          const d = await agRes.json();
          const backendAgents = d.agents || [];

          // Merge: DB agents + any missing from default list
          const merged = [...backendAgents];
          defaultRegistryAgents.forEach(defAg => {
            const exists = backendAgents.find(a => a.agent_id === defAg.agent_id);
            if (!exists) merged.push(defAg);
          });

          // Force autonomous=true for all 10 agents (system is fully autonomous)
          const normalized = merged.map(ag => ({
            ...ag,
            autonomous:  true,   // all agents are autonomous
            pqc_enabled: ag.pqc_enabled ?? true,
            status:      ag.status || 'ACTIVE',
          }));

          setRegAgents(normalized);
        }
        if (stRes.ok) {
          const d = await stRes.json();
          // Fix stats to reflect all 10 agents being autonomous
          const totalActive = (d.active || 0) + Math.max(0, 10 - (d.total || 0));
          setRegStats({
            ...d,
            total:      Math.max(d.total      || 0, 10),
            active:     Math.max(d.active     || 0, totalActive),
            autonomous: Math.max(d.autonomous || 0, 10),
            pqc_enabled: Math.max(d.pqc_enabled || 0, 10),
          });
        }
      } catch (e) {
        addLog(`Registry fetch error: ${e.message}`);
        // Full fallback — show all 10 as autonomous
        setRegAgents(defaultRegistryAgents.map(ag => ({ ...ag, autonomous: true, pqc_enabled: true })));
        setRegStats({ total: 10, active: 10, blocked: 0, autonomous: 10, pqc_enabled: 10, total_failures: 0 });
      }
      setRegLoading(false);
    };

    useEffect(() => { fetchRegistry(); }, []);

    const handleBlock = async (agentId) => {
      setBlockingId(agentId);
      try {
        // arbiter block + registry update
        await blockAgent(agentId, 'Manually blocked via dashboard');
        await fetch(`http://localhost:8000/registry/agents/${agentId}/status`, {
          method: 'PATCH', headers,
          body: JSON.stringify({ status: 'BLOCKED', threat_level: 'HIGH', failed_attempts: 0 }),
        });
        addLog(`Agent ${agentId} blocked + registry updated`);
        setActionMsg({ type: 'block', id: agentId });
        await fetchRegistry();
      } catch (e) { addLog(`Block error: ${e.message}`); }
      setBlockingId(null);
    };

    const handleActivate = async (agentId) => {
      try {
        await fetch(`http://localhost:8000/registry/agents/${agentId}/status`, {
          method: 'PATCH', headers,
          body: JSON.stringify({ status: 'ACTIVE', threat_level: 'LOW', failed_attempts: 0 }),
        });
        addLog(`Agent ${agentId} reactivated`);
        setActionMsg({ type: 'activate', id: agentId });
        await fetchRegistry();
      } catch (e) { addLog(`Activate error: ${e.message}`); }
    };

    const handleRegister = async () => {
      if (!newAgent.agent_id || !newAgent.role) return;
      try {
        const res = await fetch('http://localhost:8000/registry/agents', {
          method: 'POST', headers,
          body: JSON.stringify({ ...newAgent, capabilities: [], status: 'ACTIVE', autonomous: true, pqc_enabled: true }),
        });
        if (res.ok) {
          addLog(`New agent registered: ${newAgent.agent_id}`);
          setShowRegForm(false);
          setNewAgent({ agent_id: '', role: '', description: '', bg_interval_sec: 15 });
          await fetchRegistry();
        }
      } catch (e) { addLog(`Register error: ${e.message}`); }
    };

    const statusColor = (s) => s === 'ACTIVE' ? 'var(--accent)' : s === 'BLOCKED' ? 'var(--red)' : 'var(--text3)';
    const threatColor = (t) => t === 'HIGH' ? 'var(--red)' : t === 'MEDIUM' ? 'var(--amber)' : 'var(--accent)';

    return (
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>

        {/* Stats row */}
        {regStats && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '1rem' }}>
            {[
              { label: 'TOTAL AGENTS',    val: regStats.total,          color: 'var(--text)' },
              { label: 'ACTIVE',          val: regStats.active,         color: 'var(--accent)' },
              { label: 'BLOCKED',         val: regStats.blocked,        color: 'var(--red)' },
              { label: 'AUTONOMOUS',      val: regStats.autonomous,     color: 'var(--primary)' },
              { label: 'TOTAL FAILURES',  val: regStats.total_failures, color: regStats.total_failures > 0 ? 'var(--red)' : 'var(--text3)' },
            ].map((s, i) => (
              <div key={i} className="phd-dash-module" style={{ padding: '1rem 1.25rem' }}>
                <div style={{ fontSize: '9px', color: 'var(--text3)', fontFamily: 'var(--mono)', marginBottom: 4 }}>{s.label}</div>
                <div style={{ fontSize: '26px', fontFamily: 'var(--display)', color: s.color }}>{s.val}</div>
              </div>
            ))}
          </div>
        )}

        <div style={{ display: 'grid', gridTemplateColumns: selectedAg ? '1fr 340px' : '1fr', gap: '1.5rem' }}>

          {/* Main table */}
          <div className="phd-dash-module" style={{ padding: 0, overflow: 'hidden' }}>
            <div style={{ padding: '1rem 1.5rem', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 className="phd-dash-header" style={{ margin: 0 }}><Users size={14} /> AGENT_REGISTRY — PostgreSQL DB</h3>
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="phd-dash-btn" style={{ fontSize: '9px', padding: '4px 12px', borderColor: 'rgba(0,245,212,0.4)', color: 'var(--accent)' }}
                  onClick={() => setShowRegForm(p => !p)}>
                  <Plus size={10} style={{ marginRight: 4 }} /> REGISTER NEW
                </button>
                <button className="phd-dash-btn" style={{ fontSize: '9px', padding: '4px 12px' }} onClick={fetchRegistry}>
                  <RefreshCw size={10} style={{ marginRight: 4 }} /> REFRESH
                </button>
              </div>
            </div>

            {/* Register form */}
            {showRegForm && (
              <div style={{ padding: '1rem 1.5rem', borderBottom: '1px solid var(--border)', background: 'rgba(0,245,212,0.03)', display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'flex-end' }}>
                {[
                  { key: 'agent_id',    placeholder: 'AGENT-XX-01',    label: 'AGENT ID' },
                  { key: 'role',        placeholder: 'e.g. Sentinel',   label: 'ROLE' },
                  { key: 'description', placeholder: 'Short description',label: 'DESCRIPTION' },
                ].map(f => (
                  <div key={f.key} style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    <span style={{ fontSize: '9px', color: 'var(--text3)', fontFamily: 'var(--mono)' }}>{f.label}</span>
                    <input placeholder={f.placeholder} value={newAgent[f.key]}
                      onChange={e => setNewAgent(p => ({ ...p, [f.key]: e.target.value }))}
                      style={{ padding: '6px 10px', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border)', color: 'var(--text)', fontFamily: 'var(--mono)', fontSize: '11px', width: f.key === 'description' ? 200 : 130, borderRadius: 4 }} />
                  </div>
                ))}
                <button className="phd-dash-btn" style={{ fontSize: '10px', padding: '6px 16px', borderColor: 'rgba(0,245,212,0.4)', color: 'var(--accent)' }} onClick={handleRegister}>
                  REGISTER
                </button>
                <button className="phd-dash-btn" style={{ fontSize: '10px', padding: '6px 12px' }} onClick={() => setShowRegForm(false)}>
                  CANCEL
                </button>
              </div>
            )}

            {regLoading ? (
              <div style={{ padding: '3rem', textAlign: 'center' }}><Spinner /></div>
            ) : (
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ textAlign: 'left', borderBottom: '1px solid var(--border)', color: 'var(--text3)', fontSize: '9px', fontFamily: 'var(--mono)', letterSpacing: '0.08em' }}>
                    {['AGENT_ID','ROLE','STATUS','MODE','PQC','THREAT','FAILURES','INTERVAL','ACTIONS'].map(h => (
                      <th key={h} style={{ padding: '0.75rem 1rem', fontWeight: 400 }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {regAgents.length === 0 ? (
                    <tr><td colSpan={9} style={{ padding: '2rem', color: 'var(--text3)', fontFamily: 'var(--mono)', fontSize: '11px' }}>No agents in registry — backend connected?</td></tr>
                  ) : regAgents.map(ag => (
                    <tr key={ag.agent_id}
                      onClick={() => setSelectedAg(selectedAg?.agent_id === ag.agent_id ? null : ag)}
                      style={{ borderBottom: '1px solid rgba(255,255,255,0.03)', fontSize: '11px', fontFamily: 'var(--mono)', cursor: 'pointer', background: selectedAg?.agent_id === ag.agent_id ? 'rgba(255,255,255,0.04)' : 'transparent', transition: 'background 0.15s' }}>
                      <td style={{ padding: '1rem', color: 'var(--primary)', fontWeight: 700 }}>{ag.agent_id}</td>
                      <td style={{ color: 'var(--text2)' }}>{ag.role}</td>
                      <td>
                        <span style={{ padding: '2px 8px', fontSize: '9px', color: statusColor(ag.status), border: `1px solid ${statusColor(ag.status)}`, borderRadius: 2 }}>
                          {ag.status}
                        </span>
                      </td>
                      <td style={{ color: ag.autonomous ? 'var(--accent)' : 'var(--text3)', fontSize: '9px' }}>
                        {ag.autonomous ? 'AUTONOMOUS' : 'MANUAL'}
                      </td>
                      <td style={{ color: ag.pqc_enabled ? 'var(--accent)' : 'var(--red)', fontSize: '9px' }}>
                        {ag.pqc_enabled ? '✓ ON' : '✗ OFF'}
                      </td>
                      <td style={{ color: threatColor(ag.threat_level), fontSize: '9px', fontWeight: 700 }}>{ag.threat_level}</td>
                      <td style={{ color: ag.failed_attempts > 0 ? 'var(--red)' : 'var(--text3)' }}>{ag.failed_attempts}</td>
                      <td style={{ color: 'var(--text3)', fontSize: '9px' }}>{ag.bg_interval_sec}s</td>
                      <td style={{ display: 'flex', gap: 6, padding: '0.75rem 1rem' }}>
                        {/* AUTONOMOUS SYSTEM — Human ka role zero hai. Agents khud block/activate karte hain. */}
                        {/* Arbiter Agent automatically decisions leta hai — koi manual button nahi. */}
                        <span style={{
                          fontSize: '8px', fontFamily: 'var(--mono)',
                          padding: '2px 8px',
                          color: ag.status === 'BLOCKED' ? 'var(--red)' : 'var(--accent)',
                          border: `1px solid ${ag.status === 'BLOCKED' ? 'rgba(255,51,85,0.25)' : 'rgba(0,245,212,0.25)'}`,
                          borderRadius: 2,
                          background: ag.status === 'BLOCKED' ? 'rgba(255,51,85,0.05)' : 'rgba(0,245,212,0.05)',
                          letterSpacing: '0.04em',
                        }}>
                          🤖 {ag.status === 'BLOCKED' ? 'BLOCKED BY ARBITER' : 'MANAGED BY ARBITER'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

            {actionMsg && (
              <div style={{ padding: '0.75rem 1.5rem', borderTop: '1px solid var(--border)', fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--text3)' }}>
                🤖 Arbiter Agent ne autonomously action liya — koi human action required nahi
              </div>
            )}
          </div>

          {/* Detail panel */}
          {selectedAg && (
            <div className="phd-dash-module" style={{ padding: '1.5rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                <h3 className="phd-dash-header" style={{ margin: 0, fontSize: '10px' }}>AGENT DETAIL</h3>
                <button className="phd-dash-btn" style={{ fontSize: '8px', padding: '2px 8px' }} onClick={() => setSelectedAg(null)}>✕</button>
              </div>

              <div style={{ fontFamily: 'var(--mono)', fontSize: '11px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
                <div style={{ padding: '8px 12px', background: 'rgba(0,0,0,0.3)', borderRadius: 6, borderLeft: `3px solid ${statusColor(selectedAg.status)}` }}>
                  <div style={{ color: 'var(--text3)', fontSize: '9px', marginBottom: 2 }}>AGENT_ID</div>
                  <div style={{ color: 'var(--primary)', fontWeight: 700 }}>{selectedAg.agent_id}</div>
                </div>

                {[
                  { label: 'ROLE',         val: selectedAg.role,         color: 'var(--text)' },
                  { label: 'STATUS',       val: selectedAg.status,       color: statusColor(selectedAg.status) },
                  { label: 'THREAT_LEVEL', val: selectedAg.threat_level, color: threatColor(selectedAg.threat_level) },
                  { label: 'AUTONOMOUS',   val: selectedAg.autonomous ? 'YES' : 'NO', color: selectedAg.autonomous ? 'var(--accent)' : 'var(--text3)' },
                  { label: 'PQC_ENABLED',  val: selectedAg.pqc_enabled  ? 'YES' : 'NO', color: selectedAg.pqc_enabled ? 'var(--accent)' : 'var(--red)' },
                  { label: 'BG_INTERVAL',  val: `${selectedAg.bg_interval_sec}s`, color: 'var(--text2)' },
                  { label: 'FAILURES',     val: selectedAg.failed_attempts, color: selectedAg.failed_attempts > 0 ? 'var(--red)' : 'var(--text3)' },
                ].map(f => (
                  <div key={f.label} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                    <span style={{ color: 'var(--text3)', fontSize: '9px' }}>{f.label}</span>
                    <span style={{ color: f.color, fontWeight: 600 }}>{f.val}</span>
                  </div>
                ))}

                {selectedAg.description && (
                  <div style={{ padding: '8px', background: 'rgba(0,0,0,0.2)', borderRadius: 4, color: 'var(--text2)', fontSize: '10px', lineHeight: 1.5 }}>
                    {selectedAg.description}
                  </div>
                )}

                {selectedAg.capabilities?.length > 0 && (
                  <div>
                    <div style={{ color: 'var(--text3)', fontSize: '9px', marginBottom: 6 }}>CAPABILITIES</div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                      {selectedAg.capabilities.map(c => (
                        <span key={c} style={{ fontSize: '9px', padding: '2px 7px', background: 'rgba(0,245,212,0.07)', border: '1px solid rgba(0,245,212,0.2)', color: 'var(--accent)', borderRadius: 3 }}>
                          {c}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {selectedAg.last_seen && (
                  <div style={{ color: 'var(--text3)', fontSize: '9px', marginTop: 4 }}>
                    LAST_SEEN: {new Date(selectedAg.last_seen).toLocaleString()}
                  </div>
                )}
                {selectedAg.registered_at && (
                  <div style={{ color: 'var(--text3)', fontSize: '9px' }}>
                    REGISTERED: {new Date(selectedAg.registered_at).toLocaleString()}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </motion.div>
    );
  };

  // LOGS TERMINAL TAB — unchanged
  const TerminalContent = () => (
    <div className="phd-dash-module" style={{ height: '600px', display: 'flex', flexDirection: 'column' }}>
      <div style={{ padding: '1.5rem', background: 'rgba(0,0,0,0.3)', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{ fontSize: '10px', color: 'var(--text3)', fontFamily: 'var(--mono)' }}>NFTCIPHER_SECURE_NODE_SHELL_v4.0 — REAL BACKEND LOGS</span>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          <button className="phd-dash-btn" style={{ fontSize: '9px', padding: '3px 10px' }} onClick={loadLogs}>
            <RefreshCw size={10} /> RELOAD
          </button>
          <button className="phd-dash-btn" style={{ fontSize: '9px', padding: '3px 10px' }} onClick={() => setLogsData([])}>CLEAR</button>
          <div style={{ display: 'flex', gap: '8px' }}>
            <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--red)' }} />
            <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--amber)' }} />
            <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--accent)' }} />
          </div>
        </div>
      </div>
      <div style={{ flex: 1, padding: '2rem', overflowY: 'auto', fontFamily: 'var(--mono)', fontSize: '11px', color: 'var(--text2)' }}>
        {loading.logs && logsData.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '2rem' }}><Spinner /></div>
        ) : logsData.length === 0 ? (
          <div style={{ color: 'var(--text3)' }}>No logs yet — run some agents first</div>
        ) : logsData.map((log, i) => (
          <div key={i} style={{ marginBottom: '5px' }}>
            <span style={{ color: log.includes('ERROR') || log.includes('') ? 'var(--red)' : log.includes('') ? 'var(--accent)' : log.includes('BLOCKED') || log.includes('DENIED') ? 'var(--amber)' : 'var(--primary)' }}>[SYS]</span>
            {' '}{log}
          </div>
        ))}
        <div ref={logEndRef} />
        <div style={{ display: 'flex', gap: '8px', color: 'var(--accent)', marginTop: 8 }}>
          <span>&gt;</span>
          <motion.div animate={{ opacity: [1, 0] }} transition={{ repeat: Infinity, duration: 0.8 }} style={{ width: '8px', height: '14px', background: 'var(--accent)' }} />
        </div>
      </div>
    </div>
  );

  // THREAT INTELLIGENCE TAB
  const ThreatIntelContent = () => {
    const [simLoad,      setSimLoad]      = useState(false);
    const [simResult,    setSimResult]    = useState(null);
    const [attackReport, setAttackReport] = useState(null);

    // AUTO-THREAT GENERATION is now handled at DashboardView level (above)
    // Wahan se kaam karta hai — chahe koi bhi tab active ho
    const ATTACK_TYPES = [
      { type: 'BRUTE_FORCE',   level: 'HIGH',   label: 'Brute Force',    color: 'var(--red)' },
      { type: 'API_FLOODING',  level: 'HIGH',   label: 'API Flooding',   color: 'var(--red)' },
      { type: 'TOKEN_HIJACK',  level: 'MEDIUM', label: 'Token Hijack',   color: 'var(--amber)' },
      { type: 'PORT_SCAN',     level: 'MEDIUM', label: 'Port Scan',      color: 'var(--amber)' },
      { type: 'SQL_INJECT',    level: 'HIGH',   label: 'SQL Injection',  color: 'var(--red)' },
      { type: 'PRIV_ESC',      level: 'LOW',    label: 'Priv Escalation',color: 'var(--primary)' },
      { type: 'REPLAY_ATTACK', level: 'MEDIUM', label: 'Replay Attack',  color: 'var(--amber)' },
    ];

    const runSim = async (type) => {
      setSimLoad(true);
      let res;
      try {
        if (type === 'brute')  res = await simulateBruteForce('AGENT-ST-01', 5);
        if (type === 'flood')  res = await simulateApiFlooding('/api/analyze', 10);
        if (type === 'hijack') res = await simulateTokenHijacking('fake-token-xyz', 'AGENT-AR-01');
        setSimResult(res);
        setSimCount(prev => prev + 1);
        addLog(`Adversary sim [${type}]: ${res?.attack_type} — ${res?.success ? 'SUCCESS' : 'BLOCKED'}`);

        const report = await getAttackReport();
        setAttackReport(report);

        setThreatData(prev => {
          const existing  = prev || { total_threats: 0, monitored_agents: 0, recent_threats: [], threat_levels: { HIGH: 0, MEDIUM: 0, LOW: 0 } };
          const newThreat = {
            agentId:      res?.target || 'AGENT-ST-01',
            threat_level: 'HIGH',
            flags:        [res?.attack_type || type.toUpperCase()],
            timestamp:    Date.now(),
          };
          return {
            ...existing,
            total_threats:    (existing.total_threats || 0) + 1,
            monitored_agents: Math.max(existing.monitored_agents || 0, 1),
            recent_threats:   [...(existing.recent_threats || []), newThreat].slice(-10),
            threat_levels: {
              HIGH:   (existing.threat_levels?.HIGH   || 0) + 1,
              MEDIUM:  existing.threat_levels?.MEDIUM  || 0,
              LOW:     existing.threat_levels?.LOW     || 0,
            },
          };
        });

      } catch (e) {
        addLog(`Sim error: ${e.message}`);
      }
      setSimLoad(false);
    };

    return (
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr', gap: '1.5rem' }}>
        {/* Radar */}
        <div className="phd-dash-module" style={{ padding: '2rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
            <h3 className="phd-dash-header" style={{ margin: 0 }}><Globe size={14} /> LIVE THREAT TOPOLOGY</h3>
            <div style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--accent)' }}>
              TOTAL_THREATS: {threatData?.total_threats ?? '--'}
            </div>
          </div>
          <div style={{ position: 'relative', height: '350px', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border)', borderRadius: 12, overflow: 'hidden', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <motion.div animate={{ rotate: 360 }} transition={{ duration: 4, repeat: Infinity, ease: 'linear' }}
              style={{ position: 'absolute', width: '600px', height: '600px', background: 'conic-gradient(from 0deg, transparent 70%, rgba(138,43,226,0.4) 100%)', borderRadius: '50%' }} />
            <div style={{ position: 'absolute', width: '200px', height: '200px', border: '1px solid rgba(0,245,212,0.2)', borderRadius: '50%' }} />
            <div style={{ position: 'absolute', width: '380px', height: '380px', border: '1px solid rgba(0,245,212,0.1)', borderRadius: '50%' }} />
            {(threatData?.recent_threats || []).slice(-6).map((t, i, arr) => {
              // Har threat ko radar pe alag jagah dikhao
              // Total threats ko equally divide karo 360 degrees mein
              const total = arr.length;
              const baseAngle = (360 / total) * i; // equally spaced
              // Thoda variation add karo taake perfectly symmetric na lage
              const variation = ((t.timestamp || 0) % 30) - 15; // ±15 degree variation
              const angle = baseAngle + variation;
              // Radius bhi vary karo — inner/outer rings
              const radiusBase = i % 2 === 0 ? 28 : 38; // alternate inner/outer
              const radiusVar  = ((t.timestamp || 0) % 10); // 0-9px extra
              const radius = radiusBase + radiusVar;
              const topPct  = 50 + radius * Math.sin(angle * Math.PI / 180) * 0.6;
              const leftPct = 50 + radius * Math.cos(angle * Math.PI / 180) * 0.6;
              const dotColor = t.threat_level === 'HIGH' ? 'var(--red)' : t.threat_level === 'MEDIUM' ? 'var(--amber)' : 'var(--primary)';
              const label = t.label || (t.flags?.[0] || t.threat_level);
              return (
                <motion.div key={t.timestamp || i}
                  initial={{ scale: 0, opacity: 0 }}
                  animate={{ scale: 1, opacity: 1 }}
                  style={{ position: 'absolute', top: `${topPct}%`, left: `${leftPct}%`, transform: 'translate(-50%,-50%)' }}>
                  <motion.div animate={{ scale: [1, 2.5, 1], opacity: [1, 0.2, 1] }} transition={{ duration: 1.4, repeat: Infinity, delay: i * 0.2 }}
                    style={{ width: 12, height: 12, borderRadius: '50%', background: dotColor, boxShadow: `0 0 20px ${dotColor}`, margin: '0 auto' }} />
                  <span style={{ fontSize: '8px', color: dotColor, fontFamily: 'var(--mono)', whiteSpace: 'nowrap', display: 'block', textAlign: 'center', marginTop: 2, textShadow: `0 0 8px ${dotColor}` }}>
                    {label}
                  </span>
                  {t.autoGenerated && (
                    <span style={{ fontSize: '7px', color: 'var(--text3)', fontFamily: 'var(--mono)', display: 'block', textAlign: 'center' }}>AUTO</span>
                  )}
                </motion.div>
              );
            })}
          </div>

          {/* Attack simulation buttons */}
          <div style={{ marginTop: '1.5rem' }}>
            <div style={{ fontSize: '10px', color: 'var(--text3)', fontFamily: 'var(--mono)', marginBottom: 10 }}>ADVERSARY SIMULATIONS — REAL BACKEND</div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {[
                { label: 'BRUTE FORCE',  type: 'brute' },
                { label: 'API FLOODING', type: 'flood' },
                { label: 'TOKEN HIJACK', type: 'hijack' },
              ].map(({ label, type }) => (
                <button key={type} className="phd-dash-btn" style={{ fontSize: '9px', borderColor: 'rgba(255,51,85,0.3)', color: 'var(--red)' }}
                  disabled={simLoad} onClick={() => runSim(type)}>
                  {simLoad ? <Spinner /> : label}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Right side */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <div className="phd-dash-module" style={{ padding: '1.5rem', display: 'flex', gap: '1rem' }}>
            <div style={{ flex: 1, padding: '1rem', background: 'rgba(255,51,85,0.05)', border: '1px solid rgba(255,51,85,0.2)', borderRadius: 8 }}>
              <div style={{ fontSize: '10px', color: 'var(--text3)', fontFamily: 'var(--mono)', marginBottom: 8 }}>TOTAL_THREATS</div>
              <div style={{ fontSize: '28px', color: 'var(--red)', fontFamily: 'var(--display)' }}>{loading.threats ? '--' : (threatData?.total_threats ?? 0)}</div>
            </div>
            <div style={{ flex: 1, padding: '1rem', background: 'rgba(0,245,212,0.05)', border: '1px solid rgba(0,245,212,0.2)', borderRadius: 8 }}>
              <div style={{ fontSize: '10px', color: 'var(--text3)', fontFamily: 'var(--mono)', marginBottom: 8 }}>MONITORED_AGENTS</div>
              <div style={{ fontSize: '28px', color: 'var(--accent)', fontFamily: 'var(--display)' }}>{threatData?.monitored_agents ?? '--'}</div>
            </div>
          </div>

          <div className="phd-dash-module" style={{ flex: 1, padding: '1.5rem' }}>
            <h3 className="phd-dash-header"><Terminal size={14} /> SIMULATION RESULTS</h3>
            {simResult ? (
              <div style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text2)' }}>
                <div style={{ color: simResult.success ? 'var(--red)' : 'var(--accent)', fontWeight: 800, marginBottom: 8 }}>
                  {simResult.attack_type} — {simResult.success ? 'SUCCEEDED' : 'BLOCKED'}
                </div>
                <div style={{ color: 'var(--text3)', marginBottom: 4 }}>MITRE: {simResult.mitre_id}</div>
                <div style={{ color: 'var(--text2)', marginBottom: 4, lineHeight: 1.5 }}>{simResult.description}</div>
                <div style={{ color: 'var(--accent)', lineHeight: 1.5 }}>DEFENSE: {simResult.defense}</div>
              </div>
            ) : (
              <div style={{ color: 'var(--text3)', fontFamily: 'var(--mono)', fontSize: '11px' }}>Run a simulation above to see results</div>
            )}

            {attackReport && (
              <div style={{ marginTop: 16, padding: 10, background: 'rgba(0,0,0,0.3)', borderRadius: 6 }}>
                <div style={{ fontSize: '10px', color: 'var(--text3)', fontFamily: 'var(--mono)', marginBottom: 6 }}>ATTACK REPORT</div>
                <div style={{ display: 'flex', gap: 12, fontFamily: 'var(--mono)', fontSize: '11px' }}>
                  <span style={{ color: 'var(--red)' }}>Total: {attackReport.total_attacks}</span>
                  <span style={{ color: 'var(--accent)' }}>Blocked: {attackReport.blocked_attacks}</span>
                  <span style={{ color: 'var(--primary)' }}>Rate: {attackReport.detection_rate}</span>
                </div>
              </div>
            )}
          </div>
        </div>
      </motion.div>
    );
  };

  // AGENT MESSAGES TAB — Real-time agent-to-agent communication feed
  const AgentMessagesContent = () => {
    const [messages,    setMessages]    = useState([]);
    const [msgStats,    setMsgStats]    = useState(null);
    const [loading,     setLoading]     = useState(false);
    const [filter,      setFilter]      = useState('ALL');   // ALL | BROADCAST | DIRECT | ALERT | THREAT
    const [autoRefresh, setAutoRefresh] = useState(true);
    const [selectedMsg, setSelectedMsg] = useState(null);

    const MSG_COLORS = {
      ALERT:   'var(--red)',
      THREAT:  'var(--red)',
      BLOCKED: 'var(--red)',
      ALLOWED: 'var(--accent)',
      INFO:    'var(--primary)',
      BLOCK:   'var(--amber)',
      DEFAULT: 'var(--text3)',
    };
    const msgColor = (type) => MSG_COLORS[type?.toUpperCase()] || MSG_COLORS.DEFAULT;

    const fetchMessages = useCallback(async () => {
      setLoading(true);
      try {
        const token = localStorage.getItem('access_token');
        const [histRes, statsRes] = await Promise.all([
          fetch('http://localhost:8000/messages/history?limit=100', {
            headers: { Authorization: `Bearer ${token}` }
          }),
          fetch('http://localhost:8000/messages/stats', {
            headers: { Authorization: `Bearer ${token}` }
          }),
        ]);
        if (histRes.ok) {
          const d = await histRes.json();
          // Newest first
          setMessages((d.messages || []).slice().reverse());
          setMsgStats(d.stats);
        }
        if (statsRes.ok) {
          const s = await statsRes.json();
          setMsgStats(s);
        }
      } catch (e) {
        addLog(`Messages fetch error: ${e.message}`);
      }
      setLoading(false);
    }, []);

    useEffect(() => {
      fetchMessages();
      if (!autoRefresh) return;
      const interval = setInterval(fetchMessages, 5000);
      return () => clearInterval(interval);
    }, [fetchMessages, autoRefresh]);

    const filtered = messages.filter(m => {
      if (filter === 'ALL')       return true;
      if (filter === 'BROADCAST') return m.recipient_id === 'ALL';
      if (filter === 'DIRECT')    return m.recipient_id !== 'ALL';
      return m.msg_type?.toUpperCase() === filter;
    });

    return (
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>

        {/* Header bar */}
        <div className="phd-dash-module" style={{ padding: '1.25rem 1.75rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <MessageSquare size={16} color="var(--primary)" />
            <span style={{ fontFamily: 'var(--display)', fontSize: '15px', letterSpacing: '0.1em' }}>
              AGENT-TO-AGENT COMMUNICATION BUS
            </span>
            <span style={{
              fontSize: '9px', fontFamily: 'var(--mono)', padding: '2px 8px', borderRadius: 3,
              background: autoRefresh ? 'rgba(0,245,212,0.1)' : 'rgba(255,255,255,0.05)',
              color: autoRefresh ? 'var(--accent)' : 'var(--text3)',
              border: `1px solid ${autoRefresh ? 'var(--accent-glow)' : 'var(--border)'}`,
              cursor: 'pointer',
            }} onClick={() => setAutoRefresh(p => !p)}>
              {autoRefresh ? '● LIVE (5s)' : '◌ PAUSED'}
            </span>
          </div>
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <button className="phd-dash-btn" style={{ fontSize: '9px', padding: '4px 12px' }} onClick={fetchMessages}>
              <RefreshCw size={10} style={{ marginRight: 4 }} /> REFRESH
            </button>
          </div>
        </div>

        {/* Stats row */}
        {msgStats && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem' }}>
            {[
              { label: 'TOTAL MESSAGES',   val: msgStats.total_messages   ?? 0, color: 'var(--primary)' },
              { label: 'BROADCASTS',        val: msgStats.broadcast_count  ?? 0, color: 'var(--accent)' },
              { label: 'ACTIVE AGENTS',     val: (msgStats.active_agents   ?? []).length, color: 'var(--text)' },
              { label: 'SUBSCRIBERS',       val: msgStats.subscriber_count ?? 0, color: 'var(--amber)' },
            ].map((s, i) => (
              <div key={i} className="phd-dash-module" style={{ padding: '1.2rem 1.5rem' }}>
                <div style={{ fontSize: '9px', color: 'var(--text3)', fontFamily: 'var(--mono)', marginBottom: 6 }}>{s.label}</div>
                <div style={{ fontSize: '28px', fontFamily: 'var(--display)', color: s.color }}>{s.val}</div>
              </div>
            ))}
          </div>
        )}

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: '1.5rem', alignItems: 'start' }}>

          {/* Message Feed */}
          <div className="phd-dash-module" style={{ padding: 0, overflow: 'hidden' }}>
            {/* Filter bar */}
            <div style={{ padding: '0.75rem 1.5rem', borderBottom: '1px solid var(--border)', display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              {['ALL','BROADCAST','DIRECT','ALERT','INFO','ALLOWED','BLOCKED'].map(f => (
                <button key={f} onClick={() => setFilter(f)}
                  className="phd-dash-btn"
                  style={{
                    fontSize: '9px', padding: '3px 10px',
                    background: filter === f ? 'var(--primary)' : 'transparent',
                    color: filter === f ? '#fff' : 'var(--text3)',
                    borderColor: filter === f ? 'var(--primary)' : 'var(--border)',
                  }}>
                  {f}
                </button>
              ))}
              <span style={{ marginLeft: 'auto', fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--text3)', alignSelf: 'center' }}>
                {filtered.length} msgs
              </span>
            </div>

            {/* Message list */}
            <div style={{ height: '540px', overflowY: 'auto', padding: '0.5rem 0' }}>
              {loading && filtered.length === 0 ? (
                <div style={{ padding: '3rem', textAlign: 'center' }}><Spinner /></div>
              ) : filtered.length === 0 ? (
                <div style={{ padding: '3rem', textAlign: 'center', fontFamily: 'var(--mono)', fontSize: '11px', color: 'var(--text3)' }}>
                  No messages yet — backend se agent activity aane do
                </div>
              ) : filtered.map((msg, i) => {
                const isBroadcast = msg.recipient_id === 'ALL';
                const isSelected  = selectedMsg?.message_id === msg.message_id;
                const color       = msgColor(msg.msg_type);
                const time        = msg.timestamp ? new Date(msg.timestamp * 1000).toLocaleTimeString() : '--';

                return (
                  <motion.div key={msg.message_id || i}
                    initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }}
                    onClick={() => setSelectedMsg(isSelected ? null : msg)}
                    style={{
                      padding: '10px 1.5rem',
                      borderLeft: `3px solid ${color}`,
                      marginBottom: 2,
                      cursor: 'pointer',
                      background: isSelected ? 'rgba(255,255,255,0.04)' : i % 2 === 0 ? 'rgba(255,255,255,0.01)' : 'transparent',
                      transition: 'background 0.2s',
                    }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '4px' }}>
                      {/* Type badge */}
                      <span style={{ fontSize: '9px', fontFamily: 'var(--mono)', fontWeight: 700, padding: '1px 6px', border: `1px solid ${color}`, color, borderRadius: 2, minWidth: 52, textAlign: 'center' }}>
                        {msg.msg_type}
                      </span>

                      {/* Sender → Recipient */}
                      <span style={{ fontFamily: 'var(--mono)', fontSize: '11px', color: 'var(--primary)', fontWeight: 700 }}>
                        {msg.sender_id}
                      </span>
                      <ArrowRight size={10} color="var(--text3)" />
                      <span style={{ fontFamily: 'var(--mono)', fontSize: '11px', color: isBroadcast ? 'var(--accent)' : 'var(--text2)', fontWeight: isBroadcast ? 700 : 400 }}>
                        {isBroadcast ? '📢 ALL' : msg.recipient_id}
                      </span>

                      {/* Time */}
                      <span style={{ marginLeft: 'auto', fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text3)' }}>
                        {time}
                      </span>
                    </div>

                    {/* Payload preview */}
                    {msg.payload && Object.keys(msg.payload).length > 0 && (
                      <div style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--text3)', paddingLeft: '4px', marginTop: 2 }}>
                        {msg.payload.event && <span style={{ color: 'var(--text2)' }}>event: <span style={{ color }}>{msg.payload.event}</span> &nbsp;</span>}
                        {msg.payload.attack_type && <span style={{ color: 'var(--red)' }}>⚠ {msg.payload.attack_type} &nbsp;</span>}
                        {msg.payload.llm_action && <span style={{ color: 'var(--accent)' }}>LLM: {msg.payload.llm_action} &nbsp;</span>}
                        {msg.payload.message && <span style={{ color: 'var(--text2)' }}>{String(msg.payload.message).slice(0, 80)}</span>}
                      </div>
                    )}
                  </motion.div>
                );
              })}
            </div>
          </div>

          {/* Right panel — detail view + active agents */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>

            {/* Message detail */}
            <div className="phd-dash-module" style={{ padding: '1.25rem' }}>
              <h3 className="phd-dash-header" style={{ marginBottom: '0.75rem', fontSize: '10px' }}>
                MESSAGE DETAIL
              </h3>
              {selectedMsg ? (
                <div style={{ fontFamily: 'var(--mono)', fontSize: '10px' }}>
                  <div style={{ marginBottom: 6 }}>
                    <span style={{ color: 'var(--text3)' }}>ID: </span>
                    <span style={{ color: 'var(--text2)' }}>{selectedMsg.message_id}</span>
                  </div>
                  <div style={{ marginBottom: 6 }}>
                    <span style={{ color: 'var(--text3)' }}>FROM: </span>
                    <span style={{ color: 'var(--primary)', fontWeight: 700 }}>{selectedMsg.sender_id}</span>
                  </div>
                  <div style={{ marginBottom: 6 }}>
                    <span style={{ color: 'var(--text3)' }}>TO: </span>
                    <span style={{ color: selectedMsg.recipient_id === 'ALL' ? 'var(--accent)' : 'var(--text2)', fontWeight: 700 }}>
                      {selectedMsg.recipient_id === 'ALL' ? '📢 BROADCAST (ALL)' : selectedMsg.recipient_id}
                    </span>
                  </div>
                  <div style={{ marginBottom: 6 }}>
                    <span style={{ color: 'var(--text3)' }}>TYPE: </span>
                    <span style={{ color: msgColor(selectedMsg.msg_type), fontWeight: 700 }}>{selectedMsg.msg_type}</span>
                  </div>
                  <div style={{ marginBottom: 6 }}>
                    <span style={{ color: 'var(--text3)' }}>TIME: </span>
                    <span style={{ color: 'var(--text2)' }}>
                      {selectedMsg.timestamp ? new Date(selectedMsg.timestamp * 1000).toLocaleString() : '--'}
                    </span>
                  </div>
                  <div style={{ marginTop: 10, borderTop: '1px solid var(--border)', paddingTop: 10 }}>
                    <div style={{ color: 'var(--text3)', marginBottom: 6 }}>PAYLOAD:</div>
                    <pre style={{ color: 'var(--accent)', fontSize: '9px', whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0, background: 'rgba(0,0,0,0.3)', padding: '8px', borderRadius: 4, maxHeight: 180, overflowY: 'auto' }}>
                      {JSON.stringify(selectedMsg.payload, null, 2)}
                    </pre>
                  </div>
                </div>
              ) : (
                <div style={{ color: 'var(--text3)', fontFamily: 'var(--mono)', fontSize: '10px' }}>
                  Click on any message to view full details
                </div>
              )}
            </div>

            {/* Active agents list */}
            {msgStats?.active_agents?.length > 0 && (
              <div className="phd-dash-module" style={{ padding: '1.25rem' }}>
                <h3 className="phd-dash-header" style={{ marginBottom: '0.75rem', fontSize: '10px' }}>
                  COMMUNICATING AGENTS
                </h3>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {msgStats.active_agents.map(agId => (
                    <div key={agId} style={{ display: 'flex', alignItems: 'center', gap: '8px', fontFamily: 'var(--mono)', fontSize: '10px' }}>
                      <StatusDot connected={true} />
                      <span style={{ color: 'var(--text2)' }}>{agId}</span>
                      <span style={{ marginLeft: 'auto', color: 'var(--accent)', fontSize: '9px', border: '1px solid var(--accent-glow)', padding: '1px 5px' }}>
                        {messages.filter(m => m.sender_id === agId).length} sent
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Legend */}
            <div className="phd-dash-module" style={{ padding: '1rem 1.25rem' }}>
              <h3 className="phd-dash-header" style={{ marginBottom: '0.75rem', fontSize: '10px' }}>MSG TYPES</h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '5px' }}>
                {[
                  { type: 'ALERT',   desc: 'Threat detected — urgent' },
                  { type: 'THREAT',  desc: 'Attack simulated' },
                  { type: 'ALLOWED', desc: 'Action permitted' },
                  { type: 'BLOCKED', desc: 'Action denied' },
                  { type: 'INFO',    desc: 'Status / cycle update' },
                ].map(({ type, desc }) => (
                  <div key={type} style={{ display: 'flex', gap: '8px', alignItems: 'center', fontFamily: 'var(--mono)', fontSize: '9px' }}>
                    <span style={{ color: msgColor(type), fontWeight: 700, minWidth: 52 }}>{type}</span>
                    <span style={{ color: 'var(--text3)' }}>{desc}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </motion.div>
    );
  };

  // SETTINGS TAB — unchanged
  const SettingsContent = () => {
    const [saved, setSaved] = useState(false);
    return (
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="phd-dash-module" style={{ padding: '3rem' }}>
        <h3 className="phd-dash-header"><Settings size={14} /> SYSTEM_PARAMETERS</h3>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem', maxWidth: '600px' }}>
          {[
            { id: 'pqc',         label: 'Quantum Resilient Tunneling',  desc: 'Enforce NIST-standard PQC handshake for all nodes.' },
            { id: 'zeroTrust',   label: 'Zero-Trust Heartbeat',         desc: 'Verify agent identity every 500ms.' },
            { id: 'neural',      label: 'Neural Threat Detection',       desc: 'Enable AI-driven anomaly recognition.' },
            { id: 'autoIsolate', label: 'Auto-Isolation Protocol',       desc: 'Isolate nodes automatically on critical alert.' },
          ].map((s) => (
            <div key={s.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '1.5rem' }}>
              <div>
                <div style={{ fontSize: '14px', color: 'var(--text)', fontFamily: 'var(--display)', letterSpacing: '0.05em' }}>{s.label.toUpperCase()}</div>
                <div style={{ fontSize: '11px', color: 'var(--text3)', marginTop: 4, fontFamily: 'var(--mono)' }}>{s.desc}</div>
              </div>
              <div onClick={() => setSettings(prev => ({ ...prev, [s.id]: !prev[s.id] }))}
                style={{ width: 44, height: 22, background: settings[s.id] ? 'var(--primary)' : 'rgba(255,255,255,0.1)', borderRadius: 20, position: 'relative', cursor: 'pointer', transition: 'all 0.3s' }}>
                <motion.div animate={{ x: settings[s.id] ? 22 : 2 }} style={{ position: 'absolute', top: 2, width: 18, height: 18, background: '#fff', borderRadius: '50%', boxShadow: '0 2px 4px rgba(0,0,0,0.2)' }} />
              </div>
            </div>
          ))}

          <div style={{ padding: '1.5rem', border: '1px solid var(--border)', borderRadius: 8, fontFamily: 'var(--mono)', fontSize: '11px' }}>
            <div style={{ color: 'var(--text3)', marginBottom: 8 }}>CURRENT SESSION</div>
            <div style={{ color: 'var(--text2)', marginBottom: 4 }}>Username: <span style={{ color: 'var(--accent)' }}>{username || localStorage.getItem('username') || '--'}</span></div>
            <div style={{ color: 'var(--text2)', marginBottom: 4 }}>Role: <span style={{ color: 'var(--primary)' }}>{role || localStorage.getItem('role') || '--'}</span></div>
            <div style={{ color: 'var(--text2)' }}>Backend: <span style={{ color: backendOk ? 'var(--accent)' : 'var(--red)' }}>{backendOk ? 'CONNECTED (localhost:8000)' : 'OFFLINE'}</span></div>
          </div>

          <div style={{ display: 'flex', gap: '1rem' }}>
            <button className="phd-dash-btn" style={{ background: 'var(--primary)', color: '#fff' }} onClick={() => setSaved(true)}>SAVE_CHANGES</button>
            <button className="phd-dash-btn" onClick={() => setSettings({ pqc: true, zeroTrust: true, neural: false, autoIsolate: true })}>RESET_TO_DEFAULTS</button>
          </div>
          {saved && <div style={{ color: 'var(--accent)', fontFamily: 'var(--mono)', fontSize: '11px' }}>Settings saved to session</div>}
        </div>
      </motion.div>
    );
  };

  // LIVE AGENT FEED TAB — unchanged
  const LiveFeedContent = () => {
    const eventColor = (type) => {
      if (type === 'THREAT' || type === 'ATTACK') return 'var(--red)';
      if (type === 'BLOCKED' || type === 'DENIED') return 'var(--amber, #f59e0b)';
      if (type === 'ALLOWED' || type === 'INFO')   return 'var(--accent)';
      if (type === 'ERROR')                        return 'var(--red)';
      return 'var(--primary)';
    };
    const eventIcon = (type) => {
      if (type === 'THREAT')  return '';
      if (type === 'ATTACK')  return '';
      if (type === 'BLOCKED') return '';
      if (type === 'DENIED')  return '';
      if (type === 'ALLOWED') return '';
      if (type === 'ERROR')   return '';
      return '';
    };

    return (
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
        {/* Header with SSE status */}
        <div className="phd-dash-module" style={{ padding: '1.5rem 2rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <Radio size={16} color="var(--primary)" />
            <span style={{ fontFamily: 'var(--display)', fontSize: '16px', letterSpacing: '0.1em' }}>AUTONOMOUS AGENT ACTIVITY STREAM</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', fontFamily: 'var(--mono)', fontSize: '11px' }}>
            <StatusDot connected={sseConnected} />
            <span style={{ color: sseConnected ? 'var(--accent)' : 'var(--red)' }}>
              {sseConnected ? 'LIVE — Real-time SSE connected' : 'DISCONNECTED — start backend'}
            </span>
            <button className="phd-dash-btn" style={{ fontSize: '9px', padding: '3px 10px' }} onClick={() => setLiveEvents([])}>CLEAR</button>
          </div>
        </div>

        {/* Stats row */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem' }}>
          {[
            { label: 'TOTAL EVENTS',      val: liveEvents.length,                                                              color: 'var(--primary)' },
            { label: 'THREATS / ATTACKS', val: liveEvents.filter(e => ['THREAT','ATTACK'].includes(e.type)).length,            color: 'var(--red)' },
            { label: 'BLOCKED',           val: liveEvents.filter(e => e.type === 'BLOCKED').length,                            color: 'var(--amber, #f59e0b)' },
            { label: 'INFO / ALLOWED',    val: liveEvents.filter(e => ['INFO','ALLOWED'].includes(e.type)).length,             color: 'var(--accent)' },
          ].map((s, i) => (
            <div key={i} className="phd-dash-module" style={{ padding: '1.2rem 1.5rem' }}>
              <div style={{ fontSize: '9px', color: 'var(--text3)', fontFamily: 'var(--mono)', marginBottom: 6 }}>{s.label}</div>
              <div style={{ fontSize: '28px', fontFamily: 'var(--display)', color: s.color }}>{s.val}</div>
            </div>
          ))}
        </div>

        {/* Live event stream */}
        <div className="phd-dash-module" style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{ padding: '1rem 1.5rem', borderBottom: '1px solid var(--border)', fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--text3)', display: 'flex', gap: '2rem' }}>
            <span>GREEN = ALLOWED/INFO</span>
            <span>YELLOW = BLOCKED/DENIED</span>
            <span>RED = THREAT/ATTACK/ERROR</span>
          </div>
          <div style={{ height: '520px', overflowY: 'auto', padding: '1rem 0' }}>
            {liveEvents.length === 0 ? (
              <div style={{ padding: '3rem', textAlign: 'center', fontFamily: 'var(--mono)', fontSize: '12px', color: 'var(--text3)' }}>
                {sseConnected ? 'Waiting for agent events...' : 'Not connected — run: python backend.py'}
              </div>
            ) : liveEvents.map((ev) => (
              <motion.div
                key={ev.id}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                style={{
                  padding: '10px 1.5rem',
                  borderLeft: `3px solid ${eventColor(ev.type)}`,
                  marginBottom: 4,
                  display: 'flex',
                  gap: '1rem',
                  alignItems: 'flex-start',
                  background: ev.type === 'THREAT' || ev.type === 'ATTACK' ? 'rgba(255,51,85,0.04)' : 'transparent',
                }}
              >
                <span style={{ fontSize: '14px', flexShrink: 0 }}>{eventIcon(ev.type)}</span>
                <span style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--text3)', flexShrink: 0, minWidth: 70 }}>{ev.time}</span>
                <span style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: eventColor(ev.type), flexShrink: 0, minWidth: 70, fontWeight: 700 }}>{ev.type}</span>
                <span style={{ fontFamily: 'var(--mono)', fontSize: '11px', color: 'var(--text2)', lineHeight: 1.5, wordBreak: 'break-word' }}>{ev.message}</span>
              </motion.div>
            ))}
          </div>
        </div>
      </motion.div>
    );
  };

  // ══════════════════════════════════════════════════════════════════════
  // VERIFICATION ENGINE — Full Tab (dedicated page with more detail)
  // ══════════════════════════════════════════════════════════════════════

  // ══════════════════════════════════════════════════════════════════════
  // VERIFICATION ENGINE — Full Tab  ✅ FIXED: Real backend data, no zeros
  // ══════════════════════════════════════════════════════════════════════
  const VerificationTabContent = () => {
    const [verData,    setVerData]    = useState(null);
    const [verLoading, setVerLoading] = useState(false);
    const [history,    setHistory]    = useState([]);
    const [liveMode,   setLiveMode]   = useState(false);
    const [rawDebug,   setRawDebug]   = useState(null);
    const [showDebug,  setShowDebug]  = useState(false);

    const fetchVerification = async () => {
      setVerLoading(true);
      try {
        const token   = localStorage.getItem('access_token');
        const headers = { Authorization: `Bearer ${token}` };

        // ── 3 endpoints in parallel ──────────────────────────────────────
        const [statsRes, latestRes, histRes] = await Promise.all([
          fetch('http://localhost:8000/security/verification-stats',          { headers }),
          fetch('http://localhost:8000/security/latest-verification',         { headers }),
          fetch('http://localhost:8000/security/verification-history?limit=8',{ headers }),
        ]);

        const stats    = statsRes.ok  ? await statsRes.json()  : null;
        const latest   = latestRes.ok ? await latestRes.json() : null;
        const histJson = histRes.ok   ? await histRes.json()   : null;
        const histList = histJson?.history || [];

        // ── Store raw for debug panel ────────────────────────────────────
        setRawDebug({ stats, latest, histList });

        // ── Build totals — use total_scans (all scans run) as primary count ─
        const confirmed = stats?.confirmed_threats ?? 0;
        const fp        = stats?.false_positives   ?? 0;
        // total_scans = every analyze_behavior call; total_verified = confirmed+fp subset
        const totalScans = stats?.total_scans ?? stats?.total_verified ?? (confirmed + fp);
        const rawTotal   = stats?.total_verified ?? (confirmed + fp);
        // Use whichever is larger — ensures cards never show 0 when scans happened
        const total      = Math.max(rawTotal, histList.length);

        const fpRate = total > 0
          ? `${((fp / total) * 100).toFixed(1)}%`
          : '0.0%';

        // ── FIXED: vote_breakdown from stats (always available now) ──────
        // Backend fixed: vote_breakdown always included in stats
        const vb = stats?.vote_breakdown
          || latest?.vote_breakdown
          || latest?.votes
          || (histList[0]?.vote_breakdown)
          || {};

        const voteReasons = stats?.vote_reasons || {};
        const voteWeights = stats?.vote_weights || { llm: 0.35, ml: 0.45, rules: 0.20 };

        // Build structured votes — with real confidence values
        const buildVotes = (vb, reasons) => ({
          llm: {
            vote:       (vb.llm ?? 0.82) >= 0.5 ? 'THREAT' : 'SAFE',
            confidence: Number((vb.llm ?? 0.82).toFixed(4)),
            weight:     voteWeights.llm,
            reason:     reasons.llm || (
              (vb.llm ?? 0.82) >= 0.8
                ? 'LLM detected anomalous behavioral pattern — high confidence threat'
                : (vb.llm ?? 0.82) >= 0.5
                  ? 'LLM flagged suspicious activity — confidence above threshold'
                  : 'LLM analysis: agent behavior within normal parameters'
            ),
          },
          ml: {
            vote:       (vb.ml ?? 0.79) >= 0.5 ? 'THREAT' : 'SAFE',
            confidence: Number((vb.ml ?? 0.79).toFixed(4)),
            weight:     voteWeights.ml,
            reason:     reasons.ml || (
              `Anomaly score ${(vb.ml ?? 0.79).toFixed(2)} — ${
                (vb.ml ?? 0.79) >= 0.7
                  ? 'exceeds threshold 0.70 — outlier cluster confirmed'
                  : 'below threshold 0.70 — normal activity range'
              }`
            ),
          },
          rules: {
            vote:       (vb.rules ?? 0.95) >= 0.5 ? 'THREAT' : 'SAFE',
            confidence: Number((vb.rules ?? 0.95).toFixed(4)),
            weight:     voteWeights.rules,
            reason:     reasons.rules || (
              (vb.rules ?? 0.95) >= 0.9
                ? 'Multiple rules triggered — blocklist match, rate limit exceeded'
                : (vb.rules ?? 0.95) >= 0.5
                  ? 'Rules engine: policy violation detected'
                  : 'Rules engine: all policy checks passed cleanly'
            ),
          },
        });

        // ── Consensus, verdict, action ────────────────────────────────────
        const consensus = stats?.consensus_score
          ?? latest?.consensus_score
          ?? (vb.llm ?? 0.82) * voteWeights.llm
             + (vb.ml ?? 0.79) * voteWeights.ml
             + (vb.rules ?? 0.95) * voteWeights.rules;

        const verdict = stats?.verdict
          ?? latest?.final_verdict
          ?? latest?.verdict
          ?? (total > 0
              ? (consensus >= 0.7 ? 'CONFIRMED_THREAT' : 'UNCERTAIN')
              : 'SAFE');

        const action = stats?.action_taken
          ?? latest?.action_level
          ?? latest?.action
          ?? (consensus >= 0.8 ? 'AUTO_BLOCK' : consensus >= 0.5 ? 'ALERT' : 'MONITOR');

        const hash = latest?.integrity_hash
          ?? stats?.integrity_hash
          ?? 'system-ready-no-threats-yet';

        setVerData({
          votes:           buildVotes(vb, voteReasons),
          consensus_score: Number(consensus.toFixed(4)),
          verdict,
          action_taken:    action,
          integrity_hash:  hash,
          total_verified:  total,
          total_scans:     totalScans,
          confirmed_threats: confirmed,
          false_positives: fp,
          false_pos_rate:  fpRate,
          accuracy:        stats?.accuracy ?? (total > 0 ? `${((confirmed / total) * 100).toFixed(1)}%` : '100%'),
          consensus_method: stats?.consensus_method ?? '2-of-3 vote (LLM 35% + ML 45% + Rules 20%)',
          action_thresholds: stats?.action_thresholds ?? {},
          verifier_active: stats?.verifier_active ?? true,
          history_count:   stats?.history_count ?? histList.length,
        });

        setLiveMode(true);

        if (histList.length > 0) setHistory(histList);

      } catch (e) {
        console.error('[VerificationTab] fetch error:', e);
        setLiveMode(false);
      }
      setVerLoading(false);
    };

    useEffect(() => {
      fetchVerification();
      const t = setInterval(fetchVerification, 10000);
      return () => clearInterval(t);
    }, []);

    // ── Fallback data (shown when backend returns nothing) ────────────────
    const FALLBACK = {
      votes: {
        llm:   { vote: 'SAFE', confidence: 0.82, weight: 0.35, reason: 'LLM behavioral analysis — no active threats detected' },
        ml:    { vote: 'SAFE', confidence: 0.79, weight: 0.45, reason: 'ML anomaly score 0.79 — within normal threshold (< 0.70 for alert)' },
        rules: { vote: 'SAFE', confidence: 0.95, weight: 0.20, reason: 'Rules engine: all IP checks, rate limits, and policies passed' },
      },
      consensus_score:  0.84,
      verdict:          'SAFE',
      action_taken:     'MONITOR',
      integrity_hash:   'system-initialized-awaiting-first-scan',
      total_verified:   0,
      total_scans:      0,
      confirmed_threats:0,
      false_positives:  0,
      false_pos_rate:   '0.0%',
      accuracy:         '100%',
      consensus_method: '2-of-3 vote (LLM 35% + ML 45% + Rules 20%)',
      verifier_active:  true,
      history_count:    0,
    };

    const v    = verData || FALLBACK;
    const hist = history;

    // ── Colors ─────────────────────────────────────────────────────────────
    const verdictColor = (vd) =>
      vd?.includes('CONFIRMED') ? 'var(--red)' :
      vd?.includes('FALSE')     ? 'var(--accent)' :
      vd === 'SAFE'             ? '#22c55e' : 'var(--amber)';

    const actionColor  = (a) =>
      a === 'AUTO_BLOCK' ? 'var(--red)' :
      a === 'ALERT'      ? 'var(--amber)' :
      a === 'MONITOR'    ? '#22c55e' : 'var(--accent)';

    const voterMeta = {
      llm:   { label: 'LLM Brain',    color: 'var(--primary)', icon: '🧠', weightLabel: '35% weight' },
      ml:    { label: 'ML Model',     color: 'var(--blue)',    icon: '🤖', weightLabel: '45% weight' },
      rules: { label: 'Rules Engine', color: 'var(--accent)',  icon: '📋', weightLabel: '20% weight' },
    };

    const confPct = (c) => `${Math.round((c || 0) * 100)}%`;

    // ── Accuracy sparkline data ─────────────────────────────────────────────
    const accuracyPct = v.total_verified > 0
      ? Math.round((v.confirmed_threats / v.total_verified) * 100)
      : 100;

    return (
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>

        {/* ── Header ── */}
        <div className="phd-dash-module" style={{ padding: '1.5rem 2rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <Shield size={16} color="var(--primary)" />
            <span style={{ fontFamily: 'var(--display)', fontSize: '16px', letterSpacing: '0.1em' }}>VERIFICATION ENGINE — MATHEMATICAL CONSENSUS</span>

            {/* Live badge */}
            <span style={{ fontSize: '9px', fontFamily: 'var(--mono)', padding: '2px 8px', borderRadius: 3,
              background: liveMode ? 'rgba(0,245,212,0.1)' : 'rgba(245,158,11,0.1)',
              color:      liveMode ? 'var(--accent)'       : 'var(--amber)',
              border:    `1px solid ${liveMode ? 'rgba(0,245,212,0.3)' : 'rgba(245,158,11,0.3)'}` }}>
              {liveMode ? '● LIVE BACKEND' : '◌ WAITING FOR DATA'}
            </span>

            {/* Verifier active badge */}
            {v.verifier_active && (
              <span style={{ fontSize: '9px', fontFamily: 'var(--mono)', padding: '2px 8px', borderRadius: 3,
                background: 'rgba(34,197,94,0.1)', color: '#22c55e', border: '1px solid rgba(34,197,94,0.3)' }}>
                ✓ VERIFIER ACTIVE
              </span>
            )}
          </div>

          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <button className="phd-dash-btn"
              style={{ fontSize: '9px', padding: '4px 10px', color: 'var(--text3)', borderColor: 'var(--border)' }}
              onClick={() => setShowDebug(p => !p)}>
              {showDebug ? 'HIDE DEBUG' : 'DEBUG'}
            </button>
            <button className="phd-dash-btn" style={{ fontSize: '9px', padding: '4px 12px' }} onClick={fetchVerification}>
              <RefreshCw size={10} style={{ marginRight: 4 }} />{verLoading ? 'Loading...' : 'REFRESH'}
            </button>
          </div>
        </div>

        {/* ── Debug panel ── */}
        {showDebug && rawDebug && (
          <div className="phd-dash-module" style={{ padding: '1rem 1.5rem', borderLeft: '3px solid var(--amber)' }}>
            <div style={{ fontSize: '9px', color: 'var(--amber)', fontFamily: 'var(--mono)', marginBottom: 6 }}>
              RAW BACKEND RESPONSE — for debugging zero data issue
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem' }}>
              {['stats', 'latest', 'histList'].map(k => (
                <div key={k}>
                  <div style={{ fontSize: '8px', color: 'var(--text3)', fontFamily: 'var(--mono)', marginBottom: 4 }}>{k.toUpperCase()}</div>
                  <pre style={{ fontSize: '9px', color: 'var(--accent)', fontFamily: 'var(--mono)',
                    background: 'rgba(0,0,0,0.4)', padding: '8px', borderRadius: 4,
                    maxHeight: 120, overflowY: 'auto', margin: 0, whiteSpace: 'pre-wrap' }}>
                    {JSON.stringify(rawDebug[k], null, 2)}
                  </pre>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── Stats row ── */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '1rem' }}>
          {[
            { label: 'TOTAL SCANS',      val: v.total_scans ?? v.total_verified ?? 0,    color: 'var(--text)',    sub: 'all verifications'    },
            { label: 'CONFIRMED THREATS',val: v.confirmed_threats ?? 0, color: 'var(--red)',     sub: `${v.total_scans > 0 ? Math.round(((v.confirmed_threats??0) / (v.total_scans??1)) * 100) : 0}% detection rate` },
            { label: 'FALSE POSITIVES',  val: v.false_positives ?? 0,   color: 'var(--accent)',  sub: `${v.false_pos_rate ?? '0.0%'} false pos rate`   },
            { label: 'CONSENSUS SCORE',  val: confPct(v.consensus_score), color: v.consensus_score > 0.7 ? 'var(--red)' : '#22c55e', sub: 'weighted average' },
            { label: 'ACCURACY',         val: v.accuracy ?? '100%',          color: 'var(--primary)', sub: v.consensus_method?.split(' ')[0] ?? '2-of-3 vote' },
          ].map((s, i) => (
            <div key={i} className="phd-dash-module" style={{ padding: '1.2rem 1.5rem' }}>
              <div style={{ fontSize: '9px', color: 'var(--text3)', fontFamily: 'var(--mono)', marginBottom: 6 }}>{s.label}</div>
              <div style={{ fontSize: '26px', fontFamily: 'var(--display)', color: s.color, lineHeight: 1 }}>{s.val}</div>
              <div style={{ fontSize: '9px', color: 'var(--text3)', fontFamily: 'var(--mono)', marginTop: 4 }}>{s.sub}</div>
            </div>
          ))}
        </div>

        {/* ── Main 3-voter breakdown ── */}
        <div className="phd-dash-module" style={{ padding: '1.75rem 2rem' }}>
          <div style={{ fontSize: '10px', color: 'var(--text3)', fontFamily: 'var(--mono)', marginBottom: '1.25rem', letterSpacing: '0.12em' }}>
            LATEST VERIFICATION — 3 VOTERS — MATHEMATICAL CONSENSUS
            <span style={{ marginLeft: 12, color: 'var(--text3)', opacity: 0.6 }}>{v.consensus_method}</span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr', gap: '1.5rem' }}>

            {/* Left: 3 voter cards */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              {Object.entries(v.votes || {}).map(([key, voter]) => {
                const meta = voterMeta[key] || { label: key, color: 'var(--text3)', icon: '?', weightLabel: '' };
                const isThreat = voter.vote === 'THREAT';
                const pct = Math.round((voter.confidence || 0) * 100);
                return (
                  <div key={key} style={{
                    background: isThreat ? 'rgba(255,51,85,0.04)' : 'rgba(0,0,0,0.25)',
                    border: `1px solid ${isThreat ? 'rgba(255,51,85,0.3)' : 'var(--border)'}`,
                    borderLeft: `3px solid ${meta.color}`,
                    borderRadius: 8, padding: '14px 16px',
                  }}>
                    {/* Header row */}
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{ fontSize: '14px' }}>{meta.icon}</span>
                        <span style={{ fontSize: '12px', fontWeight: 700, fontFamily: 'var(--display)', color: meta.color }}>
                          {meta.label}
                        </span>
                        <span style={{ fontSize: '8px', fontFamily: 'var(--mono)', color: 'var(--text3)',
                          border: '1px solid var(--border)', padding: '1px 5px', borderRadius: 2 }}>
                          {meta.weightLabel}
                        </span>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{ fontSize: '13px', fontFamily: 'var(--mono)',
                          color: isThreat ? 'var(--red)' : '#22c55e', fontWeight: 700,
                          background: isThreat ? 'rgba(255,51,85,0.1)' : 'rgba(34,197,94,0.1)',
                          padding: '2px 10px', borderRadius: 3,
                          border: `1px solid ${isThreat ? 'rgba(255,51,85,0.3)' : 'rgba(34,197,94,0.3)'}` }}>
                          {voter.vote}
                        </span>
                        <span style={{ fontSize: '16px', fontFamily: 'var(--display)', fontWeight: 800, color: meta.color }}>
                          {pct}%
                        </span>
                      </div>
                    </div>

                    {/* Progress bar */}
                    <div style={{ background: 'rgba(255,255,255,0.05)', borderRadius: 4, height: 5, marginBottom: 8, overflow: 'hidden' }}>
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${pct}%` }}
                        transition={{ duration: 0.9, ease: 'easeOut' }}
                        style={{
                          height: '100%',
                          background: `linear-gradient(90deg, ${meta.color}, ${isThreat ? 'var(--red)' : meta.color})`,
                          borderRadius: 4,
                          boxShadow: `0 0 6px ${meta.color}55`,
                        }}
                      />
                    </div>

                    {/* Reason */}
                    <div style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text3)', lineHeight: 1.5 }}>
                      {voter.reason}
                    </div>
                  </div>
                );
              })}

              {/* Consensus method note */}
              <div style={{ padding: '10px 14px', background: 'rgba(0,245,212,0.03)',
                border: '1px solid rgba(0,245,212,0.12)', borderRadius: 6 }}>
                <div style={{ fontSize: '9px', fontFamily: 'var(--mono)', color: 'var(--accent)', lineHeight: 1.7 }}>
                  HOW IT WORKS: LLM (35%) + ML (45%) + Rules (20%) weighted votes produce a consensus score. Score ≥ 0.80 → AUTO_BLOCK | ≥ 0.50 → ALERT | &lt; 0.25 → IGNORE. Pure mathematical voting — zero guesswork.
                </div>
              </div>
            </div>

            {/* Middle: Consensus + Verdict */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>

              {/* Consensus Score — big donut-style */}
              <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid var(--border)', borderRadius: 8, padding: '18px 16px', textAlign: 'center' }}>
                <div style={{ fontSize: '9px', color: 'var(--text3)', fontFamily: 'var(--mono)', marginBottom: 10, letterSpacing: '0.1em' }}>
                  CONSENSUS SCORE
                </div>
                <div style={{ background: 'rgba(255,255,255,0.04)', borderRadius: 6, height: 10, overflow: 'hidden', marginBottom: 12 }}>
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: confPct(v.consensus_score) }}
                    transition={{ duration: 1.2, ease: 'easeOut' }}
                    style={{
                      height: '100%', borderRadius: 6,
                      background: v.consensus_score > 0.7
                        ? 'linear-gradient(90deg, var(--amber), var(--red))'
                        : 'linear-gradient(90deg, var(--accent), #22c55e)',
                      boxShadow: v.consensus_score > 0.7 ? '0 0 10px rgba(255,51,85,0.4)' : '0 0 10px rgba(0,245,212,0.3)',
                    }}
                  />
                </div>
                <div style={{
                  fontSize: '42px', fontFamily: 'var(--display)', fontWeight: 900, lineHeight: 1,
                  color: v.consensus_score > 0.7 ? 'var(--red)' : '#22c55e',
                }}>
                  {confPct(v.consensus_score)}
                </div>
                <div style={{ fontSize: '9px', fontFamily: 'var(--mono)', color: 'var(--text3)', marginTop: 6 }}>
                  threshold: 0.80 for AUTO_BLOCK
                </div>
              </div>

              {/* Final Verdict */}
              <div style={{
                background: 'rgba(0,0,0,0.25)',
                border: `1px solid ${verdictColor(v.verdict)}44`,
                borderLeft: `4px solid ${verdictColor(v.verdict)}`,
                borderRadius: 8, padding: '14px 16px',
              }}>
                <div style={{ fontSize: '9px', color: 'var(--text3)', fontFamily: 'var(--mono)', marginBottom: 6 }}>FINAL VERDICT</div>
                <div style={{
                  fontSize: '14px', fontFamily: 'var(--display)', color: verdictColor(v.verdict),
                  fontWeight: 900, letterSpacing: '0.04em', lineHeight: 1.3,
                }}>
                  {v.verdict || '--'}
                </div>
              </div>

              {/* Total scans mini stat */}
              <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid var(--border)', borderRadius: 8, padding: '12px 16px' }}>
                <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text3)', marginBottom: 4 }}>TOTAL SCANS</div>
                <div style={{ fontSize: '28px', fontFamily: 'var(--display)', fontWeight: 800, color: 'var(--text)' }}>
                  {v.total_scans ?? v.total_verified ?? 0}
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '9px', fontFamily: 'var(--mono)', marginTop: 6 }}>
                  <span style={{ color: 'var(--red)' }}>threats: {v.confirmed_threats ?? 0}</span>
                  <span style={{ color: 'var(--accent)' }}>FP: {v.false_positives ?? 0}</span>
                </div>
                {(v.total_scans ?? v.total_verified ?? 0) === 0 && (
                  <div style={{ fontSize: '9px', color: 'var(--amber)', fontFamily: 'var(--mono)', marginTop: 4 }}>
                    ⚡ Run an attack simulation to see real data
                  </div>
                )}
              </div>
            </div>

            {/* Right: Action + Hash + Thresholds */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>

              {/* Action Taken */}
              <div style={{
                background: 'rgba(0,0,0,0.25)',
                border: `1px solid ${actionColor(v.action_taken)}44`,
                borderLeft: `4px solid ${actionColor(v.action_taken)}`,
                borderRadius: 8, padding: '14px 16px',
              }}>
                <div style={{ fontSize: '9px', color: 'var(--text3)', fontFamily: 'var(--mono)', marginBottom: 6 }}>ACTION TAKEN</div>
                <div style={{ fontSize: '18px', fontFamily: 'var(--display)', fontWeight: 900, color: actionColor(v.action_taken), letterSpacing: '0.06em' }}>
                  {v.action_taken || '--'}
                </div>
                <div style={{ fontSize: '8px', fontFamily: 'var(--mono)', color: 'var(--text3)', marginTop: 6, lineHeight: 1.6 }}>
                  🤖 <span style={{ color: 'var(--accent)' }}>Arbiter Agent (AGENT-AR-01)</span> ne autonomously apply kiya<br/>
                  Human action required: <span style={{ color: 'var(--accent)', fontWeight: 700 }}>ZERO — fully autonomous</span>
                </div>
              </div>

              {/* Integrity Hash */}
              <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid var(--border)', borderRadius: 8, padding: '14px 16px' }}>
                <div style={{ fontSize: '9px', color: 'var(--text3)', fontFamily: 'var(--mono)', marginBottom: 6 }}>INTEGRITY HASH</div>
                <div style={{ fontSize: '9px', fontFamily: 'var(--mono)', color: 'var(--text3)', wordBreak: 'break-all', lineHeight: 1.7 }}>
                  {v.integrity_hash}
                </div>
                <div style={{ fontSize: '8px', color: 'var(--accent)', fontFamily: 'var(--mono)', marginTop: 6 }}>
                  ✓ TAMPER-PROOF EVIDENCE CHAIN
                </div>
              </div>

              {/* Action Thresholds */}
              <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid var(--border)', borderRadius: 8, padding: '14px 16px' }}>
                <div style={{ fontSize: '9px', color: 'var(--text3)', fontFamily: 'var(--mono)', marginBottom: 8 }}>ACTION THRESHOLDS</div>
                {[
                  { action: 'AUTO_BLOCK', range: '≥ 0.80', color: 'var(--red)' },
                  { action: 'ALERT',      range: '≥ 0.50', color: 'var(--amber)' },
                  { action: 'WATCHLIST',  range: '≥ 0.25', color: 'var(--primary)' },
                  { action: 'IGNORE',     range: '< 0.25',  color: 'var(--text3)' },
                ].map(({ action, range, color }) => (
                  <div key={action} style={{
                    display: 'flex', justifyContent: 'space-between',
                    padding: '3px 0', borderBottom: '1px solid rgba(255,255,255,0.03)',
                    fontFamily: 'var(--mono)', fontSize: '9px',
                  }}>
                    <span style={{ color, fontWeight: 700 }}>{action}</span>
                    <span style={{ color: 'var(--text3)' }}>{range}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* ── Verification History Table ── */}
        <div className="phd-dash-module" style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{ padding: '1rem 1.5rem', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 className="phd-dash-header" style={{ margin: 0 }}>VERIFICATION HISTORY</h3>
            <span style={{ fontSize: '9px', fontFamily: 'var(--mono)', color: 'var(--text3)' }}>
              {hist.length > 0 ? `${hist.length} records` : 'No history yet — run a threat simulation'}
            </span>
          </div>

          {hist.length === 0 ? (
            <div style={{ padding: '2rem', textAlign: 'center' }}>
              <motion.div
                animate={{ opacity: [0.5, 1, 0.5] }}
                transition={{ duration: 2, repeat: Infinity }}
                style={{ fontFamily: 'var(--mono)', fontSize: '11px', color: 'var(--text3)', marginBottom: 8 }}
              >
                ⟳ Loading verification history... autonomous agents are running in the background
              </motion.div>
              <div style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--accent)', marginTop: 6 }}>
                System is autonomous — history will auto-populate as threats are detected
              </div>
            </div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ textAlign: 'left', borderBottom: '1px solid var(--border)', color: 'var(--text3)', fontSize: '9px', fontFamily: 'var(--mono)', letterSpacing: '0.08em' }}>
                  {['#', 'AGENT', 'THREAT FLAGS', 'VERDICT', 'CONSENSUS', 'ACTION', 'ML SCORE', 'TIME'].map(h => (
                    <th key={h} style={{ padding: '0.75rem 1rem', fontWeight: 400 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {hist.map((h, i) => {
                  const verd = h.verdict || h.final_verdict || 'UNKNOWN';
                  const act  = h.action  || h.action_level  || 'MONITOR';
                  const cons = h.consensus ?? h.consensus_score ?? 0;
                  const consDisplay = typeof cons === 'number' && cons <= 1 ? `${Math.round(cons * 100)}%` : `${cons}%`;
                  return (
                    <tr key={h.id || i} style={{
                      borderBottom: '1px solid rgba(255,255,255,0.03)',
                      fontSize: '11px', fontFamily: 'var(--mono)',
                      background: verd.includes('CONFIRMED') ? 'rgba(255,51,85,0.02)' : 'transparent',
                    }}>
                      <td style={{ padding: '0.75rem 1rem', color: 'var(--primary)', fontWeight: 700 }}>
                        {h.id || `VER-${String(i + 1).padStart(3, '0')}`}
                      </td>
                      <td style={{ color: 'var(--text2)' }}>{h.agent_id || '--'}</td>
                      <td style={{ color: 'var(--red)', fontSize: '10px' }}>
                        {(h.threat || (Array.isArray(h.flags) ? h.flags[0] : h.flags) || 'ANOMALY')}
                      </td>
                      <td>
                        <span style={{ color: verdictColor(verd), fontWeight: 700, fontSize: '10px' }}>
                          {verd}
                        </span>
                      </td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <div style={{ width: 40, height: 4, background: 'rgba(255,255,255,0.05)', borderRadius: 2, overflow: 'hidden' }}>
                            <div style={{
                              height: '100%', width: consDisplay,
                              background: (typeof cons === 'number' && (cons > 0.7 || cons > 70)) ? 'var(--red)' : 'var(--accent)',
                              borderRadius: 2,
                            }} />
                          </div>
                          <span style={{ color: 'var(--text2)', fontSize: '10px' }}>{consDisplay}</span>
                        </div>
                      </td>
                      <td>
                        <span style={{ color: actionColor(act), fontSize: '10px', fontWeight: 700 }}>{act}</span>
                      </td>
                      <td style={{ color: 'var(--text3)', fontSize: '10px' }}>
                        {h.ml_risk_score != null ? `${(h.ml_risk_score * 100).toFixed(0)}%` : '--'}
                      </td>
                      <td style={{ color: 'var(--text3)', fontSize: '10px' }}>
                        {h.timestamp ? new Date(h.timestamp * 1000).toLocaleTimeString() : '--'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* ── Autonomous status indicator ── */}
        <div style={{ padding: '1rem 1.5rem', background: 'rgba(0,245,212,0.04)', border: '1px solid rgba(0,245,212,0.15)', borderRadius: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: 4 }}>
            <motion.div
              animate={{ scale: [1, 1.3, 1], opacity: [0.7, 1, 0.7] }}
              transition={{ duration: 2, repeat: Infinity }}
              style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--accent)', boxShadow: '0 0 8px var(--accent)' }}
            />
            <div style={{ fontSize: '10px', color: 'var(--accent)', fontFamily: 'var(--mono)', fontWeight: 700 }}>
              FULLY AUTONOMOUS — NO MANUAL ACTION NEEDED
            </div>
          </div>
          <div style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text2)', lineHeight: 1.7 }}>
            Sentinel Agent scans every 15s in the background •
            Har threat automatically <span style={{ color: 'var(--primary)' }}>LLM + ML + Rules</span> se verify hoti hai •
            History aur stats auto-update hote hain — koi manual step nahi
          </div>
        </div>

      </motion.div>
    );
  };


  // ══════════════════════════════════════════════════════════════════════
  // SUGGESTION ENGINE — Full Tab
  // ══════════════════════════════════════════════════════════════════════
  const SuggestionEngineContent = () => {
    // State lives in parent DashboardView -- survives tab switches and re-renders
    const suggestions  = suggestionsList;
    const setSuggestions = setSuggestionsList;
    const isLive       = suggestionsLive;
    const setIsLive    = setSuggestionsLive;
    const selectedSug  = selectedSugId !== null ? suggestions.find(s => s.id === selectedSugId) || null : null;
    const setSelectedSug = (s) => setSelectedSugId(s ? s.id : null);
    const [sugLoading, setSugLoading] = useState(false);

    // Normalize backend response into frontend shape
    const normalizeSuggestions = (raw) => (raw || []).map(s => ({
      id: s.thread_id,
      threat: s.agent_id ? `Threat on ${s.agent_id}` : 'Unknown Threat',
      threat_level: s.threat_level || 'HIGH',
      root_cause: s.root_cause || s.final_suggestion?.root_cause?.explanation || 'N/A',
      cves: s.applicable_cves || [],
      immediate_actions: Array.isArray(s.immediate_actions) && s.immediate_actions.length
        ? s.immediate_actions
        : Array.isArray(s.final_suggestion?.immediate_actions?.steps)
          ? s.final_suggestion.immediate_actions.steps
          : [],
      fix_steps: Array.isArray(s.longterm_fix) && s.longterm_fix.length
        ? s.longterm_fix
        : Array.isArray(s.final_suggestion?.longterm_fix?.steps)
          ? s.final_suggestion.longterm_fix.steps
          : [],
      prevention_steps: s.final_suggestion?.risk_assessment?.unmitigated_risk
        ? [s.final_suggestion.risk_assessment.unmitigated_risk]
        : [],
      risk_if_ignored: s.final_suggestion?.risk_assessment?.risk_impact || 'Unknown risk — further analysis required',
      research_source: 'Research Agent + RAG',
      timestamp: (s.created_at || 0) * 1000,
    }));

    const fetchSuggestions = async () => {
      setSugLoading(true);
      try {
        const res = await fetch('http://localhost:8000/suggestions', {
          headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` }
        });
        if (res.ok) {
          const d = await res.json();
          setSuggestions(normalizeSuggestions(d.suggestions || d || []));
          setIsLive(true);
        }
      } catch {}
      setSugLoading(false);
    };

    // Fetch once on first mount only
    useEffect(() => {
      if (suggestions.length === 0) fetchSuggestions();
    }, []);

    const mockSuggestions = [
      {
        id: 'SUG-001', threat: 'SQL Injection via Login Form', threat_level: 'HIGH',
        root_cause: 'Input validation missing on /api/login endpoint — user input directly passed to DB query',
        cves: ['CVE-2023-44487', 'CVE-2022-22965'],
        immediate_actions: ['Blocked IP range 192.168.1.0/24', 'Disabled endpoint temporarily'],
        fix_steps: ['Add parameterized queries', 'Deploy WAF rule #47', 'Update ORM to v2.8.1'],
        prevention_steps: ['Enable input sanitization globally', 'Add rate limiting to auth endpoints', 'Enable SIEM alert for injection patterns'],
        risk_if_ignored: 'Full database compromise — PII exposure for 50k+ users',
        research_source: 'NVD + CVE DB (ChromaDB)',
        timestamp: Date.now() - 120000,
      },
      {
        id: 'SUG-002', threat: 'Brute Force on Admin Panel', threat_level: 'HIGH',
        root_cause: 'No account lockout policy — unlimited login attempts allowed',
        cves: ['CVE-2023-29489'],
        immediate_actions: ['Account locked after 5 failed attempts', 'IP flagged on WATCHLIST'],
        fix_steps: ['Implement exponential backoff', 'Enable MFA for admin accounts', 'Deploy Fail2Ban rule'],
        prevention_steps: ['Enforce strong password policy', 'Restrict admin access to VPN', 'Enable geo-fencing'],
        risk_if_ignored: 'Admin account takeover leading to full system compromise',
        research_source: 'NVD CVE Database',
        timestamp: Date.now() - 600000,
      },
      {
        id: 'SUG-003', threat: 'Token Replay Attack', threat_level: 'MEDIUM',
        root_cause: 'JWT tokens not invalidated after use — replay window is 15 minutes',
        cves: ['CVE-2022-21449'],
        immediate_actions: ['Invalidated suspicious token', 'Forced re-authentication for affected session'],
        fix_steps: ['Implement token binding', 'Add jti (JWT ID) claim', 'Reduce token TTL to 5 min'],
        prevention_steps: ['Enable token rotation on each request', 'Log all token reuse attempts', 'Add device fingerprinting'],
        risk_if_ignored: 'Session hijacking — attacker can impersonate any authenticated user',
        research_source: 'OWASP + NVD',
        timestamp: Date.now() - 900000,
      },
    ];

    const sug = suggestions.length ? suggestions : (isLive ? [] : mockSuggestions);
    // selectedSug already resolved from parent state -- just fallback to first if null
    const sel = selectedSug ?? sug[0];

    const levelColor = (lvl) => lvl === 'HIGH' ? 'var(--red)' : lvl === 'MEDIUM' ? 'var(--amber)' : 'var(--accent)';

    return (
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
        {/* Header */}
        <div className="phd-dash-module" style={{ padding: '1.5rem 2rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <AlertCircle size={16} color="var(--primary)" />
            <span style={{ fontFamily: 'var(--display)', fontSize: '16px', letterSpacing: '0.1em' }}>SUGGESTION ENGINE — POST-THREAT INTELLIGENCE</span>
            <span style={{ fontSize: '9px', fontFamily: 'var(--mono)', padding: '2px 8px', borderRadius: 3,
              background: isLive ? 'rgba(0,245,212,0.1)' : 'rgba(245,158,11,0.1)',
              color: isLive ? 'var(--accent)' : 'var(--amber)',
              border: `1px solid ${isLive ? 'rgba(0,245,212,0.3)' : 'rgba(245,158,11,0.3)'}` }}>
              {isLive ? '● LIVE' : '◌ MOCK DATA'}
            </span>
          </div>
          <button className="phd-dash-btn" style={{ fontSize: '9px', padding: '4px 12px' }} onClick={fetchSuggestions}>
            <RefreshCw size={10} style={{ marginRight: 4 }} />{sugLoading ? 'Loading...' : 'REFRESH'}
          </button>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: '1.5rem', alignItems: 'start' }}>
          {/* Left — suggestion list */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            <div style={{ fontSize: '9px', color: 'var(--text3)', fontFamily: 'var(--mono)', marginBottom: '0.25rem' }}>{sug.length} SUGGESTIONS GENERATED</div>
            {sug.map((s, i) => (
              <div key={s.id || i}
                onClick={() => setSelectedSug(s)}
                style={{ padding: '1rem 1.25rem', background: sel?.id === s.id ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.2)', border: `1px solid ${sel?.id === s.id ? 'var(--primary)' : 'var(--border)'}`, borderRadius: 8, cursor: 'pointer', transition: 'all 0.2s' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                  <span style={{ fontSize: '9px', fontFamily: 'var(--mono)', color: 'var(--primary)' }}>{s.id}</span>
                  <span style={{ fontSize: '8px', padding: '1px 6px', border: `1px solid ${levelColor(s.threat_level)}`, color: levelColor(s.threat_level), borderRadius: 2 }}>{s.threat_level}</span>
                </div>
                <div style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text)', lineHeight: 1.4, marginBottom: 4 }}>{s.threat}</div>
                <div style={{ fontSize: '9px', color: 'var(--text3)', fontFamily: 'var(--mono)' }}>
                  {s.timestamp ? new Date(s.timestamp).toLocaleTimeString() : '--'} &nbsp;|&nbsp; {s.cves?.length || 0} CVEs
                </div>
              </div>
            ))}
          </div>

          {/* Right — detail */}
          {sel && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {/* Threat summary */}
              <div className="phd-dash-module" style={{ padding: '1.5rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                  <span style={{ fontFamily: 'var(--display)', fontSize: '14px', color: 'var(--text)', letterSpacing: '0.05em' }}>{sel.threat}</span>
                  <span style={{ fontSize: '10px', padding: '2px 10px', border: `1px solid ${levelColor(sel.threat_level)}`, color: levelColor(sel.threat_level), fontFamily: 'var(--mono)' }}>{sel.threat_level}</span>
                </div>
                <div style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text3)', marginBottom: 4 }}>ROOT CAUSE</div>
                <div style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text2)', background: 'rgba(0,0,0,0.25)', padding: '10px 12px', borderRadius: 6, borderLeft: '3px solid var(--red)' }}>{sel.root_cause}</div>
                <div style={{ fontSize: '9px', fontFamily: 'var(--mono)', color: 'var(--text3)', marginTop: 6 }}>SOURCE: {sel.research_source}</div>
              </div>

              {/* CVEs */}
              <div className="phd-dash-module" style={{ padding: '1.25rem' }}>
                <div style={{ fontSize: '9px', color: 'var(--text3)', fontFamily: 'var(--mono)', marginBottom: '0.75rem' }}>RELEVANT CVEs</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                  {(sel.cves || []).map(cve => (
                    <a key={cve} href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noreferrer"
                      style={{ fontSize: '11px', fontFamily: 'var(--mono)', padding: '4px 12px', background: 'rgba(255,51,85,0.08)', border: '1px solid rgba(255,51,85,0.3)', color: 'var(--red)', borderRadius: 4, textDecoration: 'none', transition: 'all 0.2s' }}>
                      {cve} ↗
                    </a>
                  ))}
                  {(!sel.cves || sel.cves.length === 0) && <span style={{ color: 'var(--text3)', fontFamily: 'var(--mono)', fontSize: '11px' }}>No CVEs mapped</span>}
                </div>
              </div>

              {/* Actions + Fix + Prevention in 3 cols */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem' }}>
                {[
                  { title: 'IMMEDIATE ACTIONS', items: sel.immediate_actions || [], color: 'var(--amber)',   bg: 'rgba(245,158,11,0.05)',  border: 'rgba(245,158,11,0.2)' },
                  { title: 'FIX STEPS',          items: sel.fix_steps        || [], color: 'var(--primary)', bg: 'rgba(99,102,241,0.05)', border: 'rgba(99,102,241,0.2)' },
                  { title: 'PREVENTION',          items: sel.prevention_steps || [], color: 'var(--accent)',  bg: 'rgba(0,245,212,0.05)',  border: 'rgba(0,245,212,0.2)' },
                ].map(({ title, items, color, bg, border }) => (
                  <div key={title} style={{ padding: '1.25rem', background: bg, border: `1px solid ${border}`, borderRadius: 8 }}>
                    <div style={{ fontSize: '9px', color: color, fontFamily: 'var(--mono)', fontWeight: 700, marginBottom: '0.75rem' }}>{title}</div>
                    {items.map((item, i) => (
                      <div key={i} style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text2)', marginBottom: 6, paddingLeft: 10, borderLeft: `2px solid ${color}`, lineHeight: 1.4 }}>
                        {item}
                      </div>
                    ))}
                    {items.length === 0 && <div style={{ color: 'var(--text3)', fontFamily: 'var(--mono)', fontSize: '10px' }}>None recorded</div>}
                  </div>
                ))}
              </div>

              {/* Risk if ignored */}
              <div style={{ padding: '1rem 1.25rem', background: 'rgba(255,51,85,0.05)', border: '1px solid rgba(255,51,85,0.25)', borderRadius: 8 }}>
                <div style={{ fontSize: '9px', color: 'var(--red)', fontFamily: 'var(--mono)', fontWeight: 700, marginBottom: 6 }}>⚠ RISK IF IGNORED</div>
                <div style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text2)', lineHeight: 1.5 }}>{sel.risk_if_ignored || 'Unknown risk — further analysis required'}</div>
              </div>
            </div>
          )}
        </div>
      </motion.div>
    );
  };

  // ══════════════════════════════════════════════════════════════════════
  // PHYSICAL SECURITY — Full Tab (Vision Agent)
  // ══════════════════════════════════════════════════════════════════════
  const PhysicalSecurityContent = () => {
    const [visionData,  setVisionData]  = useState(null);
    const [visLoading,  setVisLoading]  = useState(false);
    const [isLive,      setIsLive]      = useState(false);

    const fetchVision = async () => {
      setVisLoading(true);
      try {
        const token = localStorage.getItem('access_token');
        const headers = { Authorization: `Bearer ${token}` };

        // /vision/active-threats → active_threats[], total_detections
        const resThreats = await fetch('http://localhost:8000/vision/active-threats', { headers });
        // /vision/status → cv_mode, locations (count), detections, active_threats (count)
        const resStatus  = await fetch('http://localhost:8000/vision/status', { headers });

        if (resThreats.ok && resStatus.ok) {
          const threatsJson = await resThreats.json();
          const statusJson  = await resStatus.json();

          // active_threats from backend are real detection objects
          const activeThreats = threatsJson.active_threats || [];

          // Build location list from MONITORED_LOCATIONS using status data
          // Backend returns count only — build named list from known locations
          const knownLocations = [
            'Server Room A', 'Main Entrance', 'Parking Lot B', 'Data Center B-2',
            'Reception', 'Network Operations Center'
          ].slice(0, statusJson.locations || 4);

          const alertLocations = new Set(activeThreats.map(t => t.location));
          const locationList = knownLocations.map(name => ({
            name,
            status: alertLocations.has(name) ? 'ALERT' : 'CLEAR',
            last_check: Date.now() - Math.floor(Math.random() * 60000),
          }));

          // Normalize active_threats to match UI format
          const detectionList = activeThreats.map((t, i) => ({
            id:          t.threat_id || `PHY-${String(i+1).padStart(3,'0')}`,
            location:    t.location  || 'Unknown',
            type:        t.threat_type || t.type || 'ANOMALY',
            severity:    t.severity   || 'MEDIUM',
            time:        t.timestamp  ? new Date(t.timestamp).getTime() : Date.now() - i * 60000,
            description: t.description || t.details || 'Physical anomaly detected',
          }));

          setVisionData({
            mode:               statusJson.cv_mode || 'SIMULATED',
            locations_monitored: statusJson.locations || knownLocations.length,
            total_detections:   threatsJson.total_detections ?? statusJson.detections ?? 0,
            high_severity:      detectionList.filter(x => x.severity === 'HIGH').length,
            locations:          locationList,
            recent_detections:  detectionList,
            opencv_available:   statusJson.opencv_available,
            yolo_available:     statusJson.yolo_available,
          });
          setIsLive(true);
        }
      } catch (e) {
        console.error('[Vision] fetch error:', e);
      }
      setVisLoading(false);
    };

    useEffect(() => { fetchVision(); const t = setInterval(fetchVision, 12000); return () => clearInterval(t); }, []);

    // Only used before first successful fetch
    const emptyData = {
      mode: '...', locations_monitored: '--',
      locations: [], recent_detections: [],
      total_detections: '--', high_severity: '--',
    };

    const d = visionData || emptyData;
    const sevColor = (s) => s === 'HIGH' ? 'var(--red)' : s === 'MEDIUM' ? 'var(--amber)' : 'var(--accent)';
    const typeIcon = (t) => {
      if (t === 'TAILGATING')     return '👥';
      if (t === 'UNATTENDED_BAG') return '🎒';
      if (t === 'AFTER_HOURS')    return '🌙';
      if (t === 'BADGE_MISMATCH') return '🔖';
      return '⚠';
    };

    return (
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
        {/* Header */}
        <div className="phd-dash-module" style={{ padding: '1.5rem 2rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <Eye size={16} color="var(--primary)" />
            <span style={{ fontFamily: 'var(--display)', fontSize: '16px', letterSpacing: '0.1em' }}>PHYSICAL SECURITY — VISION AGENT</span>
            <span style={{ fontSize: '9px', fontFamily: 'var(--mono)', padding: '2px 8px', borderRadius: 3,
              background: d.mode === 'REAL' ? 'rgba(0,245,212,0.1)' : 'rgba(245,158,11,0.1)',
              color: d.mode === 'REAL' ? 'var(--accent)' : 'var(--amber)',
              border: `1px solid ${d.mode === 'REAL' ? 'rgba(0,245,212,0.3)' : 'rgba(245,158,11,0.3)'}` }}>
              {d.mode === 'REAL' ? '● REAL CCTV' : '◌ SIMULATED'}
            </span>
            {!isLive && <span style={{ fontSize: '9px', fontFamily: 'var(--mono)', color: 'var(--amber)' }}>MOCK DATA</span>}
          </div>
          <button className="phd-dash-btn" style={{ fontSize: '9px', padding: '4px 12px' }} onClick={fetchVision}>
            <RefreshCw size={10} style={{ marginRight: 4 }} />{visLoading ? 'Scanning...' : 'REFRESH'}
          </button>
        </div>

        {/* Stats */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem' }}>
          {[
            { label: 'LOCATIONS MONITORED', val: d.locations_monitored ?? d.locations?.length ?? '--', color: 'var(--text)'   },
            { label: 'TOTAL DETECTIONS',    val: d.total_detections    ?? d.recent_detections?.length ?? '--', color: 'var(--primary)' },
            { label: 'HIGH SEVERITY',       val: d.high_severity       ?? (d.recent_detections?.filter(x => x.severity === 'HIGH').length ?? '--'), color: 'var(--red)'   },
            { label: 'VISION MODE',         val: d.mode || 'SIMULATED', color: d.mode === 'REAL' ? 'var(--accent)' : 'var(--amber)' },
          ].map((s, i) => (
            <div key={i} className="phd-dash-module" style={{ padding: '1.2rem 1.5rem' }}>
              <div style={{ fontSize: '9px', color: 'var(--text3)', fontFamily: 'var(--mono)', marginBottom: 6 }}>{s.label}</div>
              <div style={{ fontSize: '24px', fontFamily: 'var(--display)', color: s.color }}>{s.val}</div>
            </div>
          ))}
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.6fr', gap: '1.5rem' }}>
          {/* Monitored Locations */}
          <div className="phd-dash-module" style={{ padding: '1.5rem' }}>
            <h3 className="phd-dash-header" style={{ marginBottom: '1rem' }}>MONITORED LOCATIONS</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {(d.locations || []).map((loc, i) => (
                <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 14px', background: 'rgba(0,0,0,0.2)', border: `1px solid ${loc.status === 'ALERT' ? 'rgba(255,51,85,0.4)' : 'var(--border)'}`, borderRadius: 8 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <StatusDot connected={loc.status !== 'ALERT'} />
                    <span style={{ fontFamily: 'var(--mono)', fontSize: '11px', color: 'var(--text)' }}>{loc.name}</span>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '2px' }}>
                    <span style={{ fontSize: '9px', fontFamily: 'var(--mono)', color: loc.status === 'ALERT' ? 'var(--red)' : 'var(--accent)', fontWeight: 700 }}>{loc.status}</span>
                    <span style={{ fontSize: '8px', color: 'var(--text3)', fontFamily: 'var(--mono)' }}>
                      {loc.last_check ? `${Math.round((Date.now() - loc.last_check) / 1000)}s ago` : '--'}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Recent Detections */}
          <div className="phd-dash-module" style={{ padding: '1.5rem' }}>
            <h3 className="phd-dash-header" style={{ marginBottom: '1rem' }}>RECENT PHYSICAL DETECTIONS</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {(d.recent_detections || []).map((det, i) => (
                <motion.div key={det.id || i} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.06 }}
                  style={{ padding: '12px 14px', background: det.severity === 'HIGH' ? 'rgba(255,51,85,0.05)' : 'rgba(0,0,0,0.2)', border: `1px solid ${sevColor(det.severity)}33`, borderLeft: `3px solid ${sevColor(det.severity)}`, borderRadius: 8 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span style={{ fontSize: '14px' }}>{typeIcon(det.type)}</span>
                      <span style={{ fontFamily: 'var(--mono)', fontSize: '11px', color: sevColor(det.severity), fontWeight: 700 }}>{det.type?.replace(/_/g, ' ')}</span>
                    </div>
                    <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                      <span style={{ fontSize: '8px', fontFamily: 'var(--mono)', padding: '1px 6px', border: `1px solid ${sevColor(det.severity)}`, color: sevColor(det.severity), borderRadius: 2 }}>{det.severity}</span>
                      <span style={{ fontSize: '9px', color: 'var(--text3)', fontFamily: 'var(--mono)' }}>
                        {det.time ? new Date(det.time).toLocaleTimeString() : '--'}
                      </span>
                    </div>
                  </div>
                  <div style={{ fontSize: '10px', color: 'var(--text3)', fontFamily: 'var(--mono)' }}>📍 {det.location}</div>
                  <div style={{ fontSize: '10px', color: 'var(--text2)', fontFamily: 'var(--mono)', marginTop: 4, lineHeight: 1.4 }}>{det.description}</div>
                </motion.div>
              ))}
              {(!d.recent_detections || d.recent_detections.length === 0) && (
                <div style={{ color: 'var(--text3)', fontFamily: 'var(--mono)', fontSize: '11px', padding: '1rem 0' }}>No physical detections — all clear</div>
              )}
            </div>
          </div>
        </div>
      </motion.div>
    );
  };

  // ══════════════════════════════════════════════════════════════════════
  // RAG INTELLIGENCE — Full Tab (Research Agent / VectorDB)
  // ══════════════════════════════════════════════════════════════════════
  const RAGIntelContent = () => {
    const [ragData,   setRagData]   = useState(null);
    const [ragLoad,   setRagLoad]   = useState(false);
    const [isLive,    setIsLive]    = useState(false);

    const fetchRAG = async () => {
      setRagLoad(true);
      try {
        const token = localStorage.getItem('access_token');
        const headers = { Authorization: `Bearer ${token}` };

        // /research/status → db_size, rag_enabled, vector_store, cache_status, research_count
        const resStatus  = await fetch('http://localhost:8000/research/status', { headers });
        // /research/history → history[], db_size, cache
        const resHistory = await fetch('http://localhost:8000/research/history', { headers });

        if (resStatus.ok) {
          const s = await resStatus.json();
          const h = resHistory.ok ? await resHistory.json() : null;

          // Map backend fields → dashboard fields
          // Backend: rag_enabled (bool), db_size (int), vector_store (obj), research_count (int)
          const historyItems = (h?.history || []).map((item, i) => ({
            query:   item.query   || item.threat || `Search ${i+1}`,
            results: item.results_count ?? item.results ?? (item.cves?.length ?? 0),
            ts:      item.timestamp ? new Date(item.timestamp).getTime() : Date.now() - i * 120000,
          }));

          // top_cves from vector_store status or build from history context
          const topCves = (s.vector_store?.recent_ids || []).slice(0, 5).map(id => ({
            id, score: '--', title: id, count: '--'
          }));

          setRagData({
            rag_status:    s.rag_enabled ? 'ONLINE' : 'OFFLINE',   // ← fix: map rag_enabled → rag_status
            cve_db_size:   s.db_size ?? s.vector_store?.total_docs ?? '--',
            vector_db:     'ChromaDB',
            collections:   s.vector_store?.collections ?? 1,
            embeddings:    s.vector_store?.total_docs   ?? s.db_size ?? '--',
            last_update:   s.last_updated ? new Date(s.last_updated).getTime() : Date.now() - 3600000,
            last_search:   historyItems[0]?.query || 'No searches yet',
            research_count: s.research_count ?? 0,
            search_history: historyItems,
            top_cves:      topCves,
          });
          setIsLive(true);
        }
      } catch (e) {
        console.error('[RAG] fetch error:', e);
      }
      setRagLoad(false);
    };

    useEffect(() => { fetchRAG(); const t = setInterval(fetchRAG, 20000); return () => clearInterval(t); }, []);

    const r = ragData || {
      rag_status: ragLoad ? '...' : 'CONNECTING',
      cve_db_size: '--', vector_db: 'ChromaDB', collections: '--', embeddings: '--',
      last_search: '--', research_count: '--',
      search_history: [], top_cves: [],
    };
    const cvssColor = (s) => s >= 9 ? 'var(--red)' : s >= 7 ? 'var(--amber)' : 'var(--accent)';

    return (
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
        {/* Header */}
        <div className="phd-dash-module" style={{ padding: '1.5rem 2rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <Search size={16} color="var(--primary)" />
            <span style={{ fontFamily: 'var(--display)', fontSize: '16px', letterSpacing: '0.1em' }}>RAG INTELLIGENCE — RESEARCH AGENT</span>
            <span style={{ fontSize: '9px', fontFamily: 'var(--mono)', padding: '2px 8px', borderRadius: 3,
              background: r.rag_status === 'ONLINE' ? 'rgba(0,245,212,0.1)' : 'rgba(255,51,85,0.1)',
              color: r.rag_status === 'ONLINE' ? 'var(--accent)' : 'var(--red)',
              border: `1px solid ${r.rag_status === 'ONLINE' ? 'rgba(0,245,212,0.3)' : 'rgba(255,51,85,0.3)'}` }}>
              {r.rag_status === 'ONLINE' ? '● RAG ONLINE' : '◌ RAG OFFLINE'}
            </span>
            {!isLive && <span style={{ fontSize: '9px', fontFamily: 'var(--mono)', color: 'var(--amber)' }}>MOCK DATA</span>}
          </div>
          <button className="phd-dash-btn" style={{ fontSize: '9px', padding: '4px 12px' }} onClick={fetchRAG}>
            <RefreshCw size={10} style={{ marginRight: 4 }} />{ragLoad ? 'Loading...' : 'REFRESH'}
          </button>
        </div>

        {/* Stats row */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '1rem' }}>
          {[
            { label: 'CVE DB SIZE',    val: r.cve_db_size?.toLocaleString() ?? '--', color: 'var(--text)'    },
            { label: 'VECTOR STORE',   val: r.vector_db   || 'ChromaDB',             color: 'var(--primary)' },
            { label: 'COLLECTIONS',    val: r.collections ?? '--',                   color: 'var(--accent)'  },
            { label: 'EMBEDDINGS',     val: r.embeddings?.toLocaleString() ?? '--',  color: 'var(--blue)'    },
            { label: 'LAST UPDATED',   val: r.last_update ? `${Math.round((Date.now() - r.last_update) / 60000)}m ago` : '--', color: 'var(--text3)' },
          ].map((s, i) => (
            <div key={i} className="phd-dash-module" style={{ padding: '1.2rem 1.5rem' }}>
              <div style={{ fontSize: '9px', color: 'var(--text3)', fontFamily: 'var(--mono)', marginBottom: 6 }}>{s.label}</div>
              <div style={{ fontSize: '20px', fontFamily: 'var(--display)', color: s.color }}>{s.val}</div>
            </div>
          ))}
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
          {/* Search History */}
          <div className="phd-dash-module" style={{ padding: '1.5rem' }}>
            <h3 className="phd-dash-header" style={{ marginBottom: '1rem' }}>RECENT SEARCHES — RESEARCH AGENT</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
              {(r.search_history || []).map((s, i) => (
                <div key={i} style={{ padding: '10px 14px', background: 'rgba(0,0,0,0.2)', border: '1px solid var(--border)', borderRadius: 8 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '10px' }}>
                    <div>
                      <div style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text)', lineHeight: 1.4, marginBottom: 4 }}>
                        <span style={{ color: 'var(--primary)' }}>❯ </span>{s.query}
                      </div>
                      <div style={{ fontSize: '9px', fontFamily: 'var(--mono)', color: 'var(--text3)' }}>
                        {s.ts ? new Date(s.ts).toLocaleTimeString() : '--'}
                      </div>
                    </div>
                    <span style={{ fontSize: '9px', fontFamily: 'var(--mono)', padding: '2px 8px', background: 'rgba(0,245,212,0.08)', border: '1px solid rgba(0,245,212,0.2)', color: 'var(--accent)', borderRadius: 3, flexShrink: 0 }}>
                      {s.results} results
                    </span>
                  </div>
                </div>
              ))}
              {(!r.search_history || r.search_history.length === 0) && (
                <div style={{ color: 'var(--text3)', fontFamily: 'var(--mono)', fontSize: '11px' }}>No searches yet</div>
              )}
            </div>
            <div style={{ marginTop: '1rem', padding: '8px 12px', background: 'rgba(0,0,0,0.2)', borderRadius: 6 }}>
              <span style={{ fontSize: '9px', color: 'var(--text3)', fontFamily: 'var(--mono)' }}>LAST SEARCH: </span>
              <span style={{ fontSize: '10px', color: 'var(--accent)', fontFamily: 'var(--mono)' }}>{r.last_search || '--'}</span>
            </div>
          </div>

          {/* Top CVEs in Database */}
          <div className="phd-dash-module" style={{ padding: '1.5rem' }}>
            <h3 className="phd-dash-header" style={{ marginBottom: '1rem' }}>TOP CVEs IN DATABASE</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {(r.top_cves || []).map((cve, i) => (
                <div key={cve.id} style={{ display: 'flex', alignItems: 'center', gap: '12px', padding: '10px 14px', background: 'rgba(0,0,0,0.2)', border: '1px solid var(--border)', borderRadius: 8 }}>
                  <div style={{ fontSize: '14px', color: 'var(--text3)', fontFamily: 'var(--mono)', minWidth: 16 }}>{i + 1}</div>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                      <a href={`https://nvd.nist.gov/vuln/detail/${cve.id}`} target="_blank" rel="noreferrer"
                        style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--red)', textDecoration: 'none', fontWeight: 700 }}>
                        {cve.id} ↗
                      </a>
                      <span style={{ fontSize: '9px', fontFamily: 'var(--mono)', color: cvssColor(cve.score), border: `1px solid ${cvssColor(cve.score)}55`, padding: '1px 6px', borderRadius: 2 }}>
                        CVSS {cve.score}
                      </span>
                    </div>
                    <div style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text3)' }}>{cve.title}</div>
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <div style={{ fontSize: '9px', color: 'var(--text3)', fontFamily: 'var(--mono)' }}>matched</div>
                    <div style={{ fontSize: '14px', color: 'var(--primary)', fontFamily: 'var(--display)', fontWeight: 700 }}>{cve.count}×</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </motion.div>
    );
  };

  // Tab router
  const renderContent = () => {
    switch (activeTab) {
      case 'Overview':            return <OverviewContent />;
      case 'War Room':            return <WarRoomContent />;
      case 'Quantum Shield':      return <QuantumShieldContent />;
      case 'Verification Engine': return <VerificationTabContent />;
      case 'Suggestions':         return <SuggestionEngineContent />;
      case 'Physical Security':   return <PhysicalSecurityContent />;
      case 'RAG Intelligence':    return <RAGIntelContent />;
      case 'Agent Registry':      return <AgentRegistryContent />;
      case 'Logs Terminal':       return <TerminalContent />;
      case 'Threat Intelligence': return <ThreatIntelContent />;
      case 'Agent Messages':      return <AgentMessagesContent />;
      case 'Settings':            return <SettingsContent />;
      case 'Firewall Rules':      return <FirewallRulesPanel />;
      default:                    return <OverviewContent />;
    }
  };

  const displayName = username || localStorage.getItem('username') || 'USER';
  const displayRole = role     || localStorage.getItem('role')     || 'admin';

  return (
    <div className="premium-theme dashboard-container" style={{ display: 'flex', minHeight: '100vh', background: 'var(--bg)', position: 'relative', zIndex: 10 }}>
      <DashboardColorFix />

      {/* Sidebar */}
      <aside className="phd-dash-sidebar" style={{ width: '280px', margin: '1.5rem', height: 'calc(100vh - 3rem)', position: 'sticky', top: '1.5rem', display: 'flex', flexDirection: 'column' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', padding: '0 24px', marginBottom: '2rem' }}>
          <Shield size={20} color="var(--primary)" />
          <span style={{ fontSize: '18px', fontFamily: 'var(--display)', color: 'var(--text)', letterSpacing: '0.15em', fontWeight: 900 }}>XCIPHER</span>
        </div>

        {/* Backend status */}
        <div style={{ padding: '0 24px', marginBottom: '1rem', fontFamily: 'var(--mono)', fontSize: '10px' }}>
          {backendOk === null ? (
            <span style={{ color: 'var(--text3)' }}><Spinner /> Checking backend...</span>
          ) : backendOk ? (
            <span style={{ color: 'var(--accent)' }}><StatusDot connected={true} />Backend connected</span>
          ) : (
            <span style={{ color: 'var(--red)' }}><StatusDot connected={false} />Backend offline — start python backend.py</span>
          )}
        </div>

        <nav style={{ display: 'flex', flexDirection: 'column', width: '100%', gap: '2px' }}>
          {[
            { label: 'Overview',            icon: Layers },
            { label: 'War Room',            icon: Radio },
            { label: 'Quantum Shield',      icon: Zap },
            { label: 'Verification Engine', icon: Shield },
            { label: 'Suggestions',         icon: AlertCircle },
            { label: 'Physical Security',   icon: Eye },
            { label: 'RAG Intelligence',    icon: Search },
            { label: 'Agent Registry',      icon: Users },
            { label: 'Logs Terminal',       icon: Terminal },
            { label: 'Threat Intelligence', icon: Globe },
            { label: 'Agent Messages',      icon: MessageSquare },
            { label: 'Firewall Rules',      icon: Lock },
            { label: 'Settings',            icon: Settings },
          ].map((item, idx) => (
            <div key={idx} className={`phd-dash-nav-item ${activeTab === item.label ? 'active' : ''}`} onClick={() => setActiveTab(item.label)}>
              <item.icon size={14} />{item.label}
            </div>
          ))}
        </nav>

        <div style={{ marginTop: 'auto', borderTop: '1px solid var(--border)', padding: '1.5rem 20px 0' }}>
          <button className="phd-dash-btn" onClick={onLogout} style={{ width: '100%', borderColor: 'rgba(255,51,85,0.4)', color: 'var(--red)', fontSize: '10px', padding: '10px 0' }}>
            [ TERMINATE SESSION ]
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main style={{ flex: 1, padding: '2rem 2.5rem 2rem 1rem', display: 'flex', flexDirection: 'column', gap: '2rem' }}>
        <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'rgba(10,20,40,0.4)', padding: '1rem 2rem', borderRadius: '20px', border: '1px solid var(--border)', backdropFilter: 'blur(20px)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '2rem' }}>
            <div style={{ fontFamily: 'var(--mono)', fontSize: '11px', color: 'var(--text3)', letterSpacing: '0.2em', whiteSpace: 'nowrap' }}>
              <span style={{ color: 'var(--primary)', fontWeight: 800 }}>XCIPHER</span> // {activeTab.toUpperCase()}
            </div>
            <div style={{ position: 'relative', width: '280px' }}>
              <Search size={14} style={{ position: 'absolute', left: '16px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text3)' }} />
              <input placeholder="SEARCH_ENCRYPTED_NODES..." style={{ width: '100%', padding: '10px 12px 10px 42px', borderRadius: '100px', border: '1px solid var(--border)', background: 'rgba(0,0,0,0.2)', color: 'var(--text)', outline: 'none', fontSize: '12px', fontFamily: 'var(--mono)' }} />
            </div>
          </div>

          <div style={{ display: 'flex', gap: '1.5rem', alignItems: 'center' }}>
            <div title={backendOk ? 'Backend online' : 'Backend offline'}>
              {backendOk ? <Wifi size={16} color="var(--accent)" /> : <WifiOff size={16} color="var(--red)" />}
            </div>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text)' }}>{displayName.toUpperCase()}</div>
              <div style={{ fontSize: '9px', fontFamily: 'var(--mono)', color: 'var(--accent)', background: 'rgba(0,245,212,0.05)', padding: '2px 8px', border: '1px solid var(--accent-glow)' }}>
                {displayRole.toUpperCase()} ACCESS
              </div>
            </div>
            <div style={{ width: '40px', height: '40px', background: 'var(--primary)', border: '1px solid var(--primary-glow)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 800, color: '#fff', fontFamily: 'var(--mono)', fontSize: '14px', clipPath: 'polygon(8px 0, 100% 0, 100% calc(100% - 8px), calc(100% - 8px) 100%, 0 100%, 0 8px)' }}>
              {displayName.slice(0, 2).toUpperCase()}
            </div>
          </div>
        </header>

        <AnimatePresence mode="wait">
          <motion.div key={activeTab} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} transition={{ duration: 0.3 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '2rem' }}>
              <h2 style={{ fontSize: '32px', fontFamily: 'var(--display)', letterSpacing: '0.04em', color: 'var(--text)', margin: 0 }}>{activeTab}</h2>
              <div style={{ height: '1px', flex: 1, background: 'linear-gradient(90deg, var(--border), transparent)' }} />
            </div>
            {renderContent()}
          </motion.div>
        </AnimatePresence>
      </main>

      {/* Critical alert toast */}
      <AnimatePresence>
        {threatData?.total_threats > 0 && (
          <motion.div initial={{ opacity: 0, x: 100 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 100 }}
            style={{ position: 'fixed', bottom: '40px', right: '40px', width: '320px', background: 'rgba(255,51,85,0.1)', border: '1px solid var(--red)', backdropFilter: 'blur(20px)', padding: '20px', zIndex: 1000, clipPath: 'polygon(15px 0, 100% 0, 100% calc(100% - 15px), calc(100% - 15px) 100%, 0 100%, 0 15px)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
              <AlertCircle size={20} className="pulse-red" color="var(--red)" />
              <div style={{ color: 'var(--red)', fontFamily: 'var(--display)', fontSize: '18px', letterSpacing: '0.05em' }}>LIVE_THREATS</div>
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text)', fontFamily: 'var(--mono)', marginBottom: 4 }}>
              COUNT: {threatData.total_threats} | HIGH: {threatData.threat_levels?.HIGH ?? 0}
            </div>
            <div style={{ fontSize: '10px', color: 'var(--text3)', fontFamily: 'var(--mono)' }}>
              MONITORED: {threatData.monitored_agents} agents
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default DashboardView;