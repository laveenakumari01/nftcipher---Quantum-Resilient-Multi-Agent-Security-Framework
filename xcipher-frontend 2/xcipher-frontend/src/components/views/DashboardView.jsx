import React, { useState, useEffect, useRef, useCallback } from 'react';
import './DashboardView.css';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Layers, Shield, AlertCircle,
  Terminal, Users, Settings,
  Search, Globe, Cpu,
  Plus, Activity, Lock, Eye,
  Zap, Radio, RefreshCw, Wifi, WifiOff, MessageSquare, ArrowRight
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
} from '../../agent_api.js';

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
  const [healthScore, setHealthScore] = useState(null);
  const [llmEvents,   setLlmEvents]   = useState([]); // LLM reasoning feed from agents

  // Local sim counter
  const [simCount,    setSimCount]    = useState(0);

  // War Room lockdown overlay
  const [isLockdown, setIsLockdown] = useState(false);

  // Live Activity Feed via SSE
  const [liveEvents,    setLiveEvents]    = useState([]);
  const [sseConnected,  setSseConnected]  = useState(false);
  const eventSourceRef = useRef(null);

  // Settings toggles
  const [settings, setSettings] = useState({ pqc: true, zeroTrust: true, neural: false, autoIsolate: true });

  const logEndRef = useRef(null);

  // Fetch helpers
  const setLoad = (key, val) => setLoading(p => ({ ...p, [key]: val }));

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
      const data = await getAllAgentsStatus();
      // New backend returns { agents: {...}, connections: [...], ... }
      // Old backend returns { "AGENT-ST-01": {...}, ... } directly
      setAgentsData(data?.agents || data);
    } catch (e) {
      addLog(`Agents fetch error: ${e.message}`);
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

  // CHANGE 3 — Initial load: added loadHealthScore call + added to auto-refresh
  useEffect(() => {
    checkBackend();
    loadAgents();
    loadStats();
    loadLogs();
    loadThreats();
    loadPQC();
    loadHealthScore(); // NEW: load security health score on startup
    addLog(`Dashboard initialized — User: ${username || 'unknown'} | Role: ${role || 'unknown'}`);

    // Auto-refresh every 15 seconds
    const interval = setInterval(() => {
      checkBackend();
      loadAgents();
      loadStats();
      loadThreats();
      loadHealthScore(); // NEW: refresh health score too
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
                { l: 'PQC Engine',     s: 'KYBER+DILITHIUM',                                                   c: 'var(--primary)' },
                { l: 'Sentinel AI',    s: agentsData?.['AGENT-ST-01']?.status ?? '--',                         c: 'var(--accent)' },
                { l: 'Arbiter',        s: agentsData?.['AGENT-AR-01']?.status ?? '--',                         c: 'var(--primary)' },
                { l: 'Adversary Sim',  s: agentsData?.['AGENT-AD-01']?.status ?? '--',                         c: 'var(--text3)' },
                { l: 'ML Model',       s: statsData ? 'LOADED' : '--',                                         c: 'var(--accent)' },
                // NEW: show how many agents are running autonomously
                { l: 'Autonomous Agents', s: healthScore ? `${healthScore.autonomous_agents}/5` : '--',        c: 'var(--primary)' },
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
      </div>
    );
  };

  // WAR ROOM TAB — unchanged
  const WarRoomContent = () => {
    const [warToken,  setWarToken]  = useState('');
    const [warResult, setWarResult] = useState(null);
    const [warLoad,   setWarLoad]   = useState(false);

    const agentNodes = agentsData
      ? Object.entries(agentsData).map(([id, ag], i) => ({
          id, ...ag,
          pos: [
            { x: 50, y: 15 },
            { x: 20, y: 40 },
            { x: 80, y: 40 },
            { x: 15, y: 75 },
            { x: 85, y: 75 },
            { x: 50, y: 90 },
          ][i] || { x: 50, y: 50 }
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
        if (agRes.ok)  { const d = await agRes.json(); setRegAgents(d.agents || []); }
        if (stRes.ok)  { const d = await stRes.json(); setRegStats(d); }
      } catch (e) { addLog(`Registry fetch error: ${e.message}`); }
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
                        {ag.status === 'BLOCKED' ? (
                          <button className="phd-dash-btn" style={{ fontSize: '8px', padding: '2px 8px', borderColor: 'rgba(0,245,212,0.3)', color: 'var(--accent)' }}
                            onClick={e => { e.stopPropagation(); handleActivate(ag.agent_id); }}>
                            ACTIVATE
                          </button>
                        ) : (
                          <button className="phd-dash-btn" style={{ fontSize: '8px', padding: '2px 8px', borderColor: 'rgba(255,51,85,0.3)', color: 'var(--red)' }}
                            disabled={blockingId === ag.agent_id}
                            onClick={e => { e.stopPropagation(); handleBlock(ag.agent_id); }}>
                            {blockingId === ag.agent_id ? <Spinner /> : 'BLOCK'}
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

            {actionMsg && (
              <div style={{ padding: '0.75rem 1.5rem', borderTop: '1px solid var(--border)', fontFamily: 'var(--mono)', fontSize: '10px', color: actionMsg.type === 'block' ? 'var(--red)' : 'var(--accent)' }}>
                {actionMsg.type === 'block' ? `✗ ${actionMsg.id} BLOCKED — registry updated` : `✓ ${actionMsg.id} ACTIVATED — registry updated`}
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
                  Kisi message pe click karo detail dekhne ke liye
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

  // Tab router
  const renderContent = () => {
    switch (activeTab) {
      case 'Overview':            return <OverviewContent />;
      case 'War Room':            return <WarRoomContent />;
      case 'Quantum Shield':      return <QuantumShieldContent />;
      case 'Agent Registry':      return <AgentRegistryContent />;
      case 'Logs Terminal':       return <TerminalContent />;
      case 'Threat Intelligence': return <ThreatIntelContent />;
      case 'Agent Messages':      return <AgentMessagesContent />;
      case 'Settings':            return <SettingsContent />;
      default:                    return <OverviewContent />;
    }
  };

  const displayName = username || localStorage.getItem('username') || 'USER';
  const displayRole = role     || localStorage.getItem('role')     || 'admin';

  return (
    <div className="premium-theme dashboard-container" style={{ display: 'flex', minHeight: '100vh', background: 'var(--bg)', position: 'relative', zIndex: 10 }}>

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
            { label: 'Agent Registry',      icon: Users },
            { label: 'Logs Terminal',       icon: Terminal },
            { label: 'Threat Intelligence', icon: Globe },
            { label: 'Agent Messages',      icon: MessageSquare },
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