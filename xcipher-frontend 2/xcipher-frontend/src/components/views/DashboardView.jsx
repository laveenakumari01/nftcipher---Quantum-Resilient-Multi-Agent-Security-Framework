import React, { useState, useEffect, useRef, useCallback } from 'react';
import './DashboardView.css';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Layers, Shield, AlertCircle,
  Terminal, Users, Settings,
  Search, Globe, Cpu,
  Plus, Activity, Lock, Eye,
  Zap, Radio, RefreshCw, Wifi, WifiOff
} from 'lucide-react';

// ✅ REAL API IMPORTS — agent_api.js se
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

// ── Small helper ──────────────────────────────────────────
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
  const [activeTab, setActiveTab]   = useState('Overview');
  const [backendOk, setBackendOk]   = useState(null);   // null=checking, true/false

  // ── Real data state ───────────────────────────────────
  const [agentsData,  setAgentsData]  = useState(null);
  const [statsData,   setStatsData]   = useState(null);
  const [logsData,    setLogsData]    = useState([]);
  const [threatData,  setThreatData]  = useState(null);
  const [pqcData,     setPqcData]     = useState(null);
  const [loading,     setLoading]     = useState({});
  const [actionResult, setActionResult] = useState(null);

  // Local sim counter — backend log se nahi aata isliye khud track karo
  const [simCount, setSimCount] = useState(0);

  // War Room: lockdown overlay
  const [isLockdown, setIsLockdown] = useState(false);

  // Live Activity Feed — SSE se real-time events
  const [liveEvents, setLiveEvents] = useState([]);
  const [sseConnected, setSseConnected] = useState(false);
  const eventSourceRef = useRef(null);

  // Settings toggles
  const [settings, setSettings] = useState({ pqc: true, zeroTrust: true, neural: false, autoIsolate: true });

  const logEndRef = useRef(null);

  // ── Fetch helpers ─────────────────────────────────────
  const setLoad = (key, val) => setLoading(p => ({ ...p, [key]: val }));

  const addLog = useCallback((msg) => {
    setLogsData(prev => [`[${new Date().toLocaleTimeString()}] ${msg}`, ...prev].slice(0, 80));
  }, []);

  // ── Backend health check ──────────────────────────────
  const checkBackend = useCallback(async () => {
    try {
      const res = await fetch('http://localhost:8000/health', { signal: AbortSignal.timeout(5000) });
      setBackendOk(res.ok);
      if (res.ok) {
        addLog('✅ Backend connected — localhost:8000');
      }
    } catch {
      setBackendOk(false);
      addLog('⚠ Backend offline — run: python backend.py');
    }
  }, [addLog]);

  // ── Load all agents status ────────────────────────────
  const loadAgents = useCallback(async () => {
    setLoad('agents', true);
    try {
      const data = await getAllAgentsStatus();
      setAgentsData(data);
    } catch (e) {
      addLog(`⚠ Agents fetch error: ${e.message}`);
    }
    setLoad('agents', false);
  }, [addLog]);

  // ── Load agent/stats ──────────────────────────────────
  const loadStats = useCallback(async () => {
    setLoad('stats', true);
    try {
      const res = await fetch('http://localhost:8000/agent/stats', {
        headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` }
      });
      if (res.ok) setStatsData(await res.json());
    } catch (e) {
      addLog(`⚠ Stats fetch error: ${e.message}`);
    }
    setLoad('stats', false);
  }, [addLog]);

  // ── Load logs ─────────────────────────────────────────
  const loadLogs = useCallback(async () => {
    setLoad('logs', true);
    try {
      const data = await getLogs(60);
      if (Array.isArray(data) && data.length > 0) {
        setLogsData(data.map(l =>
          `[${l.timestamp ? new Date(l.timestamp).toLocaleTimeString() : '--'}] ${l.agent_id || ''} | ${l.level || 'INFO'} | ${l.event || ''}`
        ));
      } else {
        // Fallback: local log file se
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
      addLog(`⚠ Logs fetch error: ${e.message}`);
    }
    setLoad('logs', false);
  }, [addLog]);

  // ── Load threat report ────────────────────────────────
  const loadThreats = useCallback(async () => {
    setLoad('threats', true);
    try {
      const data = await getThreatReport();
      // FIX: Backend data aur local data merge karo — overwrite mat karo
      // Agar backend mein zyada threats hain toh use karo, warna local rakho
      setThreatData(prev => {
        if (!prev) return data;
        // Jo bhi zyada hai wo rakho
        if ((data?.total_threats || 0) >= (prev?.total_threats || 0)) return data;
        return prev; // local state preserve karo
      });
    } catch (e) {
      addLog(`⚠ Threats fetch error: ${e.message}`);
    }
    setLoad('threats', false);
  }, [addLog]);

  // ── Load PQC comparison ───────────────────────────────
  const loadPQC = useCallback(async () => {
    setLoad('pqc', true);
    try {
      const data = await getPQCComparison();
      setPqcData(data);
    } catch (e) {
      addLog(`⚠ PQC fetch error: ${e.message}`);
    }
    setLoad('pqc', false);
  }, [addLog]);

  // ── Initial load on mount ─────────────────────────────
  useEffect(() => {
    checkBackend();
    loadAgents();
    loadStats();
    loadLogs();
    loadThreats();
    loadPQC();
    addLog(`Dashboard initialized — User: ${username || 'unknown'} | Role: ${role || 'unknown'}`);

    // Auto-refresh har 15 seconds
    const interval = setInterval(() => {
      checkBackend();
      loadAgents();
      loadStats();
      loadThreats();
    }, 15000);

    return () => clearInterval(interval);
  }, []);

  // ── SSE Live Feed Connection ───────────────────────────
  useEffect(() => {
    const token = localStorage.getItem('access_token') || '';
    const es = new EventSource(`http://localhost:8000/stream/events`);
    eventSourceRef.current = es;

    es.onopen = () => {
      setSseConnected(true);
      addLog('📡 Live agent feed connected (SSE)');
    };

    es.onmessage = (e) => {
      try {
        const evt = JSON.parse(e.data);
        if (evt.type === 'PING' || evt.type === 'CONNECTED') return;

        const time = new Date(evt.ts * 1000).toLocaleTimeString();
        const msg = evt.data?.message || JSON.stringify(evt.data);
        const entry = { type: evt.type, message: msg, time, id: Date.now() + Math.random() };

        setLiveEvents(prev => [entry, ...prev].slice(0, 100));

        // Threat events — addLog mein bhi show karo aur threat counter update karo
        if (evt.type === 'THREAT' || evt.type === 'ATTACK' || evt.type === 'BLOCKED') {
          addLog(`${msg}`);
          if (evt.type === 'THREAT' || evt.type === 'ATTACK') {
            setSimCount(prev => prev + 1);
          }
        }
      } catch {}
    };

    es.onerror = () => {
      setSseConnected(false);
      // Auto-reconnect — EventSource khud karta hai, bas status update karo
    };

    return () => {
      es.close();
      setSseConnected(false);
    };
  }, []);

  // ── Scroll logs to top when new log added ─────────────
  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logsData]);

  // ─────────────────────────────────────────────────────
  //  TAB CONTENTS
  // ─────────────────────────────────────────────────────

  // ── OVERVIEW ─────────────────────────────────────────
  const OverviewContent = () => {
    const secHealth  = statsData?.security_score   ?? 98;
    const totalDet   = (statsData?.total_detections ?? 0) + simCount;
    const activeThr  = (statsData?.active_threats   ?? 0) + (threatData?.total_threats ?? 0);
    const auditReq   = (statsData?.audit_requests   ?? 0) + simCount;

    const agentList = agentsData ? Object.entries(agentsData) : [];

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
        {/* Stats cards */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1.5rem' }}>
          {[
            { label: 'Security Score',    val: secHealth !== '--' ? `${secHealth}%` : '--', icon: Shield,      color: 'var(--accent)' },
            { label: 'Total Detections',  val: totalDet,                                    icon: Activity,    color: 'var(--primary)' },
            { label: 'Active Threats',    val: activeThr,                                   icon: AlertCircle, color: 'var(--red)' },
            { label: 'Audit Requests',    val: auditReq,                                    icon: Lock,        color: 'var(--blue)' },
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
          {/* Agents Status */}
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
                    <span style={{ color: 'var(--text3)', fontSize: '9px' }}>
                      fails: {ag.failed_attempts ?? 0}
                    </span>
                    <span style={{ color: ag.backend === 'connected' ? 'var(--accent)' : 'var(--red)', fontSize: '9px' }}>
                      {ag.backend === 'connected' ? '🟢 BACKEND' : '🔴 OFFLINE'}
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
                { l: 'Backend API',   s: backendOk === null ? 'CHECKING' : backendOk ? 'ONLINE' : 'OFFLINE',       c: backendOk ? 'var(--accent)' : 'var(--red)' },
                { l: 'PQC Engine',    s: 'KYBER+DILITHIUM',  c: 'var(--primary)' },
                { l: 'Sentinel AI',   s: agentsData?.['AGENT-ST-01']?.status ?? '--',  c: 'var(--accent)' },
                { l: 'Arbiter',       s: agentsData?.['AGENT-AR-01']?.status ?? '--',  c: 'var(--primary)' },
                { l: 'Adversary Sim', s: agentsData?.['AGENT-AD-01']?.status ?? '--',  c: 'var(--text3)' },
                { l: 'ML Model',      s: statsData ? 'LOADED' : '--',                  c: 'var(--accent)' },
              ].map((st, i) => (
                <div key={i} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', fontFamily: 'var(--mono)' }}>
                  <span style={{ color: 'var(--text2)' }}>{st.l}</span>
                  <span style={{ color: st.c }}>{st.s}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    );
  };

  // ── WAR ROOM ─────────────────────────────────────────
  const WarRoomContent = () => {
    const [warToken, setWarToken]   = useState('');
    const [warResult, setWarResult] = useState(null);
    const [warLoad, setWarLoad]     = useState(false);

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
        addLog(`✅ Quantum token generated for ${agentId}`);
      } catch (e) {
        addLog(`⚠ Token gen error: ${e.message}`);
      }
      setWarLoad(false);
    };

    const runAnalyze = async (agentId) => {
      setWarLoad(true);
      try {
        const tk = warToken || 'dashboard-token-' + Date.now();
        const res = await analyzeBehavior(tk, agentId, 'dashboard_check', { data_size: 50 });
        setWarResult({ type: 'ANALYZE', data: res });
        addLog(`🔍 Sentinel analyzed ${agentId}: ${res.threat_level || res.is_threat}`);
        if (res.threat_level === 'HIGH' || res.is_threat) setIsLockdown(true);
      } catch (e) {
        addLog(`⚠ Analyze error: ${e.message}`);
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
        {/* Mesh */}
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
                  <div style={{ fontSize: '7px', color: 'var(--text3)', fontFamily: 'var(--mono)' }}>{agent.backend === 'connected' ? '🟢' : '🔴'} {agent.backend}</div>
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

          {/* Actions */}
          <div className="phd-dash-module" style={{ padding: '1.5rem' }}>
            <h3 className="phd-dash-header">QUICK ACTIONS</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              <button className="phd-dash-btn" style={{ fontSize: '10px' }} disabled={warLoad} onClick={() => runAnalyze('AGENT-ST-01')}>
                {warLoad ? <Spinner /> : '🔍 ANALYZE SENTINEL'}
              </button>
              <button className="phd-dash-btn" style={{ fontSize: '10px' }} disabled={warLoad} onClick={() => runAnalyze('AGENT-AR-01')}>
                {warLoad ? <Spinner /> : '⚖️ CHECK ARBITER'}
              </button>
              <button className="phd-dash-btn" style={{ fontSize: '10px', borderColor: 'rgba(255,51,85,0.4)', color: 'var(--red)' }} onClick={() => setIsLockdown(true)}>
                🔴 TRIGGER LOCKDOWN
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

  // ── QUANTUM SHIELD ────────────────────────────────────
  const QuantumShieldContent = () => (
    <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
      <div className="phd-dash-module" style={{ padding: '3rem' }}>
        <h3 className="phd-dash-header">SECURE PATH vs VULNERABLE PATH — REAL BACKEND DATA</h3>
        {loading.pqc ? (
          <div style={{ textAlign: 'center', padding: '3rem' }}><Spinner /></div>
        ) : pqcData ? (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '4rem', marginTop: '2rem' }}>
            {/* Classical */}
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
            {/* PQC */}
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
          { label: 'HANDSHAKE_PQC',   val: pqcData?.pqc?.handshake_time || '--',   color: 'var(--accent)' },
          { label: 'SIGNATURE_VERIF', val: 'Dilithium-3',                           color: 'var(--primary)' },
          { label: 'DECRYPTION_FAIL', val: pqcData?.pqc?.resilience_to_shors || '--', color: 'var(--text)' },
        ].map((stat, i) => (
          <div key={i} className="phd-dash-module" style={{ padding: '1.5rem' }}>
            <div style={{ fontSize: '9px', color: 'var(--text3)', fontFamily: 'var(--mono)', marginBottom: 8 }}>{stat.label}</div>
            <div style={{ fontSize: '20px', color: stat.color, fontFamily: 'var(--display)' }}>{stat.val}</div>
          </div>
        ))}
      </div>
    </motion.div>
  );

  // ── AGENT REGISTRY ────────────────────────────────────
  const AgentRegistryContent = () => {
    const [blockingId, setBlockingId] = useState(null);
    const [arbResult, setArbResult]   = useState(null);

    const handleBlock = async (agentId) => {
      setBlockingId(agentId);
      try {
        const res = await blockAgent(agentId, 'Manually blocked via dashboard');
        addLog(`🚫 Agent ${agentId} blocked: ${res.status}`);
        setArbResult(res);
        await loadAgents();
      } catch (e) {
        addLog(`⚠ Block error: ${e.message}`);
      }
      setBlockingId(null);
    };

    const agentList = agentsData ? Object.entries(agentsData) : [];

    return (
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="phd-dash-module" style={{ padding: '2.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2.5rem' }}>
          <h3 className="phd-dash-header"><Users size={14} /> REGISTERED AGENT PERSONAS — REAL BACKEND</h3>
          <button className="phd-dash-btn" onClick={loadAgents}><RefreshCw size={14} /> REFRESH</button>
        </div>

        {loading.agents ? (
          <div style={{ textAlign: 'center', padding: '3rem' }}><Spinner /></div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ textAlign: 'left', borderBottom: '1px solid var(--border)', color: 'var(--text3)', fontSize: '10px', fontFamily: 'var(--mono)' }}>
                <th style={{ padding: '1rem' }}>AGENT_ID</th>
                <th>ROLE</th>
                <th>STATUS</th>
                <th>FAILED_ATTEMPTS</th>
                <th>BACKEND</th>
                <th>ACTIONS</th>
              </tr>
            </thead>
            <tbody>
              {agentList.length === 0 ? (
                <tr><td colSpan={6} style={{ padding: '2rem', color: 'var(--text3)', fontFamily: 'var(--mono)', fontSize: '11px' }}>No agents — is backend running?</td></tr>
              ) : agentList.map(([id, ag]) => (
                <tr key={id} style={{ borderBottom: '1px solid rgba(255,255,255,0.02)', fontSize: '12px', fontFamily: 'var(--mono)' }}>
                  <td style={{ padding: '1.25rem 1rem', color: 'var(--text)' }}>{id}</td>
                  <td style={{ color: 'var(--text2)' }}>{ag.role}</td>
                  <td>
                    <span style={{ background: ag.status === 'BLOCKED' ? 'rgba(255,51,85,0.1)' : 'rgba(0,245,212,0.1)', padding: '2px 8px', color: ag.status === 'BLOCKED' ? 'var(--red)' : 'var(--accent)', border: `1px solid ${ag.status === 'BLOCKED' ? 'rgba(255,51,85,0.4)' : 'var(--accent-glow)'}` }}>
                      {ag.status}
                    </span>
                  </td>
                  <td style={{ color: ag.failed_attempts > 0 ? 'var(--red)' : 'var(--text3)' }}>{ag.failed_attempts ?? 0}</td>
                  <td style={{ color: ag.backend === 'connected' ? 'var(--accent)' : 'var(--red)' }}>
                    {ag.backend === 'connected' ? '🟢 CONNECTED' : '🔴 OFFLINE'}
                  </td>
                  <td>
                    <button className="phd-dash-btn" style={{ fontSize: '9px', padding: '3px 8px', borderColor: 'rgba(255,51,85,0.3)', color: 'var(--red)' }}
                      disabled={blockingId === id} onClick={() => handleBlock(id)}>
                      {blockingId === id ? <Spinner /> : 'BLOCK'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {arbResult && (
          <div style={{ marginTop: 16, padding: 12, background: 'rgba(0,0,0,0.3)', borderRadius: 6, fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text2)' }}>
            Last action: {JSON.stringify(arbResult)}
          </div>
        )}
      </motion.div>
    );
  };

  // ── LOGS TERMINAL ─────────────────────────────────────
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
            <span style={{ color: log.includes('ERROR') || log.includes('⚠') ? 'var(--red)' : log.includes('✅') ? 'var(--accent)' : log.includes('BLOCKED') || log.includes('DENIED') ? 'var(--amber)' : 'var(--primary)' }}>[SYS]</span>
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

  // ── THREAT INTELLIGENCE ───────────────────────────────
  const ThreatIntelContent = () => {
    const [simLoad, setSimLoad]   = useState(false);
    const [simResult, setSimResult] = useState(null);
    const [attackReport, setAttackReport] = useState(null);

    const runSim = async (type) => {
      setSimLoad(true);
      let res;
      try {
        if (type === 'brute')  res = await simulateBruteForce('AGENT-ST-01', 5);
        if (type === 'flood')  res = await simulateApiFlooding('/api/analyze', 10);
        if (type === 'hijack') res = await simulateTokenHijacking('fake-token-xyz', 'AGENT-AR-01');
        setSimResult(res);
        setSimCount(prev => prev + 1);  // Overview stats update
        addLog(`💀 Adversary sim [${type}]: ${res?.attack_type} → ${res?.success ? 'SUCCESS' : 'BLOCKED'}`);

        // FIX: Attack report fetch karo
        const report = await getAttackReport();
        setAttackReport(report);

        // FIX: Local blip add karo radar ke liye — backend pe depend mat karo
        setThreatData(prev => {
          const existing = prev || { total_threats: 0, monitored_agents: 0, recent_threats: [], threat_levels: { HIGH: 0, MEDIUM: 0, LOW: 0 } };
          const newThreat = {
            agentId: res?.target || 'AGENT-ST-01',
            threat_level: 'HIGH',
            flags: [res?.attack_type || type.toUpperCase()],
            timestamp: Date.now(),
          };
          return {
            ...existing,
            total_threats: (existing.total_threats || 0) + 1,
            monitored_agents: Math.max(existing.monitored_agents || 0, 1),
            recent_threats: [...(existing.recent_threats || []), newThreat].slice(-10),
            threat_levels: {
              HIGH:   (existing.threat_levels?.HIGH   || 0) + 1,
              MEDIUM: existing.threat_levels?.MEDIUM  || 0,
              LOW:    existing.threat_levels?.LOW     || 0,
            },
          };
        });

      } catch (e) {
        addLog(`⚠ Sim error: ${e.message}`);
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
            {/* Dynamic blips from threat data */}
            {(threatData?.recent_threats || []).slice(0, 5).map((t, i) => {
              const positions = [
                { top: '25%', left: '30%' },
                { top: '55%', left: '65%' },
                { top: '35%', left: '70%' },
                { top: '65%', left: '25%' },
                { top: '45%', left: '48%' },
              ];
              const pos = positions[i % positions.length];
              return (
                <div key={i} style={{ position: 'absolute', top: pos.top, left: pos.left }}>
                  <motion.div animate={{ scale: [1, 2, 1], opacity: [1, 0.3, 1] }} transition={{ duration: 1.2, repeat: Infinity, delay: i * 0.25 }}
                    style={{ width: 10, height: 10, borderRadius: '50%', background: t.threat_level === 'HIGH' ? 'var(--red)' : 'var(--amber)', boxShadow: `0 0 20px ${t.threat_level === 'HIGH' ? 'var(--red)' : 'var(--amber)'}` }} />
                  <span style={{ fontSize: '9px', color: t.threat_level === 'HIGH' ? 'var(--red)' : 'var(--amber)', fontFamily: 'var(--mono)', whiteSpace: 'nowrap' }}>{t.threat_level}</span>
                </div>
              );
            })}
          </div>

          {/* Attack simulation buttons */}
          <div style={{ marginTop: '1.5rem' }}>
            <div style={{ fontSize: '10px', color: 'var(--text3)', fontFamily: 'var(--mono)', marginBottom: 10 }}>ADVERSARY SIMULATIONS — REAL BACKEND</div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {[
                { label: '💀 BRUTE FORCE',    type: 'brute' },
                { label: '🌊 API FLOODING',   type: 'flood' },
                { label: '🎭 TOKEN HIJACK',   type: 'hijack' },
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
          {/* Threat stats */}
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

          {/* Sim result */}
          <div className="phd-dash-module" style={{ flex: 1, padding: '1.5rem' }}>
            <h3 className="phd-dash-header"><Terminal size={14} /> SIMULATION RESULTS</h3>
            {simResult ? (
              <div style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text2)' }}>
                <div style={{ color: simResult.success ? 'var(--red)' : 'var(--accent)', fontWeight: 800, marginBottom: 8 }}>
                  {simResult.attack_type} — {simResult.success ? '⚠ SUCCEEDED' : '✅ BLOCKED'}
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

  // ── SETTINGS ──────────────────────────────────────────
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

          {/* Backend info */}
          <div style={{ padding: '1.5rem', border: '1px solid var(--border)', borderRadius: 8, fontFamily: 'var(--mono)', fontSize: '11px' }}>
            <div style={{ color: 'var(--text3)', marginBottom: 8 }}>CURRENT SESSION</div>
            <div style={{ color: 'var(--text2)', marginBottom: 4 }}>Username: <span style={{ color: 'var(--accent)' }}>{username || localStorage.getItem('username') || '--'}</span></div>
            <div style={{ color: 'var(--text2)', marginBottom: 4 }}>Role: <span style={{ color: 'var(--primary)' }}>{role || localStorage.getItem('role') || '--'}</span></div>
            <div style={{ color: 'var(--text2)' }}>Backend: <span style={{ color: backendOk ? 'var(--accent)' : 'var(--red)' }}>{backendOk ? '🟢 CONNECTED (localhost:8000)' : '🔴 OFFLINE'}</span></div>
          </div>

          <div style={{ display: 'flex', gap: '1rem' }}>
            <button className="phd-dash-btn" style={{ background: 'var(--primary)', color: '#fff' }} onClick={() => setSaved(true)}>SAVE_CHANGES</button>
            <button className="phd-dash-btn" onClick={() => setSettings({ pqc: true, zeroTrust: true, neural: false, autoIsolate: true })}>RESET_TO_DEFAULTS</button>
          </div>
          {saved && <div style={{ color: 'var(--accent)', fontFamily: 'var(--mono)', fontSize: '11px' }}>✅ Settings saved to session</div>}
        </div>
      </motion.div>
    );
  };

  // ── LIVE AGENT FEED ───────────────────────────────────
  const LiveFeedContent = () => {
    const eventColor = (type) => {
      if (type === 'THREAT' || type === 'ATTACK') return 'var(--red)';
      if (type === 'BLOCKED' || type === 'DENIED') return 'var(--amber, #f59e0b)';
      if (type === 'ALLOWED' || type === 'INFO')   return 'var(--accent)';
      if (type === 'ERROR')                        return 'var(--red)';
      return 'var(--primary)';
    };
    const eventIcon = (type) => {
      if (type === 'THREAT')  return '🚨';
      if (type === 'ATTACK')  return '💀';
      if (type === 'BLOCKED') return '🚫';
      if (type === 'DENIED')  return '❌';
      if (type === 'ALLOWED') return '✅';
      if (type === 'ERROR')   return '⚠';
      return '📋';
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
            { label: 'TOTAL EVENTS',    val: liveEvents.length,                                     color: 'var(--primary)' },
            { label: 'THREATS / ATTACKS', val: liveEvents.filter(e => ['THREAT','ATTACK'].includes(e.type)).length, color: 'var(--red)' },
            { label: 'BLOCKED',         val: liveEvents.filter(e => e.type === 'BLOCKED').length,   color: 'var(--amber, #f59e0b)' },
            { label: 'INFO / ALLOWED',  val: liveEvents.filter(e => ['INFO','ALLOWED'].includes(e.type)).length, color: 'var(--accent)' },
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
            <span>🟢 = ALLOWED/INFO</span>
            <span>🟡 = BLOCKED/DENIED</span>
            <span>🔴 = THREAT/ATTACK/ERROR</span>
          </div>
          <div style={{ height: '520px', overflowY: 'auto', padding: '1rem 0' }}>
            {liveEvents.length === 0 ? (
              <div style={{ padding: '3rem', textAlign: 'center', fontFamily: 'var(--mono)', fontSize: '12px', color: 'var(--text3)' }}>
                {sseConnected ? '⏳ Waiting for agent events...' : '🔴 Not connected — run: python backend.py'}
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
                  background: ev.type === 'THREAT' || ev.type === 'ATTACK'
                    ? 'rgba(255,51,85,0.04)'
                    : 'transparent',
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

  // ── RENDER ────────────────────────────────────────────
  const renderContent = () => {
    switch (activeTab) {
      case 'Overview':           return <OverviewContent />;
      case 'War Room':           return <WarRoomContent />;
      case 'Quantum Shield':     return <QuantumShieldContent />;
      case 'Agent Registry':     return <AgentRegistryContent />;
      case 'Logs Terminal':      return <TerminalContent />;
      case 'Threat Intelligence':return <ThreatIntelContent />;
      case 'Settings':           return <SettingsContent />;
      default:                   return <OverviewContent />;
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

        {/* Backend status indicator */}
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
            { label: 'Overview',           icon: Layers },
            { label: 'War Room',           icon: Radio },
            { label: 'Quantum Shield',     icon: Zap },
            { label: 'Agent Registry',     icon: Users },
            { label: 'Logs Terminal',      icon: Terminal },
            { label: 'Threat Intelligence',icon: Globe },
            { label: 'Settings',           icon: Settings },
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
            {/* Backend status icon in header */}
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