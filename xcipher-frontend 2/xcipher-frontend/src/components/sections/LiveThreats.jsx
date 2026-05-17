import React, { useState, useEffect } from 'react';
import { AlertTriangle, ShieldCheck, Activity } from 'lucide-react';
import './LiveThreats.css';

const MOCK_THREATS = [
  { id: 1, type: 'critical', msg: 'Abnormal Agent Behavior Detected', agent: 'Agent-Node-X7', time: 'Just now' },
  { id: 2, type: 'warning', msg: 'Elevated API Request Rate', agent: 'Agent-Gateway-2', time: '12s ago' },
  { id: 3, type: 'critical', msg: 'Classical Brute-Force Blocked', agent: 'External-IP', time: '45s ago' },
  { id: 4, type: 'safe', msg: 'PQC Key Exchange Successful', agent: 'Agent-Node-Y9', time: '1m ago' },
  { id: 5, type: 'warning', msg: 'JWT Token Refresh Anomaly', agent: 'Auth-Service', time: '2m ago' }
];

const LiveThreats = () => {
  const [threats, setThreats] = useState(MOCK_THREATS.slice(1));
  
  // Simulate live incoming threats
  useEffect(() => {
    const timer = setTimeout(() => {
      setThreats(MOCK_THREATS);
    }, 3000);
    return () => clearTimeout(timer);
  }, []);

  return (
    <section className="threats-section" id="intelligence">
      <div className="threats-container">
        
        <div className="threats-header">
          <div className="eyebrow">
            <span className="eyebrow-dot"></span>
            Intelligence Layer
          </div>
          <h2 className="threats-title">Real-Time Threat Detection Dashboard</h2>
        </div>

        <div className="dashboard-grid">
          {/* Left Panel: Logs */}
          <div className="dashboard-panel">
            <div className="panel-top">
              <h3 className="panel-heading">Live Agent Activity Logs</h3>
              <div className="live-pulse">
                <span className="pulse-dot red"></span> LIVE
              </div>
            </div>
            
            <div className="feed-list">
              {threats.map((t, idx) => (
                <div key={t.id} className="feed-item interactive" style={{ animationDelay: `${idx * 0.1}s` }}>
                  <div className={`severity-icon ${t.type}`}>
                    {t.type === 'critical' && <AlertTriangle size={16} />}
                    {t.type === 'warning' && <Activity size={16} />}
                    {t.type === 'safe' && <ShieldCheck size={16} />}
                  </div>
                  <div className="feed-content">
                    <div className="feed-msg">
                      <span className={`badge ${t.type}`}>{t.type.toUpperCase()}</span>
                      {t.msg}
                    </div>
                    <div className="feed-meta">
                      {t.agent} • {t.time}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Right Panel: Stats */}
          <div className="dashboard-stats">
            <div className="stat-card interactive">
              <div className="stat-val red">3</div>
              <div className="stat-label">Critical Anomalies Blocked</div>
            </div>
            <div className="stat-card interactive">
              <div className="stat-val blue">100%</div>
              <div className="stat-label">PQC Encryption Status</div>
            </div>
            <div className="stat-card interactive">
              <div className="stat-val">24</div>
              <div className="stat-label">Active Autonomous Agents</div>
            </div>
            <div className="stat-card interactive">
              <div className="stat-val green">99.9%</div>
              <div className="stat-label">System Security Score</div>
            </div>
          </div>

        </div>

      </div>
    </section>
  );
};

export default LiveThreats;
