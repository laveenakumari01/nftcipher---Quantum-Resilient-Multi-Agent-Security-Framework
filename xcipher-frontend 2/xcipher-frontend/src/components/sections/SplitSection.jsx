import React from 'react';
import './SplitSection.css';
import quantumBg from '../../assets/quantum_threat_bg.png';
import agentsBg from '../../assets/ai_agents_bg.png';
import { AlertTriangle, ShieldCheck, Clock, Zap, Lock, GitBranch } from 'lucide-react';

const THREAT_POINTS = [
  { label: 'NIST PQC Standard', status: 'BREACHED BY 2030', color: 'var(--red)' },
  { label: 'RSA-2048 Encryption', status: 'VULNERABLE', color: 'var(--amber)' },
  { label: 'Classical TLS/SSL', status: 'DEPRECATED', color: 'var(--amber)' },
  { label: 'Legacy JWT Tokens', status: 'CRITICAL', color: 'var(--red)' },
];

const SOLUTION_POINTS = [
  { Icon: Lock, label: 'CRYSTALS-Kyber KEM', desc: 'NIST-approved key encapsulation' },
  { Icon: Zap, label: 'Dilithium Signatures', desc: 'Post-quantum digital signing' },
  { Icon: GitBranch, label: 'Zero Trust Gateway', desc: 'Per-agent identity verification' },
  { Icon: ShieldCheck, label: 'Real-time ML Isolation', desc: 'Sub-400ms anomaly response' },
];

const SplitSection = () => {
  return (
    <section className="split-section" id="threat">

      {/* Section Header */}
      <div className="split-header">
        <div className="split-tag">// THREAT_ASSESSMENT :: CLASSIFICATION_LEVEL_5</div>
        <h2 className="split-main-title">Why Quantum<br /><em>Matters Now</em></h2>
      </div>

      <div className="split-container">
        {/* Left: Threat Brief */}
        <div className="split-pane threat-pane">
          <div className="pane-bg" style={{ backgroundImage: `url(${quantumBg})` }} />
          <div className="pane-overlay pane-overlay-left" />

          <div className="pane-content">
            <div className="pane-eyebrow">
              <AlertTriangle size={12} />
              THREAT VECTOR ANALYSIS
            </div>
            <h3 className="pane-title">The Quantum<br/>Threat</h3>
            <p className="pane-desc">
              Within a decade, quantum computers will break RSA-2048 and ECDSA — the backbone of all current AI agent infrastructure. Every unencrypted transit is being harvested now for future decryption.
            </p>

            <div className="pane-table">
              <div className="pane-table-header">
                <span>ENCRYPTION STANDARD</span>
                <span>STATUS</span>
              </div>
              {THREAT_POINTS.map((pt) => (
                <div key={pt.label} className="pane-table-row">
                  <span className="pt-label">{pt.label}</span>
                  <span className="pt-status" style={{ color: pt.color, borderColor: pt.color + '40', background: pt.color + '10' }}>
                    {pt.status}
                  </span>
                </div>
              ))}
            </div>

            <div className="pane-alert">
              <Clock size={12} />
              HORIZON: ~7 YEARS TO Q-DAY
            </div>
          </div>
        </div>

        {/* Right: Solution Brief */}
        <div className="split-pane solution-pane">
          <div className="pane-bg" style={{ backgroundImage: `url(${agentsBg})` }} />
          <div className="pane-overlay pane-overlay-right" />

          <div className="pane-content">
            <div className="pane-eyebrow" style={{ color: 'var(--cyan)', borderColor: 'rgba(0,240,255,0.2)', background: 'rgba(0,240,255,0.04)' }}>
              <ShieldCheck size={12} />
              DEFENSE PROTOCOL ACTIVE
            </div>
            <h3 className="pane-title" style={{ color: 'var(--cyan)' }}>The XCIPHER<br/>Solution</h3>
            <p className="pane-desc">
              XCIPHER deploys NIST-finalized PQC algorithms across every agent endpoint. Built from inception for AI-native environments — not retrofitted.
            </p>

            <div className="solution-modules">
              {SOLUTION_POINTS.map(({ Icon, label, desc }) => (
                <div key={label} className="solution-module">
                  <div className="solution-module-icon">
                    <Icon size={14} />
                  </div>
                  <div>
                    <div className="solution-module-label">{label}</div>
                    <div className="solution-module-desc">{desc}</div>
                  </div>
                </div>
              ))}
            </div>

            <div className="pane-alert" style={{ borderColor: 'rgba(0,240,255,0.3)', color: 'var(--cyan)', background: 'rgba(0,240,255,0.06)' }}>
              <ShieldCheck size={12} />
              STATUS: QUANTUM-RESILIENT // ALL NODES SECURED
            </div>
          </div>
        </div>
      </div>

      {/* Bottom Bar */}
      <div className="split-footer">
        <div className="split-footer-grid">
          {[
            { val: '99.97%', label: 'Detection accuracy' },
            { val: '<0.4s', label: 'Mean isolation time' },
            { val: 'CRYSTALS-Kyber', label: 'NIST PQC standard' },
            { val: '12B+', label: 'Events analyzed daily' },
          ].map((stat) => (
            <div key={stat.label} className="split-stat">
              <div className="split-stat-val">{stat.val}</div>
              <div className="split-stat-label">{stat.label}</div>
            </div>
          ))}
        </div>
      </div>

    </section>
  );
};

export default SplitSection;
