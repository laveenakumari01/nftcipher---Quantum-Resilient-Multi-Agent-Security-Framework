import React from 'react';
import { ShieldAlert, BrainCircuit, LockKeyhole, Activity } from 'lucide-react';
import './Architecture.css';

const nodes = [
  {
    id: 'NODE-001',
    Icon: LockKeyhole,
    title: 'Zero Trust Verification',
    desc: 'Every request from an AI agent is strictly authenticated using JWT tokens. No implicit trust is granted, ensuring lateral movement is impossible.',
  },
  {
    id: 'NODE-002',
    Icon: ShieldAlert,
    title: 'Post-Quantum Crypto',
    desc: 'Requests and responses are encrypted using PQC algorithms (CRYSTALS-Kyber), ensuring protection against "harvest now, decrypt later" strategies.',
  },
  {
    id: 'NODE-003',
    Icon: BrainCircuit,
    title: 'AI Anomaly Detection',
    desc: 'Machine learning models analyze behavior patterns in real-time. Any deviation from standard agent workflows triggers immediate isolation.',
  },
  {
    id: 'NODE-004',
    Icon: Activity,
    title: 'Live Telemetry',
    desc: 'System status, alerts, and metrics are displayed in real-time on the monitoring dashboard, providing total operational visibility.',
  },
];

const Architecture = () => {
  return (
    <section className="architecture-section" id="architecture">
      <div className="arch-container">
        <div className="arch-header">
          <div className="eyebrow">
            <span className="eyebrow-dot"></span>
            MODULE: SYSTEM_ARCHITECTURE
          </div>
          <h2 className="arch-title">Secure AI Agent<br/>Ecosystem</h2>
          <p className="arch-desc">
            A centralized backend managing agent communication through a zero-trust, quantum-resilient security gateway.
          </p>
        </div>

        <div className="arch-grid">
          {nodes.map(({ id, Icon, title, desc }) => (
            <div className="arch-card interactive" key={id}>
              <div className="arch-card-id">// {id}</div>
              <div className="card-icon">
                <Icon size={20} />
              </div>
              <h3 className="card-title">{title}</h3>
              <p className="card-desc">{desc}</p>
              <div className="arch-card-status">ONLINE</div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default Architecture;
