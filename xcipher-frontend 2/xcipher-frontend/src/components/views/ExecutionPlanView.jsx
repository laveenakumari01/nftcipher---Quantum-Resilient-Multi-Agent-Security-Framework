import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ArrowLeft, Terminal, Cpu, Network, Lock, Zap, Shield, Eye, Globe } from 'lucide-react';

const ExecutionPlanView = ({ onBack }) => {
  const [activePhase, setActivePhase] = useState(0);

  const phases = [
    {
      title: 'Phase 1: Agent Initialization',
      subtitle: 'Days 1-7: Establishing the PQC Foundation',
      icon: Cpu,
      color: 'var(--accent)',
      desc: 'Deploying the core agentic kernel and establishing the CRYSTALS-Kyber handshake protocol.',
      milestones: [
        'Hardware Integrity Validation',
        'Secure P2P Mesh Routing',
        'Post-Quantum JWT Minting'
      ]
    },
    {
      title: 'Phase 2: Fortress Integration',
      subtitle: 'Days 8-14: Building the Zero-Trust Mesh',
      icon: Shield,
      color: 'var(--primary)',
      desc: 'Integrating the Arbiter and Sentinel agents into the live traffic stream.',
      milestones: [
        'Real-time Risk Scoring Engine',
        'Behavioral Anomaly Detection',
        'Cross-Wing Permission Matrix'
      ]
    },
    {
      title: 'Phase 3: Adversary Simulation',
      subtitle: 'Days 15-21: Stress Testing & Red Teaming',
      icon: Eye,
      color: 'var(--red)',
      desc: 'Deploying the Adversary agent to simulate advanced persistent threats (APTs).',
      milestones: [
        'Simulated Quantum Breaches',
        'Auto-Isolation Trigger Testing',
        'Signature Revocation Speed Tests'
      ]
    },
    {
      title: 'Phase 4: Full Autonomy',
      subtitle: 'Days 22-28: Production Deployment',
      icon: Globe,
      color: 'var(--blue)',
      desc: 'Finalizing the autonomous self-policing grid and historical reporting telemetry.',
      milestones: [
        'Global Mesh Topology Sync',
        'Health Score Historical Ledger',
        'Autonomous Lockdown Activation'
      ]
    }
  ];

  return (
    <div className="premium-theme" style={{ minHeight: '100vh', background: 'var(--bg)', color: 'var(--text)', fontFamily: 'var(--body)', padding: '2rem' }}>
      <button 
        onClick={onBack}
        className="interactive"
        style={{
          background: 'rgba(255,255,255,0.03)', border: '1px solid var(--border)',
          display: 'flex', alignItems: 'center', gap: '8px',
          fontWeight: 500, cursor: 'pointer', color: 'var(--text2)',
          padding: '10px 16px', borderRadius: '100px',
          fontSize: '13px', transition: 'all 0.3s',
          marginBottom: '2rem'
        }}
      >
        <ArrowLeft size={16} /> Back to Landing
      </button>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} style={{ maxWidth: '1000px', margin: '0 auto' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem', marginBottom: '3rem' }}>
          <div style={{ background: 'rgba(138, 43, 226, 0.1)', padding: '20px', borderRadius: '24px', border: '1px solid rgba(138, 43, 226, 0.2)' }}>
            <Terminal size={32} color="var(--primary)" />
          </div>
          <div>
            <h1 style={{ fontSize: '48px', fontFamily: 'var(--display)', letterSpacing: '0.04em', margin: 0 }}>Execution Roadmap</h1>
            <p style={{ color: 'var(--text3)', fontFamily: 'var(--mono)', fontSize: '12px', marginTop: '4px' }}>[PROJECT_NFCTIPHER_V1.0_SEQUENTIAL_DEPLOYMENT]</p>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '2rem' }}>
           {/* Phase Selector */}
           <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {phases.map((p, i) => (
                <div 
                  key={i}
                  onClick={() => setActivePhase(i)}
                  style={{ 
                    padding: '1.5rem', 
                    background: activePhase === i ? 'rgba(255,255,255,0.03)' : 'transparent',
                    border: '1px solid',
                    borderColor: activePhase === i ? 'var(--primary)' : 'var(--border)',
                    borderRadius: '16px',
                    cursor: 'pointer',
                    transition: 'all 0.3s'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <p.icon size={18} color={activePhase === i ? p.color : 'var(--text3)'} />
                    <span style={{ fontSize: '14px', fontFamily: 'var(--display)', color: activePhase === i ? 'var(--text)' : 'var(--text3)' }}>{p.title}</span>
                  </div>
                </div>
              ))}
           </div>

           {/* Phase Detail */}
           <div 
             key={activePhase}
             style={{ background: 'var(--surface)', padding: '3rem', borderRadius: '24px', border: '1px solid var(--border)' }}
           >
              <div style={{ color: phases[activePhase].color, fontFamily: 'var(--mono)', fontSize: '11px', letterSpacing: '0.2em', marginBottom: '8px' }}>
                 {phases[activePhase].subtitle.toUpperCase()}
              </div>
              <h2 style={{ fontSize: '32px', marginBottom: '1.5rem', color: 'var(--text)' }}>{phases[activePhase].title}</h2>
              <p style={{ color: 'var(--text2)', lineHeight: 1.8, fontSize: '16px', marginBottom: '2.5rem' }}>
                 {phases[activePhase].desc}
              </p>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem' }}>
                 {phases[activePhase].milestones.map((m, idx) => (
                   <div key={idx} style={{ background: 'rgba(255,255,255,0.02)', padding: '1.5rem', borderRadius: '12px', border: '1px solid var(--border)', textAlign: 'center' }}>
                      <Zap size={16} color={phases[activePhase].color} style={{ marginBottom: '12px' }} />
                      <div style={{ fontSize: '11px', color: 'var(--text)', fontFamily: 'var(--mono)' }}>{m.toUpperCase()}</div>
                   </div>
                 ))}
              </div>
           </div>

        </div>

        <div style={{ marginTop: '3rem', padding: '2rem', background: 'rgba(0,245,212,0.02)', border: '1px solid rgba(0,245,212,0.1)', borderRadius: '20px', textAlign: 'center' }}>
           <div style={{ fontSize: '12px', fontFamily: 'var(--mono)', color: 'var(--accent)', marginBottom: '1rem' }}>OVERALL_PROJECT_COMPLETION</div>
           <div style={{ height: '8px', background: 'rgba(255,255,255,0.05)', borderRadius: '10px', overflow: 'hidden', maxWidth: '600px', margin: '0 auto' }}>
              <motion.div animate={{ width: '80%' }} style={{ height: '100%', background: 'var(--accent)', boxShadow: '0 0 20px var(--accent-glow)' }} />
           </div>
           <div style={{ fontSize: '24px', fontFamily: 'var(--display)', color: 'var(--accent)', marginTop: '1rem' }}>80%</div>
        </div>
      </motion.div>
    </div>
  );
};

export default ExecutionPlanView;
