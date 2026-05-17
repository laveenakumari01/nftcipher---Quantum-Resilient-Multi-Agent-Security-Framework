import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ArrowLeft, FileText, Book, Code, Shield, Terminal, Zap, Layers, Cpu, CheckCircle, Search, Terminal as TermIcon } from 'lucide-react';
import './DocsView.css';

const SECTIONS_DATA = {
  'Introduction': {
    title: 'Technical Docs',
    subtitle: 'Deep technical specifications for the XCIPHER autonomous defense grid.',
    type: 'home'
  },
  'Zero Trust Handshake': {
    title: 'Zero Trust Handshake',
    subtitle: 'Understanding the Multi-Agent Verification Protocol.',
    content: (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
        <div style={{ padding: '2rem', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border)', borderRadius: '12px' }}>
          <h3 style={{ fontFamily: 'var(--display)', color: 'var(--primary)', marginBottom: '1.5rem', fontSize: '18px' }}>[ PROTOCOL_FLOW ]</h3>
          <p style={{ color: 'var(--text2)', lineHeight: 1.8, marginBottom: '2rem', fontSize: '14px' }}>
            The XCIPHER Handshake utilizes a three-tier agent verification process. Every request must be signed by the <strong>Cryptographer</strong>, vetted by the <strong>Sentinel</strong>, and finally approved by the <strong>Arbiter</strong>.
          </p>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1.5rem' }}>
            {['AGENT_SIGNING', 'IDENTITY_PROVING', 'RISK_SCORING'].map((step, i) => (
              <div key={i} style={{ padding: '1.5rem', border: '1px solid var(--border)', textAlign: 'center', background: 'rgba(0,0,0,0.2)' }}>
                <CheckCircle size={20} color="var(--accent)" style={{ marginBottom: '12px' }} />
                <div style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text)', letterSpacing: '0.1em' }}>{step}</div>
              </div>
            ))}
          </div>
        </div>
        <div style={{ padding: '2rem', border: '1px solid var(--border)', background: 'rgba(142, 45, 226, 0.03)' }}>
           <h4 style={{ fontFamily: 'var(--mono)', fontSize: '12px', color: 'var(--primary)', marginBottom: '1rem' }}>HANDSHAKE_LATENCY_REPORT</h4>
           <div style={{ height: '40px', display: 'flex', gap: '4px', alignItems: 'flex-end' }}>
              {Array.from({length: 40}).map((_, i) => <div key={i} style={{ flex: 1, background: 'var(--primary)', height: `${20 + Math.random() * 80}%`, opacity: 0.3 }} />)}
           </div>
        </div>
      </div>
    )
  },
  'PQC Implementation': {
    title: 'PQC Implementation',
    subtitle: 'Post-Quantum Cryptography Architecture.',
    content: (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
        <div style={{ padding: '2rem', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border)', borderRadius: '12px' }}>
          <h3 style={{ fontFamily: 'var(--display)', color: 'var(--primary)', marginBottom: '1.5rem', fontSize: '18px' }}>[ ALGORITHM_STACK ]</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
             <div style={{ padding: '1.5rem', border: '1px solid var(--border)', background: 'rgba(0,245,212,0.05)' }}>
                <div style={{ fontSize: '14px', color: 'var(--accent)', fontWeight: 800, fontFamily: 'var(--display)' }}>CRYSTALS-Kyber-1024</div>
                <div style={{ fontSize: '12px', color: 'var(--text2)', marginTop: '8px', lineHeight: 1.6 }}>NIST Category 5 Lattice-based Key Encapsulation. Chosen for its high performance and robust resistance to quantum-aided cryptanalysis.</div>
             </div>
             <div style={{ padding: '1.5rem', border: '1px solid var(--border)', background: 'rgba(138,43,226,0.05)' }}>
                <div style={{ fontSize: '14px', color: 'var(--primary)', fontWeight: 800, fontFamily: 'var(--display)' }}>CRYSTALS-Dilithium</div>
                <div style={{ fontSize: '12px', color: 'var(--text2)', marginTop: '8px', lineHeight: 1.6 }}>Digital Signatures based on finding short vectors in lattices. Ensures agent identity cannot be forged by Shor's Algorithm.</div>
             </div>
          </div>
        </div>
      </div>
    )
  },
  'API Endpoints': {
    title: 'API Reference',
    subtitle: 'GraphQL and Telemetry Hooks.',
    content: (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
        {[
          { method: 'POST', path: '/v1/agent/handshake', desc: 'Initiate PQC key exchange with a remote node.' },
          { method: 'GET', path: '/v1/telemetry/anomalies', desc: 'Fetch real-time threat detection logs from Sentinel.' },
          { method: 'WS', path: '/v1/mesh/stream', desc: 'Subscribe to the live agent communication mesh.' }
        ].map((api, i) => (
          <div key={i} style={{ padding: '1.5rem', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border)', borderRadius: '8px' }}>
             <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', marginBottom: '8px' }}>
                <span style={{ color: 'var(--accent)', fontFamily: 'var(--mono)', fontSize: '12px', fontWeight: 800 }}>{api.method}</span>
                <span style={{ color: 'var(--text)', fontFamily: 'var(--mono)', fontSize: '13px' }}>{api.path}</span>
             </div>
             <div style={{ fontSize: '12px', color: 'var(--text3)' }}>{api.desc}</div>
          </div>
        ))}
      </div>
    )
  },
  'CLI Reference': {
    title: 'CLI Reference',
    subtitle: 'Command Line Interface for Node Management.',
    content: (
      <div style={{ padding: '2rem', background: '#0a0a0f', border: '1px solid var(--border)', borderRadius: '8px', fontFamily: 'var(--mono)', fontSize: '13px' }}>
         <div style={{ color: 'var(--primary)', marginBottom: '1rem' }}># XCIPHER_CORE_CLI_v1.0</div>
         <div style={{ marginBottom: '0.5rem' }}><span style={{ color: 'var(--accent)' }}>xcipher</span> init --pqc <span style={{ color: 'var(--text3)' }}># Initialize node with PQC</span></div>
         <div style={{ marginBottom: '0.5rem' }}><span style={{ color: 'var(--accent)' }}>xcipher</span> agent status <span style={{ color: 'var(--text3)' }}># Show live agent health</span></div>
         <div style={{ marginBottom: '0.5rem' }}><span style={{ color: 'var(--accent)' }}>xcipher</span> mesh connect [id] <span style={{ color: 'var(--text3)' }}># Connect to global grid</span></div>
         <div style={{ marginTop: '1rem' }}><span style={{ color: 'var(--text3)' }}>_</span></div>
      </div>
    )
  },
  'SDK Guide': {
    title: 'SDK Guide',
    subtitle: 'Build Autonomous Agents with XCIPHER SDK.',
    content: (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
         <div style={{ padding: '2rem', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border)', borderRadius: '12px' }}>
            <h4 style={{ fontFamily: 'var(--display)', color: 'var(--text)', marginBottom: '1rem' }}>INSTALLATION</h4>
            <div style={{ padding: '1rem', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border)', fontFamily: 'var(--mono)', fontSize: '13px' }}>
               npm install @xcipher/core-sdk
            </div>
         </div>
         <div style={{ padding: '2rem', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border)', borderRadius: '12px' }}>
            <h4 style={{ fontFamily: 'var(--display)', color: 'var(--text)', marginBottom: '1rem' }}>INITIALIZING_AGENT</h4>
            <pre style={{ fontSize: '12px', color: 'var(--text2)', background: 'rgba(0,0,0,0.2)', padding: '1rem', overflowX: 'auto' }}>
{`import { XCipherAgent } from '@xcipher/sdk';

const agent = new XCipherAgent({
  wing: 'OPERATIONAL',
  mode: 'ZERO_TRUST'
});

await agent.initialize();`}
            </pre>
         </div>
      </div>
    )
  }
};

const DocsView = ({ onBack }) => {
  const [activeSection, setActiveSection] = useState('Introduction');

  const navItems = [
    { group: 'Core Protocols', items: [
      { id: 'Introduction', label: 'Introduction', icon: Layers },
      { id: 'Zero Trust Handshake', label: 'Zero Trust Handshake', icon: Shield },
      { id: 'PQC Implementation', label: 'PQC Implementation', icon: Zap }
    ]},
    { group: 'Developer Hub', items: [
      { id: 'API Endpoints', label: 'API Endpoints', icon: Code },
      { id: 'CLI Reference', label: 'CLI Reference', icon: Terminal },
      { id: 'SDK Guide', label: 'SDK Guide', icon: Cpu }
    ]}
  ];

  return (
    <div className="docs-view premium-theme">
      <aside className="docs-sidebar">
        {navItems.map((group, i) => (
          <div key={i} className="docs-nav-group">
            <span className="docs-nav-label">{group.group}</span>
            {group.items.map(item => (
              <div 
                key={item.id} 
                className={`docs-nav-link ${activeSection === item.id ? 'active' : ''}`}
                onClick={() => setActiveSection(item.id)}
              >
                <item.icon size={14} /> {item.label}
              </div>
            ))}
          </div>
        ))}

        <div className="docs-nav-group" style={{ marginTop: 'auto' }}>
          <div className="docs-nav-link" onClick={onBack}>
            <ArrowLeft size={14} /> Back to Landing
          </div>
        </div>
      </aside>

      <main className="docs-content">
        <div style={{ maxWidth: '800px' }}>
            <header className="docs-header">
              <div className="docs-blueprint-bg"></div>
              <h1 style={{ color: 'var(--primary)', textShadow: '0 0 40px var(--primary-glow)', marginBottom: '0.5rem' }}>
                {SECTIONS_DATA[activeSection]?.title || activeSection}
              </h1>
              <p style={{ fontSize: '18px', color: 'var(--text2)', maxWidth: '700px', lineHeight: 1.6, marginBottom: '2rem' }}>
                {SECTIONS_DATA[activeSection]?.subtitle || 'Section details syncing...'}
              </p>
              <div style={{ height: '1px', width: '100%', background: 'linear-gradient(90deg, var(--border), transparent)', marginBottom: '3rem' }}></div>
            </header>

            {activeSection === 'Introduction' ? (
               <div className="docs-grid">
               {[
                 { id: 'Zero Trust Handshake', title: 'Handshake Protocol', icon: Shield, desc: 'Detailed breakdown of the Kyber-1024 key encapsulation mechanism and agent identity verification.' },
                 { id: 'PQC Implementation', title: 'PQC Architecture', icon: Zap, desc: 'Understanding lattice-based cryptography and resistance to quantum decryption threats.' },
                 { id: 'API Endpoints', title: 'API Integration', icon: Code, desc: 'Connect your AI agents natively via the XCIPHER GraphQL mesh and real-time telemetry hooks.' },
                 { id: 'SDK Guide', title: 'SDK Guide', icon: Cpu, desc: 'Build and deploy autonomous agents with our native TypeScript/Rust SDK.' }
               ].map((item, i) => (
                 <div key={i} className="docs-card" onClick={() => setActiveSection(item.id)}>
                   <div className="docs-card-icon">
                     <item.icon size={24} />
                   </div>
                   <h3>{item.title}</h3>
                   <p>{item.desc}</p>
                   <div style={{ marginTop: '1.5rem', display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--accent)', fontSize: '12px', fontFamily: 'var(--mono)', cursor: 'pointer' }}>
                     READ SPECIFICATION <Zap size={10} />
                   </div>
                 </div>
               ))}
             </div>
            ) : (
              <div key={activeSection}>
                {SECTIONS_DATA[activeSection]?.content || (
                  <div style={{ padding: '3rem', border: '1px dashed var(--border)', textAlign: 'center', color: 'var(--text3)' }}>
                    <TermIcon size={32} style={{ marginBottom: '1rem', opacity: 0.5 }} />
                    <p>Technical details for <strong>{activeSection}</strong> are currently under encryption review.</p>
                  </div>
                )}
              </div>
            )}

            {activeSection === 'Introduction' && (
              <div style={{ marginTop: '4rem', padding: '3rem', border: '1px dashed var(--border)', background: 'rgba(142, 45, 226, 0.02)', textAlign: 'center' }}>
                <h2 style={{ fontFamily: 'var(--display)', fontSize: '2rem', marginBottom: '1rem' }}>Developer Portal Status</h2>
                <p style={{ color: 'var(--text2)', fontFamily: 'var(--mono)', fontSize: '13px' }}>
                  [SYNCING_REAL_TIME_BLUEPRINTS]... 84% COMPLETE
                </p>
                <div style={{ width: '200px', height: '2px', background: 'var(--border)', margin: '1rem auto', position: 'relative', overflow: 'hidden' }}>
                  <div style={{ position: 'absolute', top: 0, left: 0, height: '100%', width: '84%', background: 'var(--accent)', boxShadow: '0 0 10px var(--accent-glow)' }}></div>
                </div>
              </div>
            )}
        </div>
      </main>
    </div>
  );
};

export default DocsView;
