import React from 'react';
import { motion } from 'framer-motion';
import { ArrowLeft, Shield, FileText, Lock, Eye } from 'lucide-react';
import './LegalView.css';

const LegalView = ({ onBack, title = "Legal Directives" }) => {
  return (
    <div className="legal-view premium-theme">
      <aside className="legal-sidebar">
        <div className="docs-nav-group">
          <span className="docs-nav-label">Compliance Docs</span>
          <div className="docs-nav-link active"><Shield size={14} /> Terms of Service</div>
          <div className="docs-nav-link"><Lock size={14} /> Privacy Protocol</div>
          <div className="docs-nav-link"><Eye size={14} /> Data Disclosure</div>
        </div>

        <div className="docs-nav-group" style={{ marginTop: 'auto' }}>
          <div className="docs-nav-link" onClick={onBack}>
            <ArrowLeft size={14} /> Return to Handshake
          </div>
        </div>
      </aside>

      <main className="legal-content">
        <motion.div initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }}>
          <div className="legal-dossier">
            <div className="legal-restricted-stamp">RESTRICTED</div>
            <h1 className="legal-title">{title}</h1>
            
            <div className="legal-text">
              <p style={{ marginBottom: '2rem' }}>
                [ SYSTEM_HANDSHAKE_LOG: 2026.05.03 // XCIPHER_CORE_v4.2 ]
              </p>

              <div className="legal-section-header">01. ZERO-TRUST MANDATE</div>
              <p>
                XCIPHER operates on a strict zero-trust protocol. No telemetry data is stored in plaintext. 
                All network traffic intercepted by XCIPHER nodes is immediately encrypted using AES-256 
                and wrapped in CRYSTALS-Kyber post-quantum encapsulation before transit.
              </p>

              <div className="legal-section-header">02. AGENT AUTONOMY</div>
              <p>
                By deploying an XCIPHER agent, you grant the node permission to read memory blocks 
                specified in your RBAC configuration. Agents operate defensively and are sandboxed 
                from altering core operating system kernels unless explicitly granted Level 5 Access.
              </p>

              <div className="legal-section-header">03. LIABILITY WAIVER</div>
              <p>
                XCIPHER Inc. provides enterprise-grade security tools but does not assume liability for 
                breaches resulting from compromised Master Gateway tokens or physical social engineering. 
                Maintain your keys securely.
              </p>

              <div style={{ marginTop: '4rem', padding: '1rem', borderTop: '1px solid var(--border)', fontSize: '11px', color: 'var(--text3)' }}>
                [ END_OF_DIRECTIVE // DOCUMENT_ID: {Math.random().toString(36).substring(7).toUpperCase()} ]
              </div>
            </div>
          </div>
        </motion.div>
      </main>
    </div>
  );
};

export default LegalView;
