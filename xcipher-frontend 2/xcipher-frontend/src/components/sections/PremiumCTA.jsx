import React from 'react';
import { Terminal, ShieldAlert } from 'lucide-react';
import './PremiumCTA.css';

const PremiumCTA = ({ onDeploy, onDocs }) => {
  return (
    <section className="phd-cta-section">
      <div className="phd-cta-container">
        <div className="phd-cta-terminal">
          <div className="phd-cta-header">
            <ShieldAlert size={16} color="var(--red)" />
            CRITICAL VULNERABILITY DETECTED IN LEGACY SYSTEMS
          </div>
          
          <h2 className="phd-cta-title">Stop Shipping<br/>Vulnerabilities.</h2>
          <p className="phd-cta-sub">
            Legacy security models cannot protect autonomous AI agents. Upgrade to a quantum-resilient, zero-trust infrastructure immediately.
          </p>

          <div className="phd-cta-prompt">
            <span className="phd-prompt-char">&gt;</span>
            <span className="phd-prompt-text">INITIATE DEPLOYMENT SEQUENCE...</span>
            <span className="blink">_</span>
          </div>

          <div className="phd-cta-btns">
            <button onClick={onDeploy} className="btn-primary-3d">
              <span className="btn-shine"></span>
              [ EXECUTE DEPLOY ]
            </button>
            <button onClick={onDocs} className="phd-cta-docs">
              VIEW DOCS
            </button>
          </div>
        </div>
      </div>
    </section>
  );
};

export default PremiumCTA;
