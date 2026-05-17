import React from 'react';

const PremiumFooter = ({ onNavigate }) => {
  const scrollTo = (id) => {
    const el = document.getElementById(id);
    if (el) {
      const yOffset = -80; // Account for navbar if sticky, though mostly just visual buffer
      const y = el.getBoundingClientRect().top + window.pageYOffset + yOffset;
      window.scrollTo({ top: y, behavior: 'smooth' });
    }
  };
  return (
    <footer>
  <div className="container">
    <div className="footer-grid">
      <div>
        <div className="footer-brand">X<span>Cipher</span></div>
        <div className="footer-desc">Agentic cybersecurity platform for high-compliance engineering teams. Autonomous detection. Zero-trust by default.</div>
      </div>
      <div>
        <div className="footer-col-title">Product</div>
        <div className="footer-links">
          <button className="interactive" onClick={() => scrollTo('technology')} style={{ background: 'transparent', border: 'none', color: 'var(--text3)', textAlign: 'left', cursor: 'pointer', padding: 0 }}>Features</button>
          <button className="interactive" onClick={() => scrollTo('company')} style={{ background: 'transparent', border: 'none', color: 'var(--text3)', textAlign: 'left', cursor: 'pointer', padding: 0 }}>Pricing</button>
        </div>
      </div>
      <div>
        <div className="footer-col-title">Resources</div>
        <div className="footer-links">
          <button className="interactive" onClick={() => onNavigate('docs')} style={{ background: 'transparent', border: 'none', color: 'var(--text3)', textAlign: 'left', cursor: 'pointer', padding: 0 }}>Documentation</button>
          <button className="interactive" onClick={() => onNavigate('docs')} style={{ background: 'transparent', border: 'none', color: 'var(--text3)', textAlign: 'left', cursor: 'pointer', padding: 0 }}>API Reference</button>
        </div>
      </div>
      <div>
        <div className="footer-col-title">Company</div>
        <div className="footer-links">
          <button className="interactive" onClick={() => scrollTo('security')} style={{ background: 'transparent', border: 'none', color: 'var(--text3)', textAlign: 'left', cursor: 'pointer', padding: 0 }}>Security</button>
          <button className="interactive" onClick={() => onNavigate('privacy')} style={{ background: 'transparent', border: 'none', color: 'var(--text3)', textAlign: 'left', cursor: 'pointer', padding: 0 }}>Privacy</button>
          <button className="interactive" onClick={() => onNavigate('terms')} style={{ background: 'transparent', border: 'none', color: 'var(--text3)', textAlign: 'left', cursor: 'pointer', padding: 0 }}>Terms</button>
          <button className="interactive" onClick={() => onNavigate('contact')} style={{ background: 'transparent', border: 'none', color: 'var(--text3)', textAlign: 'left', cursor: 'pointer', padding: 0 }}>Contact</button>
        </div>
      </div>
    </div>
    <div className="footer-bottom">
      <span className="footer-copy">© 2026 XCIPHER Inc. All rights reserved.</span>
      <div className="footer-sys"><span className="pulse-dot"></span>All systems operational</div>
    </div>
  </div>
</footer>
  );
};

export default PremiumFooter;
