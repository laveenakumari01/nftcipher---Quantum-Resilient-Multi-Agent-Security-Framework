import React from 'react';

const PremiumPricing = () => {
  return (
    <section className="pricing-section" id="pricing">
  <div className="container">
    <div className="sec-header reveal" style={{"textAlign":"center"}}>
      <div className="sec-tag" style={{"justifyContent":"center"}}>Pricing</div>
      <h2 className="sec-title">Simple, transparent pricing.</h2>
      <p className="sec-desc" style={{"margin":"0 auto"}}>Start free with 50 endpoints. Scale to enterprise without surprises.</p>
    </div>
    <div className="pricing-grid">
      <div className="price-card reveal reveal-d1">
        <div className="price-tier">Starter</div>
        <div className="price-amount">$0 <span>/ month</span></div>
        <div className="price-sub">50 endpoints. No credit card required.</div>
        <div className="price-feat on"><div className="pf-check"><svg viewBox="0 0 8 8" fill="none"><path d="M1.5 4L3 5.5L6.5 2" stroke="#00ff88" strokeWidth="1.2" strokeLinecap="round"/></svg></div>Autonomous threat detection</div>
        <div className="price-feat on"><div className="pf-check"><svg viewBox="0 0 8 8" fill="none"><path d="M1.5 4L3 5.5L6.5 2" stroke="#00ff88" strokeWidth="1.2" strokeLinecap="round"/></svg></div>Real-time alert feed</div>
        <div className="price-feat on"><div className="pf-check"><svg viewBox="0 0 8 8" fill="none"><path d="M1.5 4L3 5.5L6.5 2" stroke="#00ff88" strokeWidth="1.2" strokeLinecap="round"/></svg></div>Cloud &amp; on-prem agents</div>
        <div className="price-feat"><div className="pf-check"><div className="pf-dot"></div></div>Automated playbooks</div>
        <div className="price-feat"><div className="pf-check"><div className="pf-dot"></div></div>SSO &amp; RBAC</div>
        <div className="price-feat"><div className="pf-check"><div className="pf-dot"></div></div>SOC 2 reports</div>
        <a href="#" className="price-cta">Get Started Free</a>
      </div>
      <div className="price-card featured reveal reveal-d2">
        <div className="price-featured-line"></div>
        <div className="pop-badge">MOST POPULAR</div>
        <div className="price-tier">Professional</div>
        <div className="price-amount">$599 <span>/ month</span></div>
        <div className="price-sub">Unlimited endpoints. Priority response SLA.</div>
        <div className="price-feat on"><div className="pf-check"><svg viewBox="0 0 8 8" fill="none"><path d="M1.5 4L3 5.5L6.5 2" stroke="#00ff88" strokeWidth="1.2" strokeLinecap="round"/></svg></div>Autonomous threat detection</div>
        <div className="price-feat on"><div className="pf-check"><svg viewBox="0 0 8 8" fill="none"><path d="M1.5 4L3 5.5L6.5 2" stroke="#00ff88" strokeWidth="1.2" strokeLinecap="round"/></svg></div>Real-time alert feed</div>
        <div className="price-feat on"><div className="pf-check"><svg viewBox="0 0 8 8" fill="none"><path d="M1.5 4L3 5.5L6.5 2" stroke="#00ff88" strokeWidth="1.2" strokeLinecap="round"/></svg></div>Cloud &amp; on-prem agents</div>
        <div className="price-feat on"><div className="pf-check"><svg viewBox="0 0 8 8" fill="none"><path d="M1.5 4L3 5.5L6.5 2" stroke="#00ff88" strokeWidth="1.2" strokeLinecap="round"/></svg></div>Automated playbooks</div>
        <div className="price-feat on"><div className="pf-check"><svg viewBox="0 0 8 8" fill="none"><path d="M1.5 4L3 5.5L6.5 2" stroke="#00ff88" strokeWidth="1.2" strokeLinecap="round"/></svg></div>SSO &amp; RBAC</div>
        <div className="price-feat"><div className="pf-check"><div className="pf-dot"></div></div>SOC 2 reports</div>
        <a href="#" className="price-cta">Start 14-Day Trial</a>
      </div>
      <div className="price-card reveal reveal-d3">
        <div className="price-tier">Enterprise</div>
        <div className="price-amount" style={{"fontSize":"38px","lineHeight":"1.1","paddingTop":"4px"}}>Custom</div>
        <div className="price-sub">Dedicated infra. Unlimited scale.</div>
        <div className="price-feat on"><div className="pf-check"><svg viewBox="0 0 8 8" fill="none"><path d="M1.5 4L3 5.5L6.5 2" stroke="#00ff88" strokeWidth="1.2" strokeLinecap="round"/></svg></div>Everything in Pro</div>
        <div className="price-feat on"><div className="pf-check"><svg viewBox="0 0 8 8" fill="none"><path d="M1.5 4L3 5.5L6.5 2" stroke="#00ff88" strokeWidth="1.2" strokeLinecap="round"/></svg></div>SOC 2 Type II reports</div>
        <div className="price-feat on"><div className="pf-check"><svg viewBox="0 0 8 8" fill="none"><path d="M1.5 4L3 5.5L6.5 2" stroke="#00ff88" strokeWidth="1.2" strokeLinecap="round"/></svg></div>VPC peering &amp; private deploy</div>
        <div className="price-feat on"><div className="pf-check"><svg viewBox="0 0 8 8" fill="none"><path d="M1.5 4L3 5.5L6.5 2" stroke="#00ff88" strokeWidth="1.2" strokeLinecap="round"/></svg></div>Dedicated SRE support</div>
        <div className="price-feat on"><div className="pf-check"><svg viewBox="0 0 8 8" fill="none"><path d="M1.5 4L3 5.5L6.5 2" stroke="#00ff88" strokeWidth="1.2" strokeLinecap="round"/></svg></div>SLA 99.99% uptime</div>
        <div className="price-feat on"><div className="pf-check"><svg viewBox="0 0 8 8" fill="none"><path d="M1.5 4L3 5.5L6.5 2" stroke="#00ff88" strokeWidth="1.2" strokeLinecap="round"/></svg></div>Custom compliance reports</div>
        <a href="#" className="price-cta">Contact Sales →</a>
      </div>
    </div>
  </div>
</section>
  );
};

export default PremiumPricing;
