import React from 'react';

const PremiumHowItWorks = () => {
  return (
    <section className="how-section" id="how">
  <div className="container">
    <div className="sec-header reveal" style={{"textAlign":"center"}}>
      <div className="sec-tag" style={{"justifyContent":"center"}}>How It Works</div>
      <h2 className="sec-title">From deploy to defended<br />in <em>minutes.</em></h2>
    </div>
    <div className="steps-3d">
      <div className="step-3d reveal reveal-d1">
        <div className="step-node">
          <div className="step-node-ring"></div>
          <div className="step-node-inner">01</div>
        </div>
        <div className="step-title">Connect Your Infrastructure</div>
        <div className="step-desc">Install the lightweight agent or connect via API. XCIPHER maps every asset, service, and traffic flow automatically — on-prem, cloud, or hybrid.</div>
      </div>
      <div className="step-3d reveal reveal-d2">
        <div className="step-node">
          <div className="step-node-ring"></div>
          <div className="step-node-inner">02</div>
        </div>
        <div className="step-title">AI Builds Your Baseline</div>
        <div className="step-desc">The platform learns normal behavior across users, workloads, and network segments. Anomaly detection is contextual — tuned to your org, not a generic ruleset.</div>
      </div>
      <div className="step-3d reveal reveal-d3">
        <div className="step-node">
          <div className="step-node-ring"></div>
          <div className="step-node-inner">03</div>
        </div>
        <div className="step-title">Threats Neutralized Automatically</div>
        <div className="step-desc">Every event triggers a full security sweep. Detections fire automated playbooks instantly. Your team gets a report — not a queue of unread alerts.</div>
      </div>
    </div>
  </div>
</section>
  );
};

export default PremiumHowItWorks;
