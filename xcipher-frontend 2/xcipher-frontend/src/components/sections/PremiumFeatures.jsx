import React from 'react';
import './PremiumFeatures.css';

const PremiumFeatures = () => {
  const features = [
    {
      id: "SYS-01",
      hash: "0x8F9A...2B1C",
      title: "Autonomous Threat Detection",
      desc: "AI agents continuously monitor your environment, correlating signals across network, endpoint, and cloud layers — detecting anomalies before they escalate into incidents.",
      metrics: [80, 40, 95, 60]
    },
    {
      id: "SYS-02",
      hash: "0x3D4E...7F8A",
      title: "Real-Time Analytics",
      desc: "Live dashboards surfacing threat intelligence, behavioral baselines, and risk scoring across every asset — with drill-down from fleet to individual endpoint in seconds.",
      metrics: [60, 90, 50, 85]
    },
    {
      id: "SYS-03",
      hash: "0x1A2B...9C0D",
      title: "Zero-Trust Infrastructure",
      desc: "Enforce least-privilege access across every service, user, and device. Continuous verification ensures no lateral movement goes undetected — even inside your perimeter.",
      metrics: [100, 100, 100, 100]
    },
    {
      id: "SYS-04",
      hash: "0x5E6F...3A4B",
      title: "Automated Response",
      desc: "Playbooks execute automatically on detection — isolating hosts, revoking credentials, blocking IPs. Mean response time under 0.4 seconds. Your team reviews outcomes, not alerts.",
      metrics: [20, 95, 80, 40]
    }
  ];

  return (
    <section className="phd-features-section" id="features">
      <div className="phd-features-container">
        <div className="phd-section-header">
          <div className="phd-sys-tag">MODULE: CORE_DEFENSE</div>
          <h2 className="phd-section-title">Security That Thinks<br/>Before You Do.</h2>
        </div>

        <div className="phd-schematic-grid">
          {features.map((feat, index) => (
            <div key={index} className="phd-data-sheet">
              <div className="phd-connector"></div>
              
              <div className="phd-sheet-meta">
                <div className="phd-meta-block">
                  <span className="phd-meta-label">IDENTIFIER</span>
                  <span className="phd-meta-value">{feat.id}</span>
                </div>
                <div className="phd-meta-block">
                  <span className="phd-meta-label">CHECKSUM</span>
                  <span className="phd-meta-value">{feat.hash}</span>
                </div>
                <div className="phd-meta-block">
                  <span className="phd-meta-label">STATUS</span>
                  <span className="phd-meta-value" style={{color: 'var(--green)'}}>ONLINE</span>
                </div>
              </div>

              <div className="phd-sheet-core">
                <h3 className="phd-sheet-title">{feat.title}</h3>
                <p className="phd-sheet-desc">{feat.desc}</p>
              </div>

              <div className="phd-sheet-visual">
                {feat.metrics.map((val, i) => (
                  <div key={i} className="phd-vis-line">
                    <span className="phd-vis-label">CH-{i+1}</span>
                    <div className="phd-vis-bar" style={{width: `${val}%`}}></div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default PremiumFeatures;
