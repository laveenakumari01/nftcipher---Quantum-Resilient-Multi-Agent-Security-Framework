import React from 'react';

const PremiumMetrics = () => {
  return (
    <section className="metrics-section">
  <div className="container">
    <div className="metrics-3d reveal">
      <div className="metric-3d">
        <div className="metric-num-3d">99.<span>97</span>%</div>
        <div className="metric-lbl">Threat Detection Accuracy</div>
        <div className="metric-delta">↑ 2.1% vs last quarter</div>
      </div>
      <div className="metric-3d">
        <div className="metric-num-3d">&lt;<span>0.4</span>s</div>
        <div className="metric-lbl">Mean Time to Respond</div>
        <div className="metric-delta">Industry avg: 24 min</div>
      </div>
      <div className="metric-3d">
        <div className="metric-num-3d">12<span>B+</span></div>
        <div className="metric-lbl">Events Analyzed Daily</div>
        <div className="metric-delta">Across all tenants</div>
      </div>
      <div className="metric-3d">
        <div className="metric-num-3d">0.<span>001</span>%</div>
        <div className="metric-lbl">False Positive Rate</div>
        <div className="metric-delta">↓ 89% vs rule-based systems</div>
      </div>
    </div>
  </div>
</section>
  );
};

export default PremiumMetrics;
