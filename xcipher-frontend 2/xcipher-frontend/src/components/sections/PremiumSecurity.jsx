import React from 'react';

const PremiumSecurity = () => {
  return (
    <section className="security-section" id="security">
  <div className="container">
    <div className="sec-header reveal">
      <div className="sec-tag">Enterprise Security</div>
      <h2 className="sec-title">Built for high-compliance<br /><em>environments.</em></h2>
    </div>
    <div className="sec-certs">
      <div className="cert-card reveal reveal-d1">
        <div className="cert-num">01</div>
        <div><div className="cert-title">SOC 2 Type II Certified</div><div className="cert-desc">Annually audited infrastructure. Strict access controls, continuous vulnerability scanning, and isolated execution environments for every tenant.</div></div>
      </div>
      <div className="cert-card reveal reveal-d2">
        <div className="cert-num">02</div>
        <div><div className="cert-title">End-to-End Encryption</div><div className="cert-desc">AES-256 at rest, TLS 1.3 in transit. Credentials, environment variables, and event data are never stored beyond active session scope.</div></div>
      </div>
      <div className="cert-card reveal reveal-d3">
        <div className="cert-num">03</div>
        <div><div className="cert-title">SSO &amp; Granular RBAC</div><div className="cert-desc">Integrate with Okta, Azure AD, Google Workspace, or any SAML provider. Role-based access with full audit trails for every action.</div></div>
      </div>
      <div className="cert-card reveal reveal-d4">
        <div className="cert-num">04</div>
        <div><div className="cert-title">VPC Peering (Enterprise)</div><div className="cert-desc">Deploy agents inside your private network or AWS VPC. All telemetry stays within your perimeter — no staging environment exposed publicly.</div></div>
      </div>
    </div>
  </div>
</section>
  );
};

export default PremiumSecurity;
