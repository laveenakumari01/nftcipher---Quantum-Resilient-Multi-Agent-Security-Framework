import React, { useRef, useEffect } from 'react';
import { ArrowRight, Terminal } from 'lucide-react';
import './Hero.css';

const Hero = ({ onGetStarted, onReadPlan }) => {
  const heroRef = useRef(null);

  useEffect(() => {
    const handleMouseMove = (e) => {
      if (!heroRef.current) return;
      const x = (e.clientX / window.innerWidth - 0.5) * 20;
      const y = (e.clientY / window.innerHeight - 0.5) * 20;
      heroRef.current.style.transform = `perspective(1000px) rotateY(${x}deg) rotateX(${-y}deg)`;
    };
    
    window.addEventListener('mousemove', handleMouseMove);
    return () => window.removeEventListener('mousemove', handleMouseMove);
  }, []);

  return (
    <section className="phd-hero-section">
      <div className="phd-hero-bg">
        <div className="phd-glow-orb"></div>
        <div className="phd-grid-lines"></div>
      </div>
      
      <div className="phd-hero-container">
        {/* Left Telemetry HUD */}
        <div className="phd-hud-panel left-hud">
          <div className="phd-hud-metric">
            <span className="phd-label">CRYPTO.SYS</span>
            <span className="phd-value">KYBER-1024</span>
          </div>
          <div className="phd-hud-metric">
            <span className="phd-label">ENTROPY</span>
            <span className="phd-value" style={{color: 'var(--cyan)'}}>99.998%</span>
          </div>
          <div className="phd-hud-graph">
            {Array.from({length: 15}).map((_, i) => (
              <div key={i} className="phd-bar" style={{height: `${Math.random() * 100}%`}}></div>
            ))}
          </div>
        </div>

        {/* Center Content */}
        <div className="phd-hero-content" ref={heroRef}>
          <div className="phd-eyebrow">
            [ SECURE INITIALIZATION PROTOCOL ]
          </div>
          <h1 className="phd-hero-title">
            AUTONOMOUS<br/><span className="text-glow">DEFENSE GRID</span>
          </h1>
          <p className="phd-hero-subtitle">
            Zero-trust, post-quantum security framework. Designed exclusively for protecting distributed AI agents against harvest-now, decrypt-later attacks.
          </p>
          
          <div className="phd-terminal-box">
            <div className="phd-term-header">
              <Terminal size={12} /> root@x-cipher: /sys/core
            </div>
            <div className="phd-term-body">
              <div className="phd-line"><span className="phd-prompt">$</span> ./deploy_sentinel.sh --pqc</div>
              <div className="phd-line success">[OK] Quantum keys generated.</div>
              <div className="phd-line success">[OK] Neural anomaly detection active.</div>
              <div className="phd-line"><span className="phd-prompt blink">_</span></div>
            </div>
          </div>

          <div className="phd-hero-actions">
            <button className="phd-hero-deploy-btn interactive" onClick={onGetStarted}>
              Deploy Node
              <ArrowRight size={16} />
            </button>
            <button className="phd-btn-ghost" onClick={onReadPlan}>
              [ READ SPECS ]
            </button>
          </div>
        </div>

        {/* Right Telemetry HUD */}
        <div className="phd-hud-panel right-hud">
          <div className="phd-hud-metric">
            <span className="phd-label">THREAT LEVEL</span>
            <span className="phd-value" style={{color: 'var(--green)'}}>NOMINAL</span>
          </div>
          <div className="phd-hud-metric">
            <span className="phd-label">ACTIVE NODES</span>
            <span className="phd-value">14,204</span>
          </div>
          <div className="phd-hud-target">
            <div className="phd-crosshair"></div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default Hero;
