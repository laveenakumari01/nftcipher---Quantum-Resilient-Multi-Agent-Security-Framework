import React, { useState, useEffect } from 'react';
import { Shield, ChevronRight, Activity, Globe, FileText, BookOpen, Users, Mail, Scale, BarChart2 } from 'lucide-react';
import './Navbar.css';

const NAV_LINKS = [
  { label: 'Platform', section: 'technology' },
  { label: 'Solutions', section: 'solutions' },
  { label: 'Docs', view: 'docs' },
  { label: 'Contact', view: 'contact' },
];

const Navbar = ({ onLoginClick, onNavigate }) => {
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 50);
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const handleClick = (item) => {
    if (item.view && onNavigate) {
      onNavigate(item.view);
    } else if (item.section) {
      const el = document.getElementById(item.section);
      if (el) {
        el.scrollIntoView({ behavior: 'smooth' });
      }
    }
  };

  return (
    <nav className={`navbar ${scrolled ? 'scrolled' : ''}`}>
      <div className="nav-container">
        <a href="/" className="nav-brand interactive" onClick={(e) => { e.preventDefault(); onNavigate('landing'); }}>
          <div className="quantum-logo">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M12 2L4 7V17L12 22L20 17V7L12 2Z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
              <path d="M12 22V12M12 12L4 7M12 12L20 7" stroke="currentColor" strokeWidth="1.2" opacity="0.5"/>
              <circle cx="12" cy="12" r="3" fill="currentColor" fillOpacity="0.2">
                <animate attributeName="r" values="2.5;3.5;2.5" dur="3s" repeatCount="indefinite" />
                <animate attributeName="fill-opacity" values="0.1;0.3;0.1" dur="3s" repeatCount="indefinite" />
              </circle>
              <circle cx="12" cy="12" r="1" fill="currentColor" />
            </svg>
          </div>
          <span className="brand-text">XCIPHER</span>
        </a>

        <div className="nav-links">
          {NAV_LINKS.map((nav) => (
            <button 
              key={nav.label}
              className="nav-link interactive"
              onClick={() => handleClick(nav)}
            >
              {nav.label}
            </button>
          ))}
        </div>

        <div className="nav-actions">
          <div className="system-status">
            <span className="status-dot"></span>
            System Nominal
          </div>
          <button className="nav-btn interactive" onClick={onLoginClick}>
            Enter Dashboard
            <ChevronRight size={15} />
          </button>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
