import React, { useState, useEffect } from 'react';
import { AnimatePresence, motion } from 'framer-motion';

// Landing Page Components
import Background from './components/layout/Background';
import Cursor from './components/layout/Cursor';
import Navbar from './components/layout/Navbar';
import Hero from './components/sections/Hero';
import SplitSection from './components/sections/SplitSection';
import Architecture from './components/sections/Architecture';
import LiveThreats from './components/sections/LiveThreats';

import PremiumMetrics from './components/sections/PremiumMetrics';
import PremiumFeatures from './components/sections/PremiumFeatures';
import PremiumHowItWorks from './components/sections/PremiumHowItWorks';
import PremiumThreatFeed from './components/sections/PremiumThreatFeed';
import PremiumPricing from './components/sections/PremiumPricing';
import PremiumSecurity from './components/sections/PremiumSecurity';
import PremiumCTA from './components/sections/PremiumCTA';
import PremiumFooter from './components/layout/PremiumFooter';

// App Components
import LoginPage from './components/views/LoginPage';
import DashboardView from './components/views/DashboardView';
import DocsView from './components/views/DocsView';
import ExecutionPlanView from './components/views/ExecutionPlanView';
import LegalView from './components/views/LegalView';
import ContactView from './components/views/ContactView';

function App() {
  const [view, setView] = useState('landing');

  const [authData, setAuthData] = useState({
    token:    localStorage.getItem('access_token') || '',
    username: localStorage.getItem('username')     || '',
    role:     localStorage.getItem('role')         || '',
  });

  const handleLogin = (token, username, role) => {
    setAuthData({ token, username, role });
    setView('dashboard');
  };

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('username');
    localStorage.removeItem('role');
    setAuthData({ token: '', username: '', role: '' });
    setView('landing');
  };

  useEffect(() => {
    let obs;
    const initTimer = setTimeout(() => {
      obs = new IntersectionObserver(entries => {
        entries.forEach(e => {
          if (e.isIntersecting) {
            e.target.classList.add('visible');
          }
        });
      }, { threshold: 0.15 });

      document.querySelectorAll('.reveal').forEach(el => obs.observe(el));

      const magnets = document.querySelectorAll('[data-magnetic]');
      const onMouseMove = function(e) {
        const rect = this.getBoundingClientRect();
        const x = e.clientX - rect.left - rect.width / 2;
        const y = e.clientY - rect.top - rect.height / 2;
        this.style.transform = `translate(${x * 0.2}px, ${y * 0.2}px)`;
      };
      const onMouseLeave = function() {
        this.style.transform = 'translate(0,0)';
      };

      magnets.forEach(btn => {
        btn.addEventListener('mousemove', onMouseMove);
        btn.addEventListener('mouseleave', onMouseLeave);
      });

      const tiltCards = document.querySelectorAll('[data-tilt]');
      const onCardMove = function(e) {
        const rect = this.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        const xc = rect.width / 2;
        const yc = rect.height / 2;
        const dx = x - xc;
        const dy = y - yc;
        this.style.transform = `rotateY(${dx / 20}deg) rotateX(${-dy / 20}deg)`;
      };
      const onCardLeave = function() {
        this.style.transform = 'rotateY(0) rotateX(0)';
      };

      tiltCards.forEach(card => {
        card.addEventListener('mousemove', onCardMove);
        card.addEventListener('mouseleave', onCardLeave);
      });

      return () => {
        if (obs) obs.disconnect();
        magnets.forEach(btn => {
          btn.removeEventListener('mousemove', onMouseMove);
          btn.removeEventListener('mouseleave', onMouseLeave);
        });
        tiltCards.forEach(card => {
          card.removeEventListener('mousemove', onCardMove);
          card.removeEventListener('mouseleave', onCardLeave);
        });
      };
    }, 100);

    return () => clearTimeout(initTimer);
  }, [view]);

  return (
    <>
      <Background />
      <Cursor />

      <div style={{ position: 'relative', zIndex: 10 }}>

        {view === 'landing' && (
          <motion.div
            key="landing"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.5 }}
            className="premium-theme"
          >
            <Navbar onLoginClick={() => setView('login')} onNavigate={(route) => setView(route)} />
            <main>
              <div id="platform">
                <Hero
                  onGetStarted={() => setView('login')}
                  onReadPlan={() => setView('execution_plan')}
                />
              </div>
              <SplitSection />
              <div id="technology">
                <Architecture />
                <LiveThreats />
              </div>
              <div className="premium-sections">
                <PremiumMetrics />
                <PremiumFeatures />
                <PremiumHowItWorks />
                <div id="solutions">
                  <PremiumThreatFeed />
                </div>
                <div id="company">
                  <PremiumPricing />
                </div>
                <PremiumSecurity />
                <PremiumCTA onDeploy={() => setView('login')} onDocs={() => setView('docs')} />
                <PremiumFooter onNavigate={(route) => setView(route)} />
              </div>
            </main>
          </motion.div>
        )}

        {view === 'login' && (
          <motion.div
            key="login"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4 }}
          >
            <LoginPage
              onBack={() => setView('landing')}
              onLogin={handleLogin}
            />
          </motion.div>
        )}

        {view === 'dashboard' && (
          <motion.div
            key="dashboard"
            initial={{ opacity: 0, scale: 0.98 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.5 }}
          >
            <DashboardView
              onLogout={handleLogout}
              username={authData.username}
              role={authData.role}
            />
          </motion.div>
        )}

        {view === 'docs' && (
          <motion.div
            key="docs"
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.4 }}
          >
            <DocsView onBack={() => setView('landing')} />
          </motion.div>
        )}

        {view === 'execution_plan' && (
          <motion.div
            key="execution_plan"
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.4 }}
          >
            <ExecutionPlanView onBack={() => setView('landing')} />
          </motion.div>
        )}

        {view === 'privacy' && (
          <motion.div key="privacy" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} transition={{ duration: 0.4 }}>
            <LegalView onBack={() => setView('landing')} title="Privacy Policy" />
          </motion.div>
        )}

        {view === 'terms' && (
          <motion.div key="terms" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} transition={{ duration: 0.4 }}>
            <LegalView onBack={() => setView('landing')} title="Terms of Service" />
          </motion.div>
        )}

        {view === 'contact' && (
          <motion.div key="contact" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} transition={{ duration: 0.4 }}>
            <ContactView onBack={() => setView('landing')} />
          </motion.div>
        )}

      </div>
    </>
  );
}

export default App;