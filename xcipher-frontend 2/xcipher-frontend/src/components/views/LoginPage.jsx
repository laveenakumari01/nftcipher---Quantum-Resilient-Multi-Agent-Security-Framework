import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Shield, ArrowLeft, Mail, Lock, Eye, EyeOff, Globe, Terminal } from 'lucide-react';
import './LoginPage.css';

const BACKEND_URL = "http://localhost:8000";

const LoginPage = ({ onBack, onLogin }) => {
  const [showPass, setShowPass]   = useState(false);
  const [formData, setFormData]   = useState({ email: '', password: '' });
  const [loading, setLoading]     = useState(false);
  const [error, setError]         = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const res = await fetch(`${BACKEND_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: formData.email,
          password: formData.password,
        }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || 'Login failed');
      }

      const data = await res.json();

      // JWT token + user info localStorage mein save karo
      localStorage.setItem('access_token', data.access_token);
      localStorage.setItem('username',     data.username);
      localStorage.setItem('role',         data.role);

      setLoading(false);
      onLogin(data.access_token, data.username, data.role);

    } catch (err) {
      setLoading(false);
      setError(err.message || 'Backend se connect nahi ho saka');
    }
  };

  return (
    <div className="login-view premium-theme">
      <div className="login-grid-bg"></div>
      <div className="login-scanner"></div>

      <button onClick={onBack} className="login-back-btn interactive">
        <ArrowLeft size={14} /> [ RETURN_TO_PROTOCOL ]
      </button>

      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        className="login-card"
      >
        <div className="login-logo-container">
          <Shield size={32} />
        </div>

        <div className="login-header">
          <h1>NODE <span className="text-glow">AUTH</span></h1>
          <p>Establish Quantum Handshake</p>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="login-field">
            <label>Agent Identifier</label>
            <div className="login-input-wrapper">
              <Mail className="login-input-icon" size={16} />
              <input
                type="text"
                required
                className="login-input"
                placeholder="john.doe  or  john@nftcipher.com"
                value={formData.email}
                onChange={e => setFormData({ ...formData, email: e.target.value })}
              />
            </div>
          </div>

          <div className="login-field">
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <label>Access Token</label>
              <span style={{ fontSize: '9px', color: 'var(--text3)', fontFamily: 'var(--mono)' }}>CRYPTO_STRENGTH: ULTRA</span>
            </div>
            <div className="login-input-wrapper">
              <Lock className="login-input-icon" size={16} />
              <input
                type={showPass ? 'text' : 'password'}
                required
                className="login-input"
                placeholder="••••••••••••••••"
                value={formData.password}
                onChange={e => setFormData({ ...formData, password: e.target.value })}
              />
              <button
                type="button"
                onClick={() => setShowPass(!showPass)}
                style={{ position: 'absolute', right: '14px', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text3)' }}
              >
                {showPass ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>

          {/* Error message */}
          {error && (
            <div style={{ color: '#ff4444', fontSize: '11px', fontFamily: 'var(--mono)', marginBottom: '1rem', padding: '8px', border: '1px solid #ff444433', borderRadius: '4px' }}>
              ⚠ {error}
            </div>
          )}

          <button type="submit" className="login-submit-btn" disabled={loading}>
            {loading ? 'INITIALIZING PQC_WRAP...' : 'AUTHENTICATE NODE'}
          </button>
        </form>

        <div style={{ marginTop: '1rem', textAlign: 'center', fontSize: '10px', color: 'var(--text3)', fontFamily: 'var(--mono)' }}>
          Default: john.doe / secret
        </div>

        <div style={{ marginTop: '2rem', textAlign: 'center', fontSize: '10px', color: 'var(--text3)', fontFamily: 'var(--mono)' }}>
          SECURE_NODE_V4.2 // PQC_ENABLED
        </div>
      </motion.div>
    </div>
  );
};

export default LoginPage;