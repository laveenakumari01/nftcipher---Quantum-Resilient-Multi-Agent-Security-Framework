import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, ArrowLeft, Mail, Lock, Eye, EyeOff, User } from 'lucide-react';
import { auth, createUserWithEmailAndPassword, signInWithEmailAndPassword, sendEmailVerification } from '../../firebase.js';
import { loginUser } from '../../api.js';
import './LoginPage.css';

const LoginPage = ({ onBack, onLogin }) => {
  const [showPass, setShowPass]   = useState(false);
  const [mode, setMode]           = useState('login');
  const [formData, setFormData]   = useState({ email: '', password: '', fullName: '' });
  const [loading, setLoading]     = useState(false);
  const [error, setError]         = useState('');
  const [message, setMessage]     = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setMessage('');
    try {
      const userCredential = await signInWithEmailAndPassword(auth, formData.email, formData.password);
      const user = userCredential.user;

      if (!user.emailVerified) {
        setLoading(false);
        setError('Email not verified. Please verify your email before logging in.');
        return;
      }

      const data = await loginUser(formData.email, formData.password);
      setLoading(false);
      onLogin(data.access_token, data.username, data.role);

    } catch (err) {
      setLoading(false);
      if (err.code === 'auth/user-not-found' || err.code === 'auth/wrong-password' || err.code === 'auth/invalid-credential') {
        setError('Incorrect email or password.');
      } else if (err.code === 'auth/too-many-requests') {
        setError('Too many attempts. Please try again later.');
      } else {
        setError(err.message || 'Login failed.');
      }
    }
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setMessage('');
    try {
      const userCredential = await createUserWithEmailAndPassword(auth, formData.email, formData.password);
      const user = userCredential.user;

      await sendEmailVerification(user);

      setLoading(false);
      setMessage(`✅ Verification email sent to: ${formData.email} — Please verify your email then login.`);
      setMode('login');

    } catch (err) {
      setLoading(false);
      if (err.code === 'auth/email-already-in-use') {
        setError('This email is already registered. Please login.');
      } else if (err.code === 'auth/weak-password') {
        setError('Password must be at least 6 characters.');
      } else if (err.code === 'auth/invalid-email') {
        setError('Please enter a valid email address.');
      } else {
        setError(err.message || 'Registration failed.');
      }
    }
  };

  const resendVerification = async () => {
    try {
      const userCredential = await signInWithEmailAndPassword(auth, formData.email, formData.password);
      await sendEmailVerification(userCredential.user);
      setMessage('✅ Verification email sent again!');
      setError('');
    } catch (err) {
      setError('Failed to send email. Please try again.');
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
          <p>{mode === 'login' ? 'Establish Quantum Handshake' : 'Register New Node'}</p>
        </div>

        {/* Toggle */}
        <div style={{ display: 'flex', marginBottom: '2rem', border: '1px solid var(--border)', padding: '4px', gap: '4px' }}>
          <button type="button" onClick={() => { setMode('login'); setError(''); setMessage(''); }}
            style={{ flex: 1, padding: '8px', background: mode === 'login' ? 'var(--primary)' : 'transparent', color: mode === 'login' ? '#fff' : 'var(--text3)', border: 'none', cursor: 'pointer', fontFamily: 'var(--mono)', fontSize: '10px', letterSpacing: '0.1em', transition: 'all 0.3s' }}>
            LOGIN
          </button>
          <button type="button" onClick={() => { setMode('register'); setError(''); setMessage(''); }}
            style={{ flex: 1, padding: '8px', background: mode === 'register' ? 'var(--primary)' : 'transparent', color: mode === 'register' ? '#fff' : 'var(--text3)', border: 'none', cursor: 'pointer', fontFamily: 'var(--mono)', fontSize: '10px', letterSpacing: '0.1em', transition: 'all 0.3s' }}>
            REGISTER
          </button>
        </div>

        {/* Error */}
        {error && (
          <div style={{ color: '#ff4444', fontSize: '11px', fontFamily: 'var(--mono)', marginBottom: '1rem', padding: '8px', border: '1px solid #ff444433', borderRadius: '4px' }}>
            ⚠ {error}
            {error.includes('verify your email') && (
              <button onClick={resendVerification} style={{ display: 'block', marginTop: '8px', background: 'none', border: '1px solid #ff4444', color: '#ff4444', padding: '4px 8px', cursor: 'pointer', fontFamily: 'var(--mono)', fontSize: '10px' }}>
                RESEND VERIFICATION EMAIL
              </button>
            )}
          </div>
        )}

        {/* Success Message */}
        {message && (
          <div style={{ color: 'var(--accent)', fontSize: '11px', fontFamily: 'var(--mono)', marginBottom: '1rem', padding: '8px', border: '1px solid var(--accent)', borderRadius: '4px' }}>
            {message}
          </div>
        )}

        <AnimatePresence mode="wait">
          {mode === 'login' ? (
            <motion.form key="login" initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 10 }} onSubmit={handleSubmit}>
              <div className="login-field">
                <label>Email Address</label>
                <div className="login-input-wrapper">
                  <Mail className="login-input-icon" size={16} />
                  <input type="email" required className="login-input" placeholder="your@email.com"
                    value={formData.email} onChange={e => setFormData({ ...formData, email: e.target.value })} />
                </div>
              </div>
              <div className="login-field">
                <label>Password</label>
                <div className="login-input-wrapper">
                  <Lock className="login-input-icon" size={16} />
                  <input type={showPass ? 'text' : 'password'} required className="login-input" placeholder="••••••••••••••••"
                    value={formData.password} onChange={e => setFormData({ ...formData, password: e.target.value })} />
                  <button type="button" onClick={() => setShowPass(!showPass)}
                    style={{ position: 'absolute', right: '14px', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text3)' }}>
                    {showPass ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>
              <button type="submit" className="login-submit-btn" disabled={loading}>
                {loading ? 'AUTHENTICATING...' : 'AUTHENTICATE NODE'}
              </button>
            </motion.form>
          ) : (
            <motion.form key="register" initial={{ opacity: 0, x: 10 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -10 }} onSubmit={handleRegister}>
              <div className="login-field">
                <label>Full Name (optional)</label>
                <div className="login-input-wrapper">
                  <User className="login-input-icon" size={16} />
                  <input type="text" className="login-input" placeholder="Your Name"
                    value={formData.fullName} onChange={e => setFormData({ ...formData, fullName: e.target.value })} />
                </div>
              </div>
              <div className="login-field">
                <label>Email Address</label>
                <div className="login-input-wrapper">
                  <Mail className="login-input-icon" size={16} />
                  <input type="email" required className="login-input" placeholder="your@email.com"
                    value={formData.email} onChange={e => setFormData({ ...formData, email: e.target.value })} />
                </div>
              </div>
              <div className="login-field">
                <label>Password (min 6 characters)</label>
                <div className="login-input-wrapper">
                  <Lock className="login-input-icon" size={16} />
                  <input type={showPass ? 'text' : 'password'} required className="login-input" placeholder="••••••••••••••••"
                    value={formData.password} onChange={e => setFormData({ ...formData, password: e.target.value })} />
                  <button type="button" onClick={() => setShowPass(!showPass)}
                    style={{ position: 'absolute', right: '14px', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text3)' }}>
                    {showPass ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>
              <button type="submit" className="login-submit-btn" disabled={loading}>
                {loading ? 'REGISTERING...' : 'REGISTER NODE'}
              </button>
            </motion.form>
          )}
        </AnimatePresence>

        <div style={{ marginTop: '2rem', textAlign: 'center', fontSize: '10px', color: 'var(--text3)', fontFamily: 'var(--mono)' }}>
          SECURE_NODE_V4.2 // PQC_ENABLED // FIREBASE_AUTH
        </div>
      </motion.div>
    </div>
  );
};

export default LoginPage;