import React from 'react';
import { motion } from 'framer-motion';
import { ArrowLeft, MessageSquare, Shield, Zap, Terminal } from 'lucide-react';
import './ContactView.css';

const ContactView = ({ onBack }) => {
  return (
    <div className="contact-view premium-theme">
      <motion.div 
        initial={{ opacity: 0, scale: 0.95 }} 
        animate={{ opacity: 1, scale: 1 }}
        className="contact-card"
      >
        <button className="back-btn-docs" onClick={onBack} style={{ position: 'absolute', top: '-4rem', left: '0' }}>
          <ArrowLeft size={14} /> Close Terminal
        </button>

        <header className="contact-header">
          <Terminal size={40} style={{ color: 'var(--primary)', marginBottom: '1rem', filter: 'drop-shadow(0 0 10px var(--primary-glow))' }} />
          <h1>Secure Channel</h1>
          <p style={{ color: 'var(--text3)', fontFamily: 'var(--mono)', fontSize: '11px' }}>[ ENCRYPTED_CONNECTION_ESTABLISHED ]</p>
        </header>

        <form className="contact-form" onSubmit={(e) => e.preventDefault()}>
          <div className="form-group">
            <label>Sender_Identity</label>
            <input type="text" className="form-input" placeholder="User-14204" />
          </div>
          <div className="form-group">
            <label>Callback_Vector</label>
            <input type="email" className="form-input" placeholder="identity@protocol.secure" />
          </div>
          <div className="form-group">
            <label>Transmission_Payload</label>
            <textarea className="form-input" rows="4" placeholder="Enter classified message..."></textarea>
          </div>
          
          <button type="submit" className="contact-submit">
            INITIATE TRANSMISSION
          </button>
        </form>

        <footer style={{ marginTop: '2rem', textAlign: 'center', color: 'var(--text3)', fontSize: '10px', fontFamily: 'var(--mono)' }}>
          XCIPHER_SECURE_RELAY_v4.2 // SHA-256 Verified
        </footer>
      </motion.div>
    </div>
  );
};

export default ContactView;
