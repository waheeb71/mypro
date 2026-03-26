import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, User, Lock, AlertCircle, LogIn, Eye, EyeOff, Wifi, Globe, Cpu } from 'lucide-react';
import { useAuth } from '../../hooks/useAuth';
import loginVisual from '../../assets/login-visual.png';
import './Login.css';

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();

  const [form, setForm] = useState({ username: '', password: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [showPass, setShowPass] = useState(false);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    const t = setTimeout(() => setMounted(true), 60);
    return () => clearTimeout(t);
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await login(form.username, form.password);
      navigate('/');
    } catch (err) {
      if (err.response?.data?.detail) {
        setError(typeof err.response.data.detail === 'string'
          ? err.response.data.detail
          : JSON.stringify(err.response.data.detail));
      } else {
        setError('Invalid credentials or connection error. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className={`lp-root${mounted ? ' lp-root--in' : ''}`}>

      {/* ══════════════════════ LEFT — FORM PANEL ══════════════════════ */}
      <div className="lp-left">
        {/* ambient blobs */}
        <div className="lp-blob lp-blob-1" />
        <div className="lp-blob lp-blob-2" />
        <div className="lp-grid-overlay" />

        <div className="lp-form-wrapper">

          {/* Header */}
          <div className="lp-brand">
            <div className="lp-shield-wrap">
              <div className="lp-shield-ping" />
              <Shield size={26} color="#fff" />
            </div>
            <div>
              <h1 className="lp-title">CyberNexus Console</h1>
              <p className="lp-subtitle">Enterprise Next-Generation Firewall</p>
            </div>
          </div>

          {/* Divider */}
          <div className="lp-sep">
            <span className="lp-sep-line" />
            <span className="lp-sep-label">SECURE ACCESS</span>
            <span className="lp-sep-line" />
          </div>

          {/* Error */}
          {error && (
            <div className="lp-error">
              <AlertCircle size={15} />
              {error}
            </div>
          )}

          {/* Form */}
          <form className="lp-form" onSubmit={handleSubmit} autoComplete="on">

            <div className="lp-field">
              <label className="lp-label" htmlFor="lp-username">Username</label>
              <div className="lp-input-wrap">
                <User size={14} className="lp-input-icon" />
                <input
                  id="lp-username"
                  className="lp-input"
                  type="text"
                  placeholder="admin"
                  autoComplete="username"
                  value={form.username}
                  onChange={e => setForm(f => ({ ...f, username: e.target.value }))}
                  required
                />
                <div className="lp-input-glow" />
              </div>
            </div>

            <div className="lp-field">
              <label className="lp-label" htmlFor="lp-password">Password</label>
              <div className="lp-input-wrap">
                <Lock size={14} className="lp-input-icon" />
                <input
                  id="lp-password"
                  className="lp-input"
                  type={showPass ? 'text' : 'password'}
                  placeholder="••••••••"
                  autoComplete="current-password"
                  value={form.password}
                  onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
                  required
                />
                <button
                  type="button"
                  className="lp-eye-btn"
                  onClick={() => setShowPass(v => !v)}
                  tabIndex={-1}
                  aria-label="Toggle password visibility"
                >
                  {showPass ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
                <div className="lp-input-glow" />
              </div>
            </div>

            <button
              className={`lp-submit${loading ? ' lp-submit--loading' : ''}`}
              type="submit"
              disabled={loading}
            >
              {loading ? (
                <>
                  <span className="lp-spinner" />
                  Authenticating…
                </>
              ) : (
                <>
                  <LogIn size={16} />
                  Sign In
                </>
              )}
            </button>
          </form>

          {/* Footer */}
          <div className="lp-footer">
            <span className="lp-status-dot" />
            <span className="lp-footer-text">TLS 1.3 Encrypted · Sessions Audited</span>
          </div>
        </div>
      </div>

      {/* ══════════════════════ RIGHT — VISUAL PANEL ══════════════════════ */}
      <div className="lp-right">
        <div className="lp-right-overlay" />
        <img src={loginVisual} alt="CyberNexus Security Visual" className="lp-visual-img" />

        {/* Floating stat cards */}
        <div className="lp-float-card lp-float-top">
          <Wifi size={14} className="lp-float-icon" />
          <div>
            <div className="lp-float-value">99.98%</div>
            <div className="lp-float-label">System Uptime</div>
          </div>
        </div>

        <div className="lp-float-card lp-float-mid">
          <Globe size={14} className="lp-float-icon" />
          <div>
            <div className="lp-float-value">4.2M</div>
            <div className="lp-float-label">Threats Blocked Today</div>
          </div>
        </div>

        <div className="lp-float-card lp-float-bot">
          <Cpu size={14} className="lp-float-icon" />
          <div>
            <div className="lp-float-value">AI-Powered</div>
            <div className="lp-float-label">Threat Intelligence</div>
          </div>
        </div>

        {/* Brand watermark */}
        <div className="lp-watermark">
          <Shield size={18} />
          Enterprise CyberNexus v4
        </div>
      </div>

    </div>
  );
}
