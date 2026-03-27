/**
 * EmailHeader.jsx — Header and Status KPI Cards
 */
import { Mail, CheckCircle, ShieldOff, AlertTriangle, Shield, Search } from 'lucide-react';

const MODE_COLORS = { enforce: 'var(--danger)', monitor: 'var(--warning)', learning: 'var(--accent)' };

export default function EmailHeader({ status, stats, config }) {
  const plugin = status?.plugin ?? {};
  const isEnabled = config.enabled !== false;
  const mode = config.mode || 'monitor';

  const kpis = [
    { label: 'Inspected Today', value: stats.today_total?.toLocaleString() ?? 0, icon: <Search size={20} />, color: 'var(--accent)' },
    { label: 'Phishing Detected', value: stats.phishing_detected?.toLocaleString() ?? 0, icon: <AlertTriangle size={20} />, color: 'var(--warning)' },
    { label: 'Spam Detected', value: stats.spam_detected?.toLocaleString() ?? 0, icon: <Mail size={20} />, color: '#ffb400' },
    { label: 'Blocked Today', value: stats.today_blocked?.toLocaleString() ?? 0, icon: <Shield size={20} />, color: 'var(--danger)' },
  ];

  return (
    <>
      <div style={{
        background: 'linear-gradient(135deg, rgba(59,130,246,0.08) 0%, rgba(15,23,42,0.1) 100%)',
        padding: 'var(--sp-6)', borderRadius: 'var(--radius)',
        borderBottom: '1px solid var(--border)', marginBottom: 'var(--sp-6)',
        display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start'
      }}>
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 12, fontSize: '2rem' }}>
            <Mail size={32} style={{ color: 'var(--accent)' }} /> Email Security
          </h1>
          <p className="page-subtitle" style={{ marginTop: 8, fontSize: '1.05rem', maxWidth: 600 }}>
            AI-powered 7-layer pipeline detecting Phishing, Spam, Malicious URLs, and Attachment threats across SMTP, IMAP, and POP3.
          </p>
        </div>
        <div style={{ display: 'flex', gap: 'var(--sp-3)', alignItems: 'center' }}>
          <span className="badge" style={{ padding: '8px 18px', fontSize: '0.9rem', background: 'var(--bg-overlay)', color: MODE_COLORS[mode], border: `1px solid ${MODE_COLORS[mode]}`, textTransform: 'capitalize' }}>
            ● {mode}
          </span>
          <span className={`badge ${isEnabled ? 'badge-success' : 'badge-danger'}`} style={{ padding: '8px 18px', fontSize: '0.9rem', display: 'flex', alignItems: 'center', gap: 8 }}>
            {isEnabled ? <CheckCircle size={16} /> : <ShieldOff size={16} />}
            {isEnabled ? 'Active' : 'Disabled'}
          </span>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 'var(--sp-4)', marginBottom: 'var(--sp-6)' }}>
        {kpis.map(({ label, value, icon, color }) => (
          <div key={label} className="card hover-lift" style={{ padding: 'var(--sp-5)', display: 'flex', alignItems: 'center', gap: 'var(--sp-4)' }}>
            <div style={{ padding: 12, borderRadius: '50%', background: `${color}22`, flexShrink: 0 }}>
              <span style={{ color, display: 'flex' }}>{icon}</span>
            </div>
            <div>
              <div style={{ fontSize: '1.6rem', fontWeight: 800, lineHeight: 1 }}>{value}</div>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: 4 }}>{label}</div>
            </div>
          </div>
        ))}
      </div>

      <style>{`
        .hover-lift { transition: transform 0.2s, box-shadow 0.2s; }
        .hover-lift:hover { transform: translateY(-2px); box-shadow: 0 6px 16px rgba(0,0,0,0.12); }
      `}</style>
    </>
  );
}
