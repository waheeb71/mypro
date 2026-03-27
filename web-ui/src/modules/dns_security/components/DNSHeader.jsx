/**
 * DNSHeader.jsx — Page header with status badge and KPI stat cards.
 */
import { Network, Shield, CheckCircle, ShieldOff, AlertTriangle, Zap } from 'lucide-react';

const CHART_COLORS = ['var(--accent)', 'var(--success)', 'var(--danger)', '#ffb400'];

export default function DNSHeader({ config, stats }) {
  const enginesOn = [
    config.enable_dga_detection,
    config.enable_tunneling_detection,
    config.enable_threat_intel,
    config.enable_rate_limiting,
    config.enable_tld_blocking,
  ].filter(Boolean).length;

  const kpis = [
    { label: 'Total Rules',   value: stats.total_rules,   icon: <Shield size={20} />,        color: 'var(--accent)' },
    { label: 'Active Rules',  value: stats.active_rules,  icon: <CheckCircle size={20} />,   color: 'var(--success)' },
    { label: 'Total Blocked', value: stats.blocked_count, icon: <AlertTriangle size={20} />, color: 'var(--danger)' },
    { label: 'Engines On',    value: `${enginesOn} / 5`,  icon: <Zap size={20} />,           color: '#ffb400' },
  ];

  return (
    <>
      {/* ── Page Header ── */}
      <div style={{
        background: 'linear-gradient(135deg, rgba(59,130,246,0.08) 0%, rgba(15,23,42,0.1) 100%)',
        padding: 'var(--sp-6)', borderRadius: 'var(--radius)',
        borderBottom: '1px solid var(--border)', marginBottom: 'var(--sp-6)',
        display: 'flex', justifyContent: 'space-between', alignItems: 'center'
      }}>
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 12, fontSize: '2rem' }}>
            <Network size={32} style={{ color: 'var(--accent)' }} />
            DNS Security Engine
          </h1>
          <p className="page-subtitle" style={{ marginTop: 8, fontSize: '1.05rem' }}>
            DGA Detection · DNS Tunneling · Threat Intel · Blocklist / Allowlist
          </p>
        </div>
        <span className={`badge ${config.is_active ? 'badge-success' : 'badge-danger'}`}
          style={{ padding: '8px 18px', fontSize: '1rem', display: 'flex', alignItems: 'center', gap: 8 }}>
          {config.is_active ? <CheckCircle size={18} /> : <ShieldOff size={18} />}
          {config.is_active ? 'Active' : 'Disabled'}
        </span>
      </div>

      {/* ── KPI Cards ── */}
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
