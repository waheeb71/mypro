import { Network, Construction } from 'lucide-react';
export default function DNS() {
  return (
    <div className="module-page">
      <div className="page-header">
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Network size={24} style={{ color: 'var(--accent)' }} /> DNS Security
          </h1>
          <p className="page-subtitle">DNS Tunneling Detection • Blocklist Management</p>
        </div>
        <span className="badge badge-warning"><Construction size={12} /> In Progress</span>
      </div>
      <div className="card" style={{ padding: 'var(--sp-10)', textAlign: 'center' }}>
        <Network size={48} style={{ color: 'var(--text-muted)', margin: '0 auto var(--sp-4)' }} />
        <div style={{ fontSize: 'var(--text-lg)', fontWeight: 600, color: 'var(--text-primary)' }}>DNS Security</div>
        <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', marginTop: 'var(--sp-2)' }}>
          Domain blocklist, tunneling alerts, and threat intel integration coming soon.
        </div>
      </div>
    </div>
  );
}
