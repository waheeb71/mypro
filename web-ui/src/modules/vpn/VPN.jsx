// Generic stub for modules not yet fully developed
import { Lock, Construction } from 'lucide-react';

export default function VPN() {
  return (
    <div className="module-page">
      <div className="page-header">
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Lock size={24} style={{ color: 'var(--accent)' }} /> VPN
          </h1>
          <p className="page-subtitle">WireGuard / IPSec Tunnel Management</p>
        </div>
        <span className="badge badge-warning"><Construction size={12} /> In Progress</span>
      </div>
      <div className="card" style={{ padding: 'var(--sp-10)', textAlign: 'center' }}>
        <Construction size={48} style={{ color: 'var(--text-muted)', margin: '0 auto var(--sp-4)' }} />
        <div style={{ fontSize: 'var(--text-lg)', fontWeight: 600, color: 'var(--text-primary)' }}>VPN Module</div>
        <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', marginTop: 'var(--sp-2)' }}>
          Peer management, tunnel status and key rotation UI coming soon.
        </div>
      </div>
    </div>
  );
}
