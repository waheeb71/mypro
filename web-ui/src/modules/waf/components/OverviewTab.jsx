import { Zap, Server } from 'lucide-react';
import LiveMonitor from './LiveMonitor';

export default function OverviewTab({ status }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--sp-5)' }}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-5)' }}>
         <div className="card" style={{ padding: 'var(--sp-5)' }}>
            <div className="section-title" style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 'var(--sp-4)' }}>
               <Zap size={18} style={{ color: 'var(--accent)' }} /> System Modules
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--sp-4)' }}>
               <div className="info-item">
                 <span className="info-item-label">Deployment Mode</span>
                 <span className="info-item-value">{status?.mode?.toUpperCase() || 'ENFORCE'}</span>
               </div>
               <div className="info-item">
                 <span className="info-item-label">NLP Deep Learning</span>
                 <span className="info-item-value" style={{ color: status?.features?.nlp ? 'var(--success)' : 'var(--text-muted)' }}>
                    {status?.features?.nlp ? 'Online' : 'Offline'}
                 </span>
               </div>
               <div className="info-item">
                 <span className="info-item-label">Behavioral Bot Det.</span>
                 <span className="info-item-value" style={{ color: status?.features?.bot_detection ? 'var(--success)' : 'var(--text-muted)' }}>
                    {status?.features?.bot_detection ? 'Online' : 'Offline'}
                 </span>
               </div>
               <div className="info-item">
                 <span className="info-item-label">Graph Neural Network</span>
                 <span className="info-item-value" style={{ color: status?.features?.gnn ? 'var(--success)' : 'var(--text-muted)' }}>
                    {status?.features?.gnn ? 'Online' : 'Offline'}
                 </span>
               </div>
            </div>
         </div>
         
         <div className="card" style={{ padding: 'var(--sp-5)' }}>
            <div className="section-title" style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 'var(--sp-3)' }}>
               <Server size={18} style={{ color: 'var(--accent)' }} /> Protected Ports
            </div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
               {status?.monitored_ports?.map(p => (
                  <span key={p} className="badge badge-info" style={{ fontSize: 13, padding: '4px 10px' }}>Port {p}</span>
               )) || <span className="badge badge-info">80, 443</span>}
            </div>
         </div>
      </div>
      <LiveMonitor />
    </div>
  );
}
