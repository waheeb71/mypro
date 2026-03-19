import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Server, Shield, RefreshCw, Settings,
  Globe, Activity, Lock, Database, Search
} from 'lucide-react';
import { proxyApi } from '../../services/api';

export default function Proxy() {
  const qc = useQueryClient();
  const [tab, setTab] = useState('config');

  const { data: status } = useQuery({
    queryKey: ['proxy_status'],
    queryFn: () => proxyApi.status().then(r => r.data)
  });

  const { data: config } = useQuery({
    queryKey: ['proxy_config'],
    queryFn: () => proxyApi.config().then(r => r.data)
  });

  const updateMutation = useMutation({
    mutationFn: (d) => proxyApi.updateConfig(d),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['proxy_config'] })
  });

  const cfg = config ?? {};

  return (
    <div className="module-page">
      <div className="page-header">
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Server size={24} style={{ color: 'var(--accent)' }} /> Forward Proxy
          </h1>
          <p className="page-subtitle">Transparent HTTP/HTTPS proxy and traffic interception engine</p>
        </div>
        <div style={{ display: 'flex', gap: 'var(--sp-3)', alignItems: 'center' }}>
          <span className={`badge ${cfg.is_active ? 'badge-success' : 'badge-info'}`}>
            {cfg.is_active ? '● Running' : '○ Standby'}
          </span>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 'var(--sp-2)', borderBottom: '1px solid var(--border)', paddingBottom: 'var(--sp-2)' }}>
        {['config', 'sessions'].map(t => (
          <button key={t} onClick={() => setTab(t)}
            className={`btn ${tab === t ? 'btn-primary' : 'btn-ghost'}`}
            style={{ textTransform: 'capitalize' }}>
            {t}
          </button>
        ))}
      </div>

      {tab === 'config' && (
        <div className="card" style={{ padding: 'var(--sp-6)' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-5)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ fontWeight: 700 }}>Enable Proxy Engine</div>
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>Start the internal proxy service for client traffic</div>
              </div>
              <label className="toggle">
                <input type="checkbox" checked={cfg.is_active} onChange={() => updateMutation.mutate({ ...cfg, is_active: !cfg.is_active })} />
                <span className="toggle-slider" />
              </label>
            </div>

            <div className="info-grid">
              <div className="info-item">
                <span className="info-item-label">Proxy Mode</span>
                <select className="input" value={cfg.mode} onChange={e => updateMutation.mutate({ ...cfg, mode: e.target.value })}>
                  <option value="transparent_proxy">Transparent Proxy (Auto)</option>
                  <option value="standard_proxy">Standard Forward Proxy</option>
                  <option value="reverse_proxy">Reverse Proxy (Inbound)</option>
                </select>
              </div>
              <div className="info-item">
                <span className="info-item-label">Listen Port</span>
                <input className="input" type="number" value={cfg.listen_port} onChange={e => updateMutation.mutate({ ...cfg, listen_port: parseInt(e.target.value) })} />
              </div>
              <div className="info-item">
                <span className="info-item-label">Max Connections</span>
                <input className="input" type="number" value={cfg.max_connections} onChange={e => updateMutation.mutate({ ...cfg, max_connections: parseInt(e.target.value) })} />
              </div>
              <div className="info-item">
                <span className="info-item-label">Strict Cert Validation</span>
                <label className="toggle">
                  <input type="checkbox" checked={cfg.strict_cert_validation} onChange={() => updateMutation.mutate({ ...cfg, strict_cert_validation: !cfg.strict_cert_validation })} />
                  <span className="toggle-slider" />
                </label>
              </div>
            </div>
          </div>
        </div>
      )}

      {tab === 'sessions' && (
        <div className="card" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 300, color: 'var(--text-muted)' }}>
          <div style={{ textAlign: 'center' }}>
            <Activity size={40} style={{ opacity: 0.2, marginBottom: 12 }} />
            <p>Live session tracking is coming in the next update.</p>
          </div>
        </div>
      )}
    </div>
  );
}
