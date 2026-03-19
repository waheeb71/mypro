import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Zap, Gauge, Activity, RefreshCw, Settings,
  BarChart3, Clock, Database, Server, Wifi
} from 'lucide-react';
import { qosApi } from '../../services/api';

export default function QoS() {
  const qc = useQueryClient();
  const [tab, setTab] = useState('stats');

  const { data: status } = useQuery({
    queryKey: ['qos_status'],
    queryFn: () => qosApi.status().then(r => r.data),
    refetchInterval: 10000
  });

  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['qos_stats'],
    queryFn: () => qosApi.stats().then(r => r.data),
    refetchInterval: 5000
  });

  const { data: config } = useQuery({
    queryKey: ['qos_config'],
    queryFn: () => qosApi.config().then(r => r.data)
  });

  const updateMutation = useMutation({
    mutationFn: (d) => qosApi.updateConfig(d),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['qos_config'] })
  });

  const cfg = config ?? {};
  const buckets = stats?.buckets ?? [];

  return (
    <div className="module-page">
      <div className="page-header">
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Gauge size={24} style={{ color: 'var(--accent)' }} /> Quality of Service (QoS)
          </h1>
          <p className="page-subtitle">Traffic shaping, rate limiting, and priority queuing (Token Bucket)</p>
        </div>
        <div style={{ display: 'flex', gap: 'var(--sp-3)', alignItems: 'center' }}>
          <span className={`badge ${cfg.enabled ? 'badge-success' : 'badge-info'}`}>
            {cfg.enabled ? '● Shaping Active' : '○ Disabled'}
          </span>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 'var(--sp-4)' }}>
        <div className="card" style={{ padding: 'var(--sp-4)' }}>
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>ACTIVE BUCKETS</div>
          <div style={{ fontSize: '1.5rem', fontWeight: 700 }}>{stats?.active_buckets ?? 0}</div>
        </div>
        <div className="card" style={{ padding: 'var(--sp-4)' }}>
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>DEFAULT RATE</div>
          <div style={{ fontSize: '1.5rem', fontWeight: 700 }}>{((cfg.default_user_rate_bytes || 0) * 8 / 1000000).toFixed(1)} Mbps</div>
        </div>
        <div className="card" style={{ padding: 'var(--sp-4)' }}>
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>BURST CAPACITY</div>
          <div style={{ fontSize: '1.5rem', fontWeight: 700 }}>{((cfg.default_user_burst_bytes || 0) / 1024).toFixed(0)} KB</div>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 'var(--sp-2)', borderBottom: '1px solid var(--border)', paddingBottom: 'var(--sp-2)' }}>
        {['stats', 'config'].map(t => (
          <button key={t} onClick={() => setTab(t)}
            className={`btn ${tab === t ? 'btn-primary' : 'btn-ghost'}`}
            style={{ textTransform: 'capitalize' }}>
            {t}
          </button>
        ))}
      </div>

      {tab === 'stats' && (
        <div className="card" style={{ overflow: 'hidden' }}>
          <div className="section-header">
            <h3>Live Traffic Shaping</h3>
            <span className="badge badge-info"><RefreshCw size={10} className="spin" /> Real-time</span>
          </div>
          <table className="table">
            <thead>
              <tr><th>Source IP</th><th>Tokens Left</th><th>Utilization</th><th>Fill Rate</th></tr>
            </thead>
            <tbody>
              {buckets.map(b => (
                <tr key={b.ip}>
                  <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{b.ip}</td>
                  <td>{b.tokens_remaining.toLocaleString()}</td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <div style={{ flex: 1, height: 6, background: 'var(--bg-overlay)', borderRadius: 3, overflow: 'hidden' }}>
                        <div style={{ width: `${b.utilization_pct}%`, height: '100%', background: b.utilization_pct > 80 ? 'var(--danger)' : 'var(--accent)' }} />
                      </div>
                      <span style={{ fontSize: 'var(--text-xs)', minWidth: 35 }}>{b.utilization_pct}%</span>
                    </div>
                  </td>
                  <td style={{ fontSize: 'var(--text-xs)' }}>{(b.fill_rate_bps / 1000).toFixed(0)} Kbps</td>
                </tr>
              ))}
              {buckets.length === 0 && (
                <tr><td colSpan={4} style={{ textAlign: 'center', padding: 'var(--sp-8)', color: 'var(--text-muted)' }}>No active traffic buckets.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {tab === 'config' && (
        <div className="card" style={{ padding: 'var(--sp-6)' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-5)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ fontWeight: 700 }}>Enable Traffic Shaping</div>
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>Apply token-bucket rate limiting to all internal users</div>
              </div>
              <label className="toggle">
                <input type="checkbox" checked={cfg.enabled} onChange={() => updateMutation.mutate({ ...cfg, enabled: !cfg.enabled })} />
                <span className="toggle-slider" />
              </label>
            </div>

            <div className="form-group">
              <label className="form-label">Default User Rate (Bytes/sec)</label>
              <input className="input" type="number" value={cfg.default_user_rate_bytes} onChange={e => updateMutation.mutate({ ...cfg, default_user_rate_bytes: parseInt(e.target.value) })} />
              <p className="help-text">Current: {((cfg.default_user_rate_bytes * 8) / 1000000).toFixed(2)} Mbps</p>
            </div>

            <div className="form-group">
              <label className="form-label">Default Burst Size (Bytes)</label>
              <input className="input" type="number" value={cfg.default_user_burst_bytes} onChange={e => updateMutation.mutate({ ...cfg, default_user_burst_bytes: parseInt(e.target.value) })} />
              <p className="help-text">Current: {(cfg.default_user_burst_bytes / 1024).toFixed(0)} KB</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
