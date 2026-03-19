import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Mail, Shield, AlertTriangle, CheckCircle, RefreshCw, Plus, Trash2, X } from 'lucide-react';
import { emailApi } from '../../services/api';

function StatCard({ icon, label, value, color = 'var(--accent)' }) {
  return (
    <div className="card" style={{ padding: 'var(--sp-4)', display: 'flex', alignItems: 'center', gap: 'var(--sp-3)' }}>
      <div style={{ width: 40, height: 40, borderRadius: '50%', background: 'var(--bg-overlay)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        {icon}
      </div>
      <div>
        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{label}</div>
        <div style={{ fontSize: '1.4rem', fontWeight: 700, color }}>{value ?? '—'}</div>
      </div>
    </div>
  );
}

const MODE_COLORS = { enforce: 'var(--danger)', monitor: 'var(--warning)', learning: 'var(--accent)' };

export default function EmailSecurity() {
  const qc = useQueryClient();
  const [tab, setTab] = useState('overview');
  const [newEntry, setNewEntry] = useState({ type: 'email', value: '' });

  const { data: status, isLoading: statusLoading } = useQuery({ queryKey: ['email_status'], queryFn: () => emailApi.status().then(r => r.data), refetchInterval: 20000 });
  const { data: config } = useQuery({ queryKey: ['email_config'], queryFn: () => emailApi.config().then(r => r.data) });
  const { data: whitelist } = useQuery({ queryKey: ['email_whitelist'], queryFn: () => emailApi.whitelist().then(r => r.data) });

  const updateMutation = useMutation({
    mutationFn: emailApi.updateConfig,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['email_config'] }),
  });

  const addWhitelistMutation = useMutation({
    mutationFn: emailApi.addWhitelist,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['email_whitelist'] }); setNewEntry({ type: 'email', value: '' }); },
  });

  const removeWhitelistMutation = useMutation({
    mutationFn: ({ type, value }) => emailApi.removeWhitelist(type, value),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['email_whitelist'] }),
  });

  const plugin = status?.plugin ?? {};
  const mode = plugin.mode ?? config?.mode ?? 'monitor';
  const TABS = ['overview', 'config', 'whitelist'];

  return (
    <div className="module-page">
      <div className="page-header">
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Mail size={24} style={{ color: 'var(--accent)' }} /> Email Security
          </h1>
          <p className="page-subtitle">Phishing detection, spam filtering, attachment scanning, and sender reputation</p>
        </div>
        <div style={{ display: 'flex', gap: 'var(--sp-3)', alignItems: 'center' }}>
          <span className="badge" style={{ background: 'var(--bg-overlay)', color: MODE_COLORS[mode] ?? 'var(--accent)', border: `1px solid ${MODE_COLORS[mode] ?? 'var(--accent)'}`, textTransform: 'capitalize' }}>
            ● {mode}
          </span>
          <span className={`badge ${plugin.enabled !== false ? 'badge-success' : 'badge-danger'}`}>
            {plugin.enabled !== false ? 'Active' : 'Disabled'}
          </span>
        </div>
      </div>

      {/* Stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 'var(--sp-4)' }}>
        <StatCard icon={<Mail size={18} style={{ color: 'var(--accent)' }} />} label="INSPECTED" value={plugin.inspected?.toLocaleString()} />
        <StatCard icon={<AlertTriangle size={18} style={{ color: 'var(--danger)' }} />} label="DETECTED" value={plugin.detected?.toLocaleString()} color="var(--danger)" />
        <StatCard icon={<Shield size={18} style={{ color: 'var(--warning)' }} />} label="BLOCKED" value={plugin.blocked?.toLocaleString()} color="var(--warning)" />
        <StatCard icon={<CheckCircle size={18} style={{ color: 'var(--success)' }} />} label="STATUS" value={status?.status ?? 'Unknown'} color="var(--success)" />
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 'var(--sp-2)', borderBottom: '1px solid var(--border)', paddingBottom: 'var(--sp-2)' }}>
        {TABS.map(t => (
          <button key={t} onClick={() => setTab(t)}
            className={`btn ${tab === t ? 'btn-primary' : 'btn-ghost'}`}
            style={{ textTransform: 'capitalize', fontSize: 'var(--text-sm)' }}>
            {t}
          </button>
        ))}
      </div>

      {/* Overview Tab */}
      {tab === 'overview' && (
        <div className="card" style={{ padding: 'var(--sp-5)' }}>
          <h3 style={{ marginBottom: 'var(--sp-4)', fontWeight: 700, fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>Enabled Scanners</h3>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 'var(--sp-3)' }}>
            {[
              { name: 'Phishing Detector', icon: '🎣', desc: 'ML-based phishing link detection' },
              { name: 'Spam Filter', icon: '📧', desc: 'NLP spam classification' },
              { name: 'Attachment Guard', icon: '📎', desc: 'File type & sandbox analysis' },
              { name: 'URL Scanner', icon: '🔗', desc: 'Reputation-based URL checking' },
              { name: 'Sender Reputation', icon: '👤', desc: 'SPF, DKIM, DMARC validation' },
              { name: 'SMTP Guard', icon: '🔒', desc: 'Protocol anomaly detection' },
            ].map(s => (
              <div key={s.name} style={{ padding: 'var(--sp-3)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', background: 'var(--bg-raised)' }}>
                <div style={{ fontSize: '1.4rem', marginBottom: 4 }}>{s.icon}</div>
                <div style={{ fontWeight: 600, fontSize: 'var(--text-sm)' }}>{s.name}</div>
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 4 }}>{s.desc}</div>
                <span className="badge badge-success" style={{ marginTop: 8 }}>Active</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Config Tab */}
      {tab === 'config' && config && (
        <div className="card" style={{ padding: 'var(--sp-5)' }}>
          <h3 style={{ marginBottom: 'var(--sp-4)', fontWeight: 700, fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>Email Security Configuration</h3>
          <div className="info-grid">
            <div className="info-item"><span className="info-item-label">Mode</span>
              <select className="input" defaultValue={mode}
                onChange={e => updateMutation.mutate({ mode: e.target.value })}>
                <option value="enforce">Enforce (Block threats)</option>
                <option value="monitor">Monitor (Log only)</option>
                <option value="learning">Learning (Build baseline)</option>
              </select>
            </div>
            <div className="info-item"><span className="info-item-label">Monitored Ports</span>
              <span className="info-item-value">{config.monitored_ports?.join(', ') ?? '25, 587, 465, 143, 993'}</span>
            </div>
            <div className="info-item"><span className="info-item-label">Spam Threshold</span>
              <span className="info-item-value">{config.thresholds?.spam_score ?? '0.7'}</span>
            </div>
            <div className="info-item"><span className="info-item-label">Phishing Threshold</span>
              <span className="info-item-value">{config.thresholds?.phishing_score ?? '0.8'}</span>
            </div>
          </div>
        </div>
      )}

      {/* Whitelist Tab */}
      {tab === 'whitelist' && (
        <div className="card" style={{ overflow: 'hidden' }}>
          <div className="section-header">
            <h3>Whitelist</h3>
            <span className="tag">{(whitelist?.emails?.length ?? 0) + (whitelist?.domains?.length ?? 0) + (whitelist?.ips?.length ?? 0)} entries</span>
          </div>

          {/* Add Entry */}
          <div style={{ display: 'flex', gap: 'var(--sp-3)', padding: 'var(--sp-4)', borderBottom: '1px solid var(--border)' }}>
            <select className="input" style={{ width: 130 }} value={newEntry.type} onChange={e => setNewEntry(p => ({ ...p, type: e.target.value }))}>
              <option value="email">Email</option>
              <option value="domain">Domain</option>
              <option value="ip">IP</option>
            </select>
            <input className="input" style={{ flex: 1 }} placeholder={`Enter ${newEntry.type}…`} value={newEntry.value}
              onChange={e => setNewEntry(p => ({ ...p, value: e.target.value }))} />
            <button className="btn btn-primary"
              disabled={!newEntry.value.trim() || addWhitelistMutation.isPending}
              onClick={() => addWhitelistMutation.mutate({ type: newEntry.type, value: newEntry.value.trim() })}>
              <Plus size={14} /> Add
            </button>
          </div>

          <table className="table">
            <thead><tr><th>Type</th><th>Value</th><th></th></tr></thead>
            <tbody>
              {['email', 'domain', 'ip'].flatMap(type =>
                (whitelist?.[type + 's'] ?? []).map(val => (
                  <tr key={`${type}-${val}`}>
                    <td><span className="tag">{type}</span></td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>{val}</td>
                    <td>
                      <button className="icon-btn danger" onClick={() => removeWhitelistMutation.mutate({ type, value: val })}>
                        <Trash2 size={13} />
                      </button>
                    </td>
                  </tr>
                ))
              )}
              {!whitelist?.emails?.length && !whitelist?.domains?.length && !whitelist?.ips?.length && (
                <tr><td colSpan={3} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 'var(--sp-6)' }}>Whitelist is empty</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
