import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Globe, Search, Code, Shield, RefreshCw, Plus, Trash2,
  AlertTriangle, CheckCircle, FileText, Settings, Activity
} from 'lucide-react';
import { httpApi } from '../../services/api';

export default function HTTPInspection() {
  const qc = useQueryClient();
  const [tab, setTab] = useState('patterns');
  const [newPattern, setNewPattern] = useState({ target: 'url', pattern: '', severity: 'MEDIUM', description: '' });

  const { data: patterns, isLoading: patternsLoading } = useQuery({
    queryKey: ['http_patterns'],
    queryFn: () => httpApi.patterns().then(r => r.data)
  });

  const { data: config } = useQuery({
    queryKey: ['http_config'],
    queryFn: () => httpApi.config().then(r => r.data)
  });

  const updateConfigMutation = useMutation({
    mutationFn: (d) => httpApi.updateConfig(d),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['http_config'] })
  });

  const addPatternMutation = useMutation({
    mutationFn: (d) => httpApi.addPattern(d),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['http_patterns'] });
      setNewPattern({ target: 'url', pattern: '', severity: 'MEDIUM', description: '' });
    }
  });

  const deletePatternMutation = useMutation({
    mutationFn: (id) => httpApi.deletePattern(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['http_patterns'] })
  });

  const cfg = config ?? {};

  return (
    <div className="module-page">
      <div className="page-header">
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Globe size={24} style={{ color: 'var(--accent)' }} /> HTTP Inspection
          </h1>
          <p className="page-subtitle">Deep HTTP payload analysis, header sanitization, and regex pattern matching</p>
        </div>
        <div style={{ display: 'flex', gap: 'var(--sp-3)' }}>
          <span className={`badge ${cfg.is_active ? 'badge-success' : 'badge-info'}`}>{cfg.is_active ? '● Active' : '○ Disabled'}</span>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 'var(--sp-2)', borderBottom: '1px solid var(--border)', paddingBottom: 'var(--sp-2)' }}>
        {['patterns', 'config'].map(t => (
          <button key={t} onClick={() => setTab(t)}
            className={`btn ${tab === t ? 'btn-primary' : 'btn-ghost'}`}
            style={{ textTransform: 'capitalize' }}>
            {t}
          </button>
        ))}
      </div>

      {tab === 'patterns' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
          <div className="card" style={{ padding: 'var(--sp-4)' }}>
            <h3 style={{ fontSize: 'var(--text-sm)', fontWeight: 700, marginBottom: 'var(--sp-4)' }}>Create New Pattern</h3>
            <div style={{ display: 'grid', gridTemplateColumns: '150px 1fr 150px 100px', gap: 'var(--sp-3)' }}>
              <select className="input" value={newPattern.target} onChange={e => setNewPattern({ ...newPattern, target: e.target.value })}>
                <option value="url">URL Path</option>
                <option value="header">HTTP Header</option>
                <option value="body">Request Body</option>
              </select>
              <input className="input" placeholder="Regex pattern (e.g. \.\./\.\./)" value={newPattern.pattern} onChange={e => setNewPattern({ ...newPattern, pattern: e.target.value })} />
              <select className="input" value={newPattern.severity} onChange={e => setNewPattern({ ...newPattern, severity: e.target.value })}>
                <option value="HIGH">High Severity</option>
                <option value="MEDIUM">Medium Severity</option>
                <option value="LOW">Low Severity</option>
              </select>
              <button className="btn btn-primary" onClick={() => addPatternMutation.mutate(newPattern)}>Add</button>
            </div>
          </div>

          <div className="card" style={{ overflow: 'hidden' }}>
            <table className="table">
              <thead>
                <tr><th>Target</th><th>Pattern</th><th>Severity</th><th>Status</th><th></th></tr>
              </thead>
              <tbody>
                {patterns?.map(p => (
                  <tr key={p.id}>
                    <td><span className="tag">{p.target}</span></td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)', color: 'var(--accent)' }}>{p.pattern}</td>
                    <td><span className={`badge ${p.severity === 'HIGH' ? 'badge-danger' : 'badge-warning'}`}>{p.severity}</span></td>
                    <td>{p.enabled ? 'Active' : 'Disabled'}</td>
                    <td>
                      <button className="icon-btn danger" onClick={() => deletePatternMutation.mutate(p.id)}><Trash2 size={13} /></button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === 'config' && (
        <div className="card" style={{ padding: 'var(--sp-6)' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-5)' }}>
            {[
              { id: 'is_active', label: 'HTTP Inspection Master Switch', desc: 'Enable global deep packet inspection for HTTP traffic' },
              { id: 'block_dangerous_methods', label: 'Block Dangerous Methods', desc: 'Auto-block PUT, DELETE, TRACE, and non-RFC methods' },
              { id: 'scan_headers', label: 'Scan Headers', desc: 'Inspect HTTP request and response headers for anomalies' },
              { id: 'scan_body', label: 'Scan Body', desc: 'Inspect request body/POST data for pattern matching' },
            ].map(f => (
              <div key={f.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div style={{ fontWeight: 700 }}>{f.label}</div>
                  <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{f.desc}</div>
                </div>
                <label className="toggle">
                  <input type="checkbox" checked={cfg[f.id]} onChange={() => updateConfigMutation.mutate({ ...cfg, [f.id]: !cfg[f.id] })} />
                  <span className="toggle-slider" />
                </label>
              </div>
            ))}
            <div className="form-group">
              <label className="form-label">Max Scan Size (MB)</label>
              <input className="input" type="number" value={cfg.max_upload_size_mb || 100} onChange={e => updateConfigMutation.mutate({ ...cfg, max_upload_size_mb: parseInt(e.target.value) })} />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
