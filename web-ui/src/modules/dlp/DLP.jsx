import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ShieldOff, Search, Eye, Shield, RefreshCw, Plus, Trash2,
  AlertTriangle, CheckCircle, FileText, Lock, Database
} from 'lucide-react';
import { dlpApi } from '../../services/api';

export default function DLP() {
  const qc = useQueryClient();
  const [tab, setTab] = useState('rules');
  const [newRule, setNewRule] = useState({ name: '', pattern: '', severity: 'MEDIUM', description: '' });

  const { data: rules, isLoading: rulesLoading } = useQuery({
    queryKey: ['dlp_rules'],
    queryFn: () => dlpApi.rules().then(r => r.data)
  });

  const { data: config } = useQuery({
    queryKey: ['dlp_config'],
    queryFn: () => dlpApi.config().then(r => r.data)
  });

  const updateConfigMutation = useMutation({
    mutationFn: (d) => dlpApi.updateConfig(d),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['dlp_config'] })
  });

  const addRuleMutation = useMutation({
    mutationFn: (d) => dlpApi.createRule(d),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['dlp_rules'] });
      setNewRule({ name: '', pattern: '', severity: 'MEDIUM', description: '' });
    }
  });

  const deleteRuleMutation = useMutation({
    mutationFn: (id) => dlpApi.deleteRule(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['dlp_rules'] })
  });

  const cfg = config ?? {};

  return (
    <div className="module-page">
      <div className="page-header">
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <FileText size={24} style={{ color: 'var(--danger)' }} /> Data Loss Prevention (DLP)
          </h1>
          <p className="page-subtitle">Inspect sensitive data (PII, SSN, CC) from leaving the internal network</p>
        </div>
        <div style={{ display: 'flex', gap: 'var(--sp-3)' }}>
          <span className={`badge ${cfg.is_active ? 'badge-success' : 'badge-info'}`}>{cfg.is_active ? '● Active' : '○ Disabled'}</span>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 'var(--sp-2)', borderBottom: '1px solid var(--border)', paddingBottom: 'var(--sp-2)' }}>
        {['rules', 'config', 'logs'].map(t => (
          <button key={t} onClick={() => setTab(t)}
            className={`btn ${tab === t ? 'btn-primary' : 'btn-ghost'}`}
            style={{ textTransform: 'capitalize' }}>
            {t}
          </button>
        ))}
      </div>

      {tab === 'rules' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
          <div className="card" style={{ padding: 'var(--sp-4)' }}>
            <h3 style={{ fontSize: 'var(--text-sm)', fontWeight: 700, marginBottom: 'var(--sp-4)' }}>Create New Data Pattern</h3>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr 150px 100px', gap: 'var(--sp-3)' }}>
              <input className="input" placeholder="Rule Name (e.g. CC-Numbers)" value={newRule.name} onChange={e => setNewRule({ ...newRule, name: e.target.value })} />
              <input className="input" placeholder="Regex Pattern (e.g. \b\d{4}-\d{4}-\d{4}-\d{4}\b)" value={newRule.pattern} onChange={e => setNewRule({ ...newRule, pattern: e.target.value })} />
              <select className="input" value={newRule.severity} onChange={e => setNewRule({ ...newRule, severity: e.target.value })}>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
              <button className="btn btn-primary" onClick={() => addRuleMutation.mutate(newRule)}>Add</button>
            </div>
          </div>

          <div className="card" style={{ overflow: 'hidden' }}>
            <table className="table">
              <thead>
                <tr><th>Rule Name</th><th>Pattern</th><th>Severity</th><th>Status</th><th></th></tr>
              </thead>
              <tbody>
                {rules?.map(r => (
                  <tr key={r.id}>
                    <td style={{ fontWeight: 600 }}>{r.name}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)' }}>{r.pattern}</td>
                    <td><span className={`badge ${r.severity === 'CRITICAL' ? 'badge-danger' : (r.severity === 'HIGH' ? 'badge-warning' : 'badge-info')}`}>{r.severity}</span></td>
                    <td>{r.enabled ? 'Active' : 'Disabled'}</td>
                    <td>
                      <button className="icon-btn danger" onClick={() => deleteRuleMutation.mutate(r.id)}><Trash2 size={13} /></button>
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
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ fontWeight: 700 }}>Enable DLP Monitoring</div>
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>Scan all outbound traffic for restricted data patterns</div>
              </div>
              <label className="toggle">
                <input type="checkbox" checked={cfg.is_active} onChange={() => updateConfigMutation.mutate({ ...cfg, is_active: !cfg.is_active })} />
                <span className="toggle-slider" />
              </label>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ fontWeight: 700 }}>Auto-Block Outbound Leaks</div>
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>Immediately drop packets matching CRITICAL/HIGH DLP rules</div>
              </div>
              <label className="toggle">
                <input type="checkbox" checked={cfg.block_on_match} onChange={() => updateConfigMutation.mutate({ ...cfg, block_on_match: !cfg.block_on_match })} />
                <span className="toggle-slider" />
              </label>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
