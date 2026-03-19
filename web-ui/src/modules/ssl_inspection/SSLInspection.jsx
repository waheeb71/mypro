import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Lock, Shield, Eye, Database, RefreshCw, Plus, Trash2,
  AlertTriangle, CheckCircle, FileText, Key, Globe
} from 'lucide-react';
import { sslApi } from '../../services/api';

export default function SSLInspection() {
  const qc = useQueryClient();
  const [tab, setTab] = useState('policies');
  const [showNewPolicy, setShowNewPolicy] = useState(false);

  const { data: policies, isLoading: policiesLoading } = useQuery({
    queryKey: ['ssl_policies'],
    queryFn: () => sslApi.policies().then(r => r.data)
  });

  const { data: certs } = useQuery({
    queryKey: ['ssl_certs'],
    queryFn: () => sslApi.certificates().then(r => r.data)
  });

  const deleteMutation = useMutation({
    mutationFn: (id) => sslApi.deletePolicy(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ssl_policies'] })
  });

  return (
    <div className="module-page">
      <div className="page-header">
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Lock size={24} style={{ color: 'var(--accent)' }} /> SSL Inspection
          </h1>
          <p className="page-subtitle">HTTPS decryption, certificate validation, and CA management</p>
        </div>
        <div style={{ display: 'flex', gap: 'var(--sp-3)' }}>
          <button className="btn btn-primary" onClick={() => setShowNewPolicy(true)}><Plus size={16} /> New Policy</button>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 'var(--sp-2)', borderBottom: '1px solid var(--border)', paddingBottom: 'var(--sp-2)' }}>
        {['policies', 'certificates', 'settings'].map(t => (
          <button key={t} onClick={() => setTab(t)}
            className={`btn ${tab === t ? 'btn-primary' : 'btn-ghost'}`}
            style={{ textTransform: 'capitalize' }}>
            {t}
          </button>
        ))}
      </div>

      {tab === 'policies' && (
        <div className="card" style={{ overflow: 'hidden' }}>
          <table className="table">
            <thead>
              <tr><th>Name</th><th>Action</th><th>Target Domains</th><th>Log</th><th>Status</th><th></th></tr>
            </thead>
            <tbody>
              {policies?.map(p => (
                <tr key={p.id}>
                  <td style={{ fontWeight: 600 }}>{p.name}</td>
                  <td>
                    <span className={`tag ${p.action === 'DECRYPT' ? 'tag-danger' : 'tag-info'}`}>{p.action}</span>
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>{p.target_domains}</td>
                  <td>{p.log_traffic ? 'Yes' : 'No'}</td>
                  <td>
                    <span className={`badge ${p.enabled ? 'badge-success' : 'badge-info'}`}>{p.enabled ? 'Active' : 'Disabled'}</span>
                  </td>
                  <td>
                    <button className="icon-btn danger" onClick={() => deleteMutation.mutate(p.id)}><Trash2 size={13} /></button>
                  </td>
                </tr>
              ))}
              {!policies?.length && !policiesLoading && (
                <tr><td colSpan={6} style={{ textAlign: 'center', padding: 'var(--sp-8)', color: 'var(--text-muted)' }}>No SSL policies defined.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {tab === 'certificates' && (
        <div className="card">
          <div className="section-header">
            <h3>CA & Server Certificates</h3>
            <button className="btn btn-ghost btn-xs"><Plus size={12} /> Upload</button>
          </div>
          <table className="table">
            <thead>
              <tr><th>Name</th><th>Type</th><th>Expiry</th><th>Status</th></tr>
            </thead>
            <tbody>
              {certs?.map(c => (
                <tr key={c.id}>
                  <td style={{ fontWeight: 600 }}>{c.name}</td>
                  <td><span className="tag">{c.type}</span></td>
                  <td style={{ fontSize: 'var(--text-xs)' }}>{c.expiry ? new Date(c.expiry).toLocaleDateString() : 'N/A'}</td>
                  <td>
                    <span className={`badge ${c.is_active ? 'badge-success' : 'badge-info'}`}>{c.is_active ? 'Active' : 'Inactive'}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
