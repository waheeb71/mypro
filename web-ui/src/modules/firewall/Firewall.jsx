import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Shield, Plus, Trash2, Edit2, Search, Filter, CheckCircle, XCircle
} from 'lucide-react';
import { firewallApi } from '../../services/api';
import './Firewall.css';

const DEMO_RULES = [
  { id: 1, name: 'Allow-HTTP-Out',  action: 'ALLOW', protocol: 'tcp', source_ip: 'any', destination_ip: 'any', destination_port: '80',   priority: 10,  enabled: true },
  { id: 2, name: 'Allow-HTTPS-Out', action: 'ALLOW', protocol: 'tcp', source_ip: 'any', destination_ip: 'any', destination_port: '443',  priority: 20,  enabled: true },
  { id: 3, name: 'Block-TOR-Exit',  action: 'DROP',  protocol: 'any', source_ip: 'any', destination_ip: 'any', destination_port: '9001', priority: 50,  enabled: true },
  { id: 4, name: 'Allow-DNS',       action: 'ALLOW', protocol: 'udp', source_ip: 'any', destination_ip: 'any', destination_port: '53',   priority: 15,  enabled: true },
  { id: 5, name: 'Drop-SMB',        action: 'DROP',  protocol: 'tcp', source_ip: 'any', destination_ip: 'any', destination_port: '445',  priority: 100, enabled: false },
  { id: 6, name: 'Allow-SSH-Admin', action: 'ALLOW', protocol: 'tcp', source_ip: '10.0.0.0/8', destination_ip: 'any', destination_port: '22', priority: 30, enabled: true },
];

function ActionBadge({ action }) {
  const cls = action === 'ALLOW' ? 'badge-success' : action === 'DROP' ? 'badge-danger' : 'badge-warning';
  return <span className={`badge ${cls}`}>{action}</span>;
}

export default function Firewall() {
  const qc = useQueryClient();
  const [search, setSearch] = useState('');

  const { data: rules = DEMO_RULES, isLoading } = useQuery({
    queryKey: ['firewall-rules'],
    queryFn: () => firewallApi.rules().then(r => r.data),
    retry: false,
    placeholderData: DEMO_RULES,
  });

  const deleteMutation = useMutation({
    mutationFn: (id) => firewallApi.deleteRule(id),
    onSuccess: () => qc.invalidateQueries(['firewall-rules']),
  });

  const filtered = rules.filter(r =>
    r.name.toLowerCase().includes(search.toLowerCase()) ||
    r.destination_port?.toString().includes(search)
  );

  return (
    <div className="module-page">
      <div className="page-header">
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Shield size={24} style={{ color: 'var(--accent)' }} />
            Firewall Rules
          </h1>
          <p className="page-subtitle">Manage network access control policies</p>
        </div>
        <div style={{ display: 'flex', gap: 'var(--sp-3)' }}>
          <button className="btn btn-ghost">
            <Filter size={15} /> Filter
          </button>
          <button className="btn btn-primary">
            <Plus size={15} /> Add Rule
          </button>
        </div>
      </div>

      {/* Search */}
      <div className="card" style={{ padding: 'var(--sp-4)', display: 'flex', alignItems: 'center', gap: 'var(--sp-3)' }}>
        <Search size={16} style={{ color: 'var(--text-muted)' }} />
        <input
          className="input"
          style={{ border: 'none', background: 'transparent', padding: 0 }}
          placeholder="Search rules by name or port…"
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
        <span className="tag">{filtered.length} rules</span>
      </div>

      {/* Rules Table */}
      <div className="card" style={{ overflow: 'hidden' }}>
        <table className="table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Action</th>
              <th>Protocol</th>
              <th>Source</th>
              <th>Destination</th>
              <th>Port</th>
              <th>Priority</th>
              <th>Status</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(rule => (
              <tr key={rule.id}>
                <td>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--accent)' }}>
                    {rule.name}
                  </span>
                </td>
                <td><ActionBadge action={rule.action} /></td>
                <td><span className="tag">{rule.protocol.toUpperCase()}</span></td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>{rule.source_ip}</td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>{rule.destination_ip}</td>
                <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{rule.destination_port}</td>
                <td style={{ color: 'var(--text-muted)' }}>{rule.priority}</td>
                <td>
                  {rule.enabled
                    ? <span className="badge badge-success"><CheckCircle size={11} /> Active</span>
                    : <span className="badge badge-info"><XCircle size={11} /> Disabled</span>
                  }
                </td>
                <td>
                  <div style={{ display: 'flex', gap: 'var(--sp-2)' }}>
                    <button className="icon-btn" title="Edit">
                      <Edit2 size={14} />
                    </button>
                    <button
                      className="icon-btn danger"
                      title="Delete"
                      onClick={() => deleteMutation.mutate(rule.id)}
                    >
                      <Trash2 size={14} />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
