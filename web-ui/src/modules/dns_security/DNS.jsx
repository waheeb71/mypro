import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Network, Shield, ShieldOff, Settings, Plus, Trash2,
  AlertTriangle, CheckCircle, BarChart2, Zap, Edit2, X, Save,
} from 'lucide-react';
import { dnsApi } from '../../services/api';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from 'recharts';

// ─────────────────────────────────────────────────────────────────────────────
// Constants / helpers
// ─────────────────────────────────────────────────────────────────────────────
const EMPTY_RULE = { domain_pattern: '', filter_type: 'EXACT', action: 'BLOCK', description: '', enabled: true };

const FILTER_TYPES = ['EXACT', 'WILDCARD', 'REGEX'];
const ACTIONS      = ['BLOCK', 'ALLOW'];

const DEFAULT_CFG = {
  is_active: true,
  enable_dga_detection:       true,
  enable_tunneling_detection: true,
  enable_threat_intel:        true,
  enable_rate_limiting:       true,
  enable_tld_blocking:        true,
  dga_entropy_threshold:      3.8,
  tunneling_query_threshold:  50,
  rate_limit_per_minute:      100,
  suspicious_tlds:            '.tk,.ml,.ga,.cf,.gq,.xyz,.top,.win,.bid,.onion',
};

const DEFAULT_STATS = { total_rules: 0, active_rules: 0, blocked_count: 0, top_blocked: [] };

function Toggle({ checked, onChange }) {
  return (
    <label className="toggle">
      <input type="checkbox" checked={!!checked} onChange={onChange} />
      <span className="toggle-slider" />
    </label>
  );
}

function ActionBadge({ action }) {
  return (
    <span className={`badge ${action === 'BLOCK' ? 'badge-danger' : 'badge-success'}`}>
      {action === 'BLOCK' ? <ShieldOff size={10} /> : <CheckCircle size={10} />}
      {' '}{action}
    </span>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main component
// ─────────────────────────────────────────────────────────────────────────────
export default function DNS() {
  const [tab,     setTab]     = useState('rules');
  const [newRule, setNewRule] = useState(EMPTY_RULE);
  const [editId,  setEditId]  = useState(null);
  const [editBuf, setEditBuf] = useState({});
  const qc = useQueryClient();

  // ── Queries ────────────────────────────────────────────────────────────────
  const { data: cfg = DEFAULT_CFG } = useQuery({
    queryKey: ['dns-config'],
    queryFn: () => dnsApi.getConfig().then(r => r.data),
    retry: false,
    placeholderData: DEFAULT_CFG,
  });

  const { data: stats = DEFAULT_STATS } = useQuery({
    queryKey: ['dns-stats'],
    queryFn: () => dnsApi.stats().then(r => r.data),
    retry: false,
    placeholderData: DEFAULT_STATS,
    refetchInterval: 15000,
  });

  const { data: rules = [] } = useQuery({
    queryKey: ['dns-rules'],
    queryFn: () => dnsApi.rules().then(r => r.data),
    retry: false,
    placeholderData: [],
  });

  // ── Mutations ──────────────────────────────────────────────────────────────
  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['dns-config'] });
    qc.invalidateQueries({ queryKey: ['dns-stats']  });
    qc.invalidateQueries({ queryKey: ['dns-rules']  });
  };

  const updateCfg   = useMutation({ mutationFn: d => dnsApi.updateConfig(d), onSuccess: invalidate });
  const createRule  = useMutation({ mutationFn: d => dnsApi.createRule(d),   onSuccess: invalidate });
  const updateRule  = useMutation({ mutationFn: ({ id, d }) => dnsApi.updateRule(id, d), onSuccess: invalidate });
  const deleteRule  = useMutation({ mutationFn: id => dnsApi.deleteRule(id), onSuccess: invalidate });

  const config = cfg ?? DEFAULT_CFG;

  // ── Helpers ────────────────────────────────────────────────────────────────
  const handleAddRule = () => {
    if (!newRule.domain_pattern.trim()) return;
    createRule.mutate(newRule, { onSuccess: () => setNewRule(EMPTY_RULE) });
  };

  const startEdit = (rule) => {
    setEditId(rule.id);
    setEditBuf({ domain_pattern: rule.domain_pattern, filter_type: rule.filter_type, action: rule.action, description: rule.description, enabled: rule.enabled });
  };

  const saveEdit = () => {
    updateRule.mutate({ id: editId, d: editBuf }, { onSuccess: () => setEditId(null) });
  };

  // Chart colours
  const CHART_COLORS = ['#ff4d6a', '#ff8c42', '#ffb400', '#4fc3f7', '#81c995', '#cf6cc9', '#4dd0e1', '#aed581', '#f06292', '#ffcc02'];

  const barData = (stats.top_blocked || []).slice(0, 8).map(r => ({
    name: r.domain_pattern.length > 18 ? r.domain_pattern.slice(0, 16) + '…' : r.domain_pattern,
    count: r.blocked_count,
    action: r.action,
  }));

  // ── Render ─────────────────────────────────────────────────────────────────
  return (
    <div className="module-page">

      {/* ── Header ── */}
      <div className="page-header">
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Network size={24} style={{ color: 'var(--accent)' }} />
            DNS Security
          </h1>
          <p className="page-subtitle">
            DGA Detection · DNS Tunneling · Threat Intel · Blocklist / Allowlist
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-3)' }}>
          <span className={`badge ${config.is_active ? 'badge-success' : 'badge-danger'}`}>
            {config.is_active ? <CheckCircle size={11} /> : <ShieldOff size={11} />}
            {' '}{config.is_active ? 'Active' : 'Disabled'}
          </span>
        </div>
      </div>

      {/* ── KPI Cards ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 'var(--sp-4)', marginBottom: 'var(--sp-5)' }}>
        {[
          { label: 'Total Rules',   value: stats.total_rules,   icon: <Shield size={18} />,       color: 'var(--accent)' },
          { label: 'Active Rules',  value: stats.active_rules,  icon: <CheckCircle size={18} />,  color: 'var(--success)' },
          { label: 'Total Blocked', value: stats.blocked_count, icon: <AlertTriangle size={18} />, color: 'var(--danger)' },
          { label: 'Engines On',    value: [config.enable_dga_detection, config.enable_tunneling_detection, config.enable_threat_intel, config.enable_rate_limiting, config.enable_tld_blocking].filter(Boolean).length + ' / 5', icon: <Zap size={18} />, color: '#ffb400' },
        ].map(({ label, value, icon, color }) => (
          <div key={label} className="card" style={{ padding: 'var(--sp-5)', display: 'flex', alignItems: 'center', gap: 'var(--sp-4)' }}>
            <div style={{ padding: 10, borderRadius: '50%', background: `${color}22` }}>
              <span style={{ color }}>{icon}</span>
            </div>
            <div>
              <div style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--text-primary)' }}>{value}</div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* ── Tabs ── */}
      <div style={{ display: 'flex', gap: 'var(--sp-2)', borderBottom: '1px solid var(--border)', marginBottom: 'var(--sp-5)', paddingBottom: 'var(--sp-2)' }}>
        {[
          { key: 'rules',    label: 'Filter Rules',  icon: <Shield size={14} /> },
          { key: 'stats',    label: 'Statistics',    icon: <BarChart2 size={14} /> },
          { key: 'settings', label: 'Settings',      icon: <Settings size={14} /> },
        ].map(({ key, label, icon }) => (
          <button key={key} onClick={() => setTab(key)}
            className={`btn ${tab === key ? 'btn-primary' : 'btn-ghost'}`}
            style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            {icon}{label}
          </button>
        ))}
      </div>

      {/* ══════════════════════════════════ TAB: RULES ══════════════════════════════════ */}
      {tab === 'rules' && (
        <>
          {/* Add Rule */}
          <div className="card" style={{ padding: 'var(--sp-5)', marginBottom: 'var(--sp-4)' }}>
            <div className="section-title" style={{ marginBottom: 'var(--sp-4)', display: 'flex', alignItems: 'center', gap: 8 }}>
              <Plus size={15} style={{ color: 'var(--accent)' }} /> Add Filter Rule
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr 2fr auto', gap: 'var(--sp-3)', alignItems: 'center' }}>
              <input
                className="input"
                placeholder="Domain pattern (e.g. *.tk, ^bad.*\.io$, evil.com)"
                value={newRule.domain_pattern}
                onChange={e => setNewRule(p => ({ ...p, domain_pattern: e.target.value }))}
                onKeyDown={e => e.key === 'Enter' && handleAddRule()}
              />
              <select className="input" value={newRule.filter_type}
                onChange={e => setNewRule(p => ({ ...p, filter_type: e.target.value }))}>
                {FILTER_TYPES.map(t => <option key={t}>{t}</option>)}
              </select>
              <select className="input" value={newRule.action}
                onChange={e => setNewRule(p => ({ ...p, action: e.target.value }))}>
                {ACTIONS.map(a => <option key={a}>{a}</option>)}
              </select>
              <input
                className="input"
                placeholder="Description (optional)"
                value={newRule.description}
                onChange={e => setNewRule(p => ({ ...p, description: e.target.value }))}
              />
              <button className="btn btn-primary" onClick={handleAddRule}
                disabled={createRule.isPending} style={{ display: 'flex', alignItems: 'center', gap: 6, whiteSpace: 'nowrap' }}>
                <Plus size={14} /> Add Rule
              </button>
            </div>
          </div>

          {/* Rules Table */}
          <div className="card" style={{ overflow: 'hidden' }}>
            <div className="section-header">
              <div className="section-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Shield size={16} style={{ color: 'var(--accent)' }} /> Domain Filter Rules
              </div>
              <span className="tag">{rules.length} rules</span>
            </div>
            <table className="table">
              <thead>
                <tr>
                  <th>Domain Pattern</th>
                  <th>Type</th>
                  <th>Action</th>
                  <th>Hits</th>
                  <th>Last Hit</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {rules.length === 0 && (
                  <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 'var(--sp-6)' }}>No rules yet. Add one above.</td></tr>
                )}
                {rules.map(rule => (
                  <tr key={rule.id}>
                    {editId === rule.id ? (
                      <>
                        <td>
                          <input className="input" style={{ fontSize: 'var(--text-xs)', padding: '4px 8px' }}
                            value={editBuf.domain_pattern}
                            onChange={e => setEditBuf(p => ({ ...p, domain_pattern: e.target.value }))} />
                        </td>
                        <td>
                          <select className="input" style={{ fontSize: 'var(--text-xs)', padding: '4px 8px' }}
                            value={editBuf.filter_type}
                            onChange={e => setEditBuf(p => ({ ...p, filter_type: e.target.value }))}>
                            {FILTER_TYPES.map(t => <option key={t}>{t}</option>)}
                          </select>
                        </td>
                        <td>
                          <select className="input" style={{ fontSize: 'var(--text-xs)', padding: '4px 8px' }}
                            value={editBuf.action}
                            onChange={e => setEditBuf(p => ({ ...p, action: e.target.value }))}>
                            {ACTIONS.map(a => <option key={a}>{a}</option>)}
                          </select>
                        </td>
                        <td>{rule.blocked_count ?? 0}</td>
                        <td style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                          {rule.last_triggered ? new Date(rule.last_triggered).toLocaleString() : '—'}
                        </td>
                        <td><Toggle checked={editBuf.enabled} onChange={() => setEditBuf(p => ({ ...p, enabled: !p.enabled }))} /></td>
                        <td>
                          <div style={{ display: 'flex', gap: 6 }}>
                            <button className="icon-btn" title="Save" onClick={saveEdit} disabled={updateRule.isPending} style={{ color: 'var(--success)' }}><Save size={14} /></button>
                            <button className="icon-btn" title="Cancel" onClick={() => setEditId(null)} style={{ color: 'var(--text-muted)' }}><X size={14} /></button>
                          </div>
                        </td>
                      </>
                    ) : (
                      <>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-primary)', fontWeight: 600 }}>
                          {rule.domain_pattern}
                        </td>
                        <td><span className="tag">{rule.filter_type}</span></td>
                        <td><ActionBadge action={rule.action} /></td>
                        <td style={{ fontWeight: 600, color: rule.blocked_count > 0 ? 'var(--danger)' : 'var(--text-muted)' }}>
                          {rule.blocked_count ?? 0}
                        </td>
                        <td style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                          {rule.last_triggered ? new Date(rule.last_triggered).toLocaleString() : '—'}
                        </td>
                        <td><Toggle checked={rule.enabled} onChange={() => updateRule.mutate({ id: rule.id, d: { enabled: !rule.enabled } })} /></td>
                        <td>
                          <div style={{ display: 'flex', gap: 6 }}>
                            <button className="icon-btn" title="Edit" onClick={() => startEdit(rule)} style={{ color: 'var(--accent)' }}><Edit2 size={14} /></button>
                            <button className="icon-btn" title="Delete" onClick={() => deleteRule.mutate(rule.id)} disabled={deleteRule.isPending} style={{ color: 'var(--danger)' }}><Trash2 size={14} /></button>
                          </div>
                        </td>
                      </>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {/* ══════════════════════════════════ TAB: STATS ══════════════════════════════════ */}
      {tab === 'stats' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-5)' }}>

          {/* Top Blocked Chart */}
          <div className="card" style={{ padding: 'var(--sp-5)' }}>
            <div className="section-title" style={{ marginBottom: 'var(--sp-4)', display: 'flex', alignItems: 'center', gap: 8 }}>
              <BarChart2 size={16} style={{ color: 'var(--accent)' }} /> Top Blocked Domains
            </div>
            {barData.length === 0 ? (
              <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 'var(--sp-8)' }}>No block events recorded yet.</div>
            ) : (
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={barData} layout="vertical">
                  <XAxis type="number" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <YAxis type="category" dataKey="name" width={140} tick={{ fill: 'var(--text-primary)', fontSize: 11, fontFamily: 'var(--font-mono)' }} axisLine={false} tickLine={false} />
                  <Tooltip
                    contentStyle={{ background: 'var(--bg-raised)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }}
                    itemStyle={{ color: 'var(--danger)' }}
                    labelStyle={{ color: 'var(--text-secondary)' }}
                  />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                    {barData.map((_, i) => (
                      <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>

          {/* Top blocked table detail */}
          <div className="card" style={{ overflow: 'hidden' }}>
            <div className="section-header">
              <div className="section-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <AlertTriangle size={15} style={{ color: 'var(--danger)' }} /> Top Hit Rules
              </div>
            </div>
            <table className="table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Domain Pattern</th>
                  <th>Action</th>
                  <th>Blocked Count</th>
                  <th>Last Triggered</th>
                </tr>
              </thead>
              <tbody>
                {(stats.top_blocked || []).map((r, i) => (
                  <tr key={i}>
                    <td style={{ color: 'var(--text-muted)' }}>{i + 1}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', fontWeight: 600 }}>{r.domain_pattern}</td>
                    <td><ActionBadge action={r.action} /></td>
                    <td style={{ fontWeight: 700, color: 'var(--danger)' }}>{r.blocked_count}</td>
                    <td style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                      {r.last_triggered ? new Date(r.last_triggered).toLocaleString() : '—'}
                    </td>
                  </tr>
                ))}
                {(stats.top_blocked || []).length === 0 && (
                  <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 'var(--sp-6)' }}>No data yet.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ══════════════════════════════════ TAB: SETTINGS ══════════════════════════════════ */}
      {tab === 'settings' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>

          {/* Module Status */}
          <div className="card" style={{ padding: 'var(--sp-6)' }}>
            <h3 style={{ marginBottom: 'var(--sp-5)', fontWeight: 700 }}>Module Status</h3>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ fontWeight: 700 }}>DNS Security Engine</div>
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>Enable or disable the entire DNS inspection pipeline</div>
              </div>
              <Toggle checked={config.is_active} onChange={() => updateCfg.mutate({ ...config, is_active: !config.is_active })} />
            </div>
          </div>

          {/* Engine Toggles */}
          <div className="card" style={{ padding: 'var(--sp-6)' }}>
            <h3 style={{ marginBottom: 'var(--sp-5)', fontWeight: 700 }}>Detection Engines</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-5)' }}>
              {[
                { key: 'enable_dga_detection',       label: 'DGA Detection',       desc: 'Detect Domain Generation Algorithm domains using Shannon entropy analysis' },
                { key: 'enable_tunneling_detection', label: 'DNS Tunneling',        desc: 'Block DNS tunneling tools (iodine, dnscat2) via length and query-type heuristics' },
                { key: 'enable_threat_intel',        label: 'Threat Intelligence', desc: 'Match domains against embedded and external IOC feeds' },
                { key: 'enable_rate_limiting',       label: 'Rate Limiting',        desc: 'Flag source IPs exceeding the configured query-per-minute threshold' },
                { key: 'enable_tld_blocking',        label: 'Suspicious TLD Block', desc: 'Block queries to high-risk TLDs (.tk, .ml, .onion, etc.)' },
              ].map(({ key, label, desc }) => (
                <div key={key} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <div style={{ fontWeight: 700 }}>{label}</div>
                    <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{desc}</div>
                  </div>
                  <Toggle checked={config[key]} onChange={() => updateCfg.mutate({ ...config, [key]: !config[key] })} />
                </div>
              ))}
            </div>
          </div>

          {/* Numeric Parameters */}
          <div className="card" style={{ padding: 'var(--sp-6)' }}>
            <h3 style={{ marginBottom: 'var(--sp-5)', fontWeight: 700 }}>Engine Parameters</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-5)' }}>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div style={{ fontWeight: 700 }}>DGA Entropy Threshold</div>
                  <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>Shannon entropy score above which a domain is flagged as DGA (default: 3.8)</div>
                </div>
                <input className="input" type="number" style={{ width: 100 }} step={0.1} min={2} max={5}
                  value={config.dga_entropy_threshold}
                  onBlur={e => updateCfg.mutate({ ...config, dga_entropy_threshold: parseFloat(e.target.value) })}
                  onChange={e => {}} defaultValue={config.dga_entropy_threshold} key={config.dga_entropy_threshold} />
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div style={{ fontWeight: 700 }}>Tunneling Query Threshold</div>
                  <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>Max repeated queries to the same domain/IP before flagging tunneling</div>
                </div>
                <input className="input" type="number" style={{ width: 100 }} step={5} min={10} max={500}
                  defaultValue={config.tunneling_query_threshold} key={config.tunneling_query_threshold}
                  onBlur={e => updateCfg.mutate({ ...config, tunneling_query_threshold: parseInt(e.target.value) })}
                  onChange={e => {}} />
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div style={{ fontWeight: 700 }}>Rate Limit (queries / min)</div>
                  <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>Maximum DNS queries per minute per source IP before alerting</div>
                </div>
                <input className="input" type="number" style={{ width: 100 }} step={10} min={10} max={1000}
                  defaultValue={config.rate_limit_per_minute} key={config.rate_limit_per_minute}
                  onBlur={e => updateCfg.mutate({ ...config, rate_limit_per_minute: parseInt(e.target.value) })}
                  onChange={e => {}} />
              </div>

              {/* Suspicious TLDs */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-2)' }}>
                <div>
                  <div style={{ fontWeight: 700 }}>Suspicious TLDs</div>
                  <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 'var(--sp-2)' }}>Comma-separated list of TLDs to block (e.g. .tk,.onion,.xyz)</div>
                </div>
                <input className="input" style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}
                  defaultValue={config.suspicious_tlds} key={config.suspicious_tlds}
                  onBlur={e => updateCfg.mutate({ ...config, suspicious_tlds: e.target.value })}
                  onChange={e => {}} />
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
