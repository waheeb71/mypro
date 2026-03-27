/**
 * DNSFilterRules.jsx — CRUD table for domain filter rules with inline edit.
 */
import { useState } from 'react';
import { Plus, Trash2, Edit2, Save, X, ShieldOff, CheckCircle, Search } from 'lucide-react';

const EMPTY_RULE   = { domain_pattern: '', filter_type: 'EXACT', action: 'BLOCK', description: '', enabled: true };
const FILTER_TYPES = ['EXACT', 'WILDCARD', 'REGEX'];
const ACTIONS      = ['BLOCK', 'ALLOW'];

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
    <span className={`badge ${action === 'BLOCK' ? 'badge-danger' : 'badge-success'}`} style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
      {action === 'BLOCK' ? <ShieldOff size={11} /> : <CheckCircle size={11} />}
      {action}
    </span>
  );
}

function TypeBadge({ type }) {
  const colors = { EXACT: 'var(--accent)', WILDCARD: '#ffb400', REGEX: 'var(--success)' };
  return (
    <span className="tag" style={{ background: `${colors[type] || 'var(--accent)'}22`, color: colors[type], fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>
      {type}
    </span>
  );
}

export default function DNSFilterRules({ rules, createRule, updateRule, deleteRule }) {
  const [newRule, setNewRule] = useState(EMPTY_RULE);
  const [editId,  setEditId]  = useState(null);
  const [editBuf, setEditBuf] = useState({});
  const [search,  setSearch]  = useState('');

  const handleAdd = () => {
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

  const filtered = rules.filter(r =>
    r.domain_pattern.toLowerCase().includes(search.toLowerCase()) ||
    (r.description || '').toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
      {/* ── Add Rule Card ── */}
      <div className="card" style={{ padding: 'var(--sp-5)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 'var(--sp-4)', fontWeight: 700, fontSize: '1.05rem' }}>
          <Plus size={16} style={{ color: 'var(--accent)' }} /> Add Filter Rule
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr 2fr auto', gap: 'var(--sp-3)', alignItems: 'center' }}>
          <input
            className="input"
            placeholder="Domain pattern (e.g. *.tk, ^bad.*\.io$, evil.com)"
            value={newRule.domain_pattern}
            onChange={e => setNewRule(p => ({ ...p, domain_pattern: e.target.value }))}
            onKeyDown={e => e.key === 'Enter' && handleAdd()}
          />
          <select className="input" value={newRule.filter_type} onChange={e => setNewRule(p => ({ ...p, filter_type: e.target.value }))}>
            {FILTER_TYPES.map(t => <option key={t}>{t}</option>)}
          </select>
          <select className="input" value={newRule.action} onChange={e => setNewRule(p => ({ ...p, action: e.target.value }))}>
            {ACTIONS.map(a => <option key={a}>{a}</option>)}
          </select>
          <input className="input" placeholder="Description (optional)" value={newRule.description} onChange={e => setNewRule(p => ({ ...p, description: e.target.value }))} />
          <button className="btn btn-primary" onClick={handleAdd} disabled={createRule.isPending} style={{ display: 'flex', alignItems: 'center', gap: 6, whiteSpace: 'nowrap' }}>
            <Plus size={15} /> Add Rule
          </button>
        </div>
      </div>

      {/* ── Rules Table ── */}
      <div className="card" style={{ overflow: 'hidden' }}>
        <div style={{ padding: 'var(--sp-4) var(--sp-5)', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
            Domain Filter Rules <span className="tag">{rules.length} total</span>
          </span>
          <div style={{ position: 'relative', width: 220 }}>
            <Search size={14} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
            <input className="input" style={{ paddingLeft: 32, fontSize: '0.85rem' }} placeholder="Search rules..." value={search} onChange={e => setSearch(e.target.value)} />
          </div>
        </div>
        <div style={{ overflowX: 'auto', maxHeight: 520, overflowY: 'auto' }}>
          <table className="table" style={{ width: '100%' }}>
            <thead style={{ position: 'sticky', top: 0, background: 'var(--bg-raised)', zIndex: 1 }}>
              <tr>
                <th style={{ padding: '12px 16px' }}>Domain Pattern</th>
                <th style={{ padding: '12px 16px' }}>Type</th>
                <th style={{ padding: '12px 16px' }}>Action</th>
                <th style={{ padding: '12px 16px' }}>Hits</th>
                <th style={{ padding: '12px 16px' }}>Last Triggered</th>
                <th style={{ padding: '12px 16px' }}>Enabled</th>
                <th style={{ padding: '12px 16px', textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 && (
                <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 'var(--sp-6)' }}>No rules found.</td></tr>
              )}
              {filtered.map(rule => (
                <tr key={rule.id} style={{ borderTop: '1px solid var(--border)' }}>
                  {editId === rule.id ? (
                    <>
                      <td style={{ padding: '10px 16px' }}>
                        <input className="input" style={{ fontSize: '0.85rem', padding: '4px 8px' }}
                          value={editBuf.domain_pattern} onChange={e => setEditBuf(p => ({ ...p, domain_pattern: e.target.value }))} />
                      </td>
                      <td style={{ padding: '10px 16px' }}>
                        <select className="input" style={{ fontSize: '0.85rem', padding: '4px 8px' }}
                          value={editBuf.filter_type} onChange={e => setEditBuf(p => ({ ...p, filter_type: e.target.value }))}>
                          {FILTER_TYPES.map(t => <option key={t}>{t}</option>)}
                        </select>
                      </td>
                      <td style={{ padding: '10px 16px' }}>
                        <select className="input" style={{ fontSize: '0.85rem', padding: '4px 8px' }}
                          value={editBuf.action} onChange={e => setEditBuf(p => ({ ...p, action: e.target.value }))}>
                          {ACTIONS.map(a => <option key={a}>{a}</option>)}
                        </select>
                      </td>
                      <td style={{ padding: '10px 16px' }}>{rule.blocked_count ?? 0}</td>
                      <td style={{ padding: '10px 16px', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                        {rule.last_triggered ? new Date(rule.last_triggered).toLocaleString() : '—'}
                      </td>
                      <td style={{ padding: '10px 16px' }}>
                        <Toggle checked={editBuf.enabled} onChange={() => setEditBuf(p => ({ ...p, enabled: !p.enabled }))} />
                      </td>
                      <td style={{ padding: '10px 16px', textAlign: 'right' }}>
                        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                          <button className="icon-btn" style={{ color: 'var(--success)' }} onClick={saveEdit} disabled={updateRule.isPending} title="Save"><Save size={15} /></button>
                          <button className="icon-btn" style={{ color: 'var(--text-muted)' }} onClick={() => setEditId(null)} title="Cancel"><X size={15} /></button>
                        </div>
                      </td>
                    </>
                  ) : (
                    <>
                      <td style={{ padding: '12px 16px', fontFamily: 'var(--font-mono)', fontSize: '0.88rem', fontWeight: 600 }}>{rule.domain_pattern}</td>
                      <td style={{ padding: '12px 16px' }}><TypeBadge type={rule.filter_type} /></td>
                      <td style={{ padding: '12px 16px' }}><ActionBadge action={rule.action} /></td>
                      <td style={{ padding: '12px 16px', fontWeight: 700, color: rule.blocked_count > 0 ? 'var(--danger)' : 'var(--text-muted)' }}>
                        {rule.blocked_count ?? 0}
                      </td>
                      <td style={{ padding: '12px 16px', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                        {rule.last_triggered ? new Date(rule.last_triggered).toLocaleString() : '—'}
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <Toggle checked={rule.enabled} onChange={() => updateRule.mutate({ id: rule.id, d: { enabled: !rule.enabled } })} />
                      </td>
                      <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                          <button className="icon-btn" style={{ color: 'var(--accent)' }} onClick={() => startEdit(rule)} title="Edit"><Edit2 size={15} /></button>
                          <button className="icon-btn danger" onClick={() => deleteRule.mutate(rule.id)} disabled={deleteRule.isPending} title="Delete"><Trash2 size={15} /></button>
                        </div>
                      </td>
                    </>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
