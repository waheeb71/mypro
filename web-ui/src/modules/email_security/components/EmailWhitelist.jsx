/**
 * EmailWhitelist.jsx — CRUD table for allowlisted emails, domains, and IPs.
 */
import { useState } from 'react';
import { Plus, Trash2, CheckCircle } from 'lucide-react';

export default function EmailWhitelist({ whitelist, addToWhitelist, removeFromWhitelist }) {
  const [newEntry, setNewEntry] = useState({ type: 'email', value: '' });

  const handleAdd = () => {
    if (!newEntry.value.trim()) return;
    addToWhitelist.mutate({ type: newEntry.type, value: newEntry.value.trim() }, { onSuccess: () => setNewEntry(p => ({ ...p, value: '' })) });
  };

  const types = ['email', 'domain', 'ip'];

  return (
    <div className="card" style={{ overflow: 'hidden' }}>
      <div style={{ padding: 'var(--sp-4) var(--sp-5)', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h3 style={{ display: 'flex', alignItems: 'center', gap: 8, fontWeight: 700 }}>
          <CheckCircle size={18} style={{ color: 'var(--success)' }} /> Trusted Whitelist
        </h3>
        <span className="tag">
          {types.reduce((sum, t) => sum + (whitelist[t + 's']?.length || 0), 0)} entries
        </span>
      </div>

      {/* ── Add Entry ── */}
      <div style={{ display: 'flex', gap: 'var(--sp-3)', padding: 'var(--sp-4)', borderBottom: '1px solid var(--border)', background: 'var(--bg-raised)' }}>
        <select className="input" style={{ width: 130 }} value={newEntry.type} onChange={e => setNewEntry(p => ({ ...p, type: e.target.value }))}>
          {types.map(t => <option key={t} value={t}>{t.charAt(0).toUpperCase() + t.slice(1)}</option>)}
        </select>
        <input
          className="input" style={{ flex: 1 }}
          placeholder={`Enter trusted ${newEntry.type} (e.g. ${newEntry.type === 'domain' ? 'partner.com' : newEntry.type === 'ip' ? '192.168.1.50' : 'ceo@company.com'})`}
          value={newEntry.value}
          onChange={e => setNewEntry(p => ({ ...p, value: e.target.value }))}
          onKeyDown={e => e.key === 'Enter' && handleAdd()}
        />
        <button className="btn btn-primary" disabled={!newEntry.value.trim() || addToWhitelist.isPending} onClick={handleAdd} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <Plus size={15} /> Add
        </button>
      </div>

      {/* ── Table ── */}
      <table className="table" style={{ width: '100%' }}>
        <thead>
          <tr style={{ textAlign: 'left', background: 'var(--bg-overlay)' }}>
            <th style={{ padding: '12px 16px', width: 120 }}>Type</th>
            <th style={{ padding: '12px 16px' }}>Value</th>
            <th style={{ padding: '12px 16px', textAlign: 'right' }}>Actions</th>
          </tr>
        </thead>
        <tbody>
          {types.flatMap(type =>
            (whitelist[type + 's'] || []).map(val => (
              <tr key={`${type}-${val}`} style={{ borderTop: '1px solid var(--border)' }}>
                <td style={{ padding: '12px 16px' }}>
                  <span className="tag" style={{ textTransform: 'uppercase', fontSize: '0.7rem', fontWeight: 700, letterSpacing: 0.5 }}>{type}</span>
                </td>
                <td style={{ padding: '12px 16px', fontFamily: 'var(--font-mono)', fontSize: '0.9rem' }}>{val}</td>
                <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                  <button className="icon-btn danger" onClick={() => removeFromWhitelist.mutate({ type, val })} disabled={removeFromWhitelist.isPending} title="Remove">
                    <Trash2 size={15} />
                  </button>
                </td>
              </tr>
            ))
          )}
          {types.every(t => !(whitelist[t + 's']?.length)) && (
            <tr><td colSpan={3} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 'var(--sp-6)' }}>The whitelist is currently empty.</td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
