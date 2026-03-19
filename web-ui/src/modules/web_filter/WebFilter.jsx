import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Globe, Shield, Search, Plus, Trash2, RefreshCw, CheckCircle, XCircle, AlertTriangle } from 'lucide-react';
import { webFilterApi } from '../../services/api';

const CATEGORIES = [
  { id: 'adult', label: 'Adult Content', icon: '🔞', blocked: true },
  { id: 'gambling', label: 'Gambling', icon: '🎰', blocked: true },
  { id: 'social_media', label: 'Social Media', icon: '📱', blocked: false },
  { id: 'streaming', label: 'Streaming / Video', icon: '🎬', blocked: false },
  { id: 'malware', label: 'Malware Sites', icon: '☠️', blocked: true },
  { id: 'phishing', label: 'Phishing', icon: '🎣', blocked: true },
  { id: 'proxy_bypass', label: 'Proxy/VPN Bypass', icon: '🔀', blocked: true },
  { id: 'games', label: 'Online Games', icon: '🎮', blocked: false },
];

const DEMO_BLOCKED = [
  { url: 'torrent.example.com', reason: 'P2P Traffic', added: '2026-03-18' },
  { url: 'ads.tracking.net', reason: 'Tracker', added: '2026-03-17' },
  { url: 'malware-host.ru', reason: 'Malware Distribution', added: '2026-03-15' },
];

export default function WebFilter() {
  const [categories, setCategories] = useState(CATEGORIES);
  const [blockedUrls, setBlockedUrls] = useState(DEMO_BLOCKED);
  const [newUrl, setNewUrl] = useState('');
  const [newReason, setNewReason] = useState('');
  const [search, setSearch] = useState('');
  const [safeSearch, setSafeSearch] = useState(true);
  const [ytSafeMode, setYtSafeMode] = useState(true);

  const { data: statusData } = useQuery({
    queryKey: ['web_filter_status'],
    queryFn: () => webFilterApi.status().then(r => r.data),
    retry: false,
    refetchInterval: 30000,
  });

  const toggleCategory = (id) => {
    setCategories(cats => cats.map(c => c.id === id ? { ...c, blocked: !c.blocked } : c));
  };

  const addUrl = (e) => {
    e.preventDefault();
    if (!newUrl.trim()) return;
    setBlockedUrls(prev => [...prev, { url: newUrl.trim(), reason: newReason || 'Manual block', added: new Date().toISOString().split('T')[0] }]);
    setNewUrl(''); setNewReason('');
  };

  const removeUrl = (url) => setBlockedUrls(prev => prev.filter(u => u.url !== url));

  const filtered = blockedUrls.filter(u => u.url.toLowerCase().includes(search.toLowerCase()));
  const blockedCount = categories.filter(c => c.blocked).length;

  return (
    <div className="module-page">
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Globe size={24} style={{ color: 'var(--accent)' }} /> Web Filter
          </h1>
          <p className="page-subtitle">URL filtering, category blocking, and safe search enforcement</p>
        </div>
        <div style={{ display: 'flex', gap: 'var(--sp-3)', alignItems: 'center' }}>
          <span className={`badge ${statusData ? 'badge-success' : 'badge-info'}`}>
            {statusData ? '● Active' : '○ Loading'}
          </span>
        </div>
      </div>

      {/* Stats row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 'var(--sp-4)' }}>
        {[
          { label: 'Categories Blocked', value: blockedCount, color: 'var(--danger)' },
          { label: 'Custom URLs Blocked', value: blockedUrls.length, color: 'var(--warning)' },
          { label: 'Safe Search', value: safeSearch ? 'ON' : 'OFF', color: safeSearch ? 'var(--success)' : 'var(--text-muted)' },
          { label: 'YouTube Safe Mode', value: ytSafeMode ? 'ON' : 'OFF', color: ytSafeMode ? 'var(--success)' : 'var(--text-muted)' },
        ].map(s => (
          <div key={s.label} className="card" style={{ padding: 'var(--sp-4)', textAlign: 'center' }}>
            <div style={{ fontSize: '1.6rem', fontWeight: 700, color: s.color }}>{s.value}</div>
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 4 }}>{s.label}</div>
          </div>
        ))}
      </div>

      {/* Safe Search toggles */}
      <div className="card" style={{ padding: 'var(--sp-5)' }}>
        <h3 style={{ marginBottom: 'var(--sp-4)', fontSize: 'var(--text-sm)', fontWeight: 700, color: 'var(--text-secondary)' }}>
          🔒 Safe Search Settings
        </h3>
        <div style={{ display: 'flex', gap: 'var(--sp-6)' }}>
          {[
            { label: 'Google / Bing Safe Search', value: safeSearch, set: setSafeSearch },
            { label: 'YouTube Restricted Mode', value: ytSafeMode, set: setYtSafeMode },
          ].map(t => (
            <div key={t.label} style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-3)' }}>
              <label className="toggle">
                <input type="checkbox" checked={t.value} onChange={() => t.set(v => !v)} />
                <span className="toggle-slider" />
              </label>
              <span style={{ fontSize: 'var(--text-sm)' }}>{t.label}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Category Blocking */}
      <div className="card" style={{ padding: 'var(--sp-5)' }}>
        <h3 style={{ marginBottom: 'var(--sp-4)', fontSize: 'var(--text-sm)', fontWeight: 700, color: 'var(--text-secondary)' }}>
          📂 Category Filters
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 'var(--sp-3)' }}>
          {categories.map(cat => (
            <div
              key={cat.id}
              onClick={() => toggleCategory(cat.id)}
              style={{
                padding: 'var(--sp-3) var(--sp-4)',
                border: `1px solid ${cat.blocked ? 'var(--danger)' : 'var(--border)'}`,
                borderRadius: 'var(--radius)',
                background: cat.blocked ? 'var(--danger-dim)' : 'var(--bg-raised)',
                cursor: 'pointer',
                transition: 'all 0.2s',
                display: 'flex', alignItems: 'center', gap: 'var(--sp-2)',
              }}
            >
              <span style={{ fontSize: '1.2rem' }}>{cat.icon}</span>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600 }}>{cat.label}</div>
                <div style={{ fontSize: '0.65rem', color: cat.blocked ? 'var(--danger)' : 'var(--text-muted)', marginTop: 2 }}>
                  {cat.blocked ? '● BLOCKED' : '○ Allowed'}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Custom URL Blocklist */}
      <div className="card" style={{ overflow: 'hidden' }}>
        <div className="section-header">
          <h3 style={{ fontSize: 'var(--text-sm)', fontWeight: 700 }}>🌐 Custom URL Blocklist</h3>
          <span className="tag">{blockedUrls.length} URLs</span>
        </div>

        {/* Add URL form */}
        <form onSubmit={addUrl} style={{ display: 'flex', gap: 'var(--sp-3)', padding: 'var(--sp-4)', borderBottom: '1px solid var(--border)' }}>
          <input className="input" style={{ flex: 2 }} placeholder="domain or URL to block…" value={newUrl} onChange={e => setNewUrl(e.target.value)} />
          <input className="input" style={{ flex: 1 }} placeholder="Reason (optional)" value={newReason} onChange={e => setNewReason(e.target.value)} />
          <button className="btn btn-primary" type="submit"><Plus size={15} /> Add</button>
        </form>

        {/* Search bar */}
        <div style={{ padding: 'var(--sp-3) var(--sp-4)', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 'var(--sp-2)' }}>
          <Search size={14} style={{ color: 'var(--text-muted)' }} />
          <input className="input" style={{ border: 'none', background: 'transparent', padding: 0 }}
            placeholder="Search URLs…" value={search} onChange={e => setSearch(e.target.value)} />
        </div>

        <table className="table">
          <thead>
            <tr><th>URL / Domain</th><th>Reason</th><th>Added</th><th></th></tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr><td colSpan={4} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 'var(--sp-6)' }}>No blocked URLs</td></tr>
            ) : filtered.map(u => (
              <tr key={u.url}>
                <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--danger)' }}>{u.url}</td>
                <td style={{ color: 'var(--text-muted)' }}>{u.reason}</td>
                <td style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)' }}>{u.added}</td>
                <td>
                  <button className="icon-btn danger" onClick={() => removeUrl(u.url)}><Trash2 size={13} /></button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
