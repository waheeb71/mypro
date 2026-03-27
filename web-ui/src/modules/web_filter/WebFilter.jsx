import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Globe, Shield, Search, Plus, Trash2, CheckCircle, XCircle, Settings, AlertTriangle, ShieldAlert } from 'lucide-react';
import { webFilterApi } from '../../services/api';

export default function WebFilter() {
  const qc = useQueryClient();
  const [newDomain, setNewDomain] = useState('');
  const [newReason, setNewReason] = useState('');
  const [search, setSearch] = useState('');

  // Fetchers
  const { data: statusData } = useQuery({ queryKey: ['wf_status'], queryFn: () => webFilterApi.status().then(r => r.data) });
  const { data: config = {} } = useQuery({ queryKey: ['wf_config'], queryFn: () => webFilterApi.config().then(r => r.data) });
  const { data: categories = [] } = useQuery({ queryKey: ['wf_categories'], queryFn: () => webFilterApi.categories().then(r => r.data) });
  const { data: domains = [] } = useQuery({ queryKey: ['wf_domains'], queryFn: () => webFilterApi.domains().then(r => r.data) });

  // Mutations
  const updateConfig = useMutation({
    mutationFn: (d) => webFilterApi.updateConfig(d),
    onSuccess: () => { qc.invalidateQueries(['wf_config']); qc.invalidateQueries(['wf_status']); }
  });

  const addDomain = useMutation({
    mutationFn: (d) => webFilterApi.addDomain(d),
    onSuccess: () => qc.invalidateQueries(['wf_domains'])
  });

  const deleteDomain = useMutation({
    mutationFn: (id) => webFilterApi.deleteDomain(id),
    onSuccess: () => qc.invalidateQueries(['wf_domains'])
  });

  const addCategory = useMutation({
    mutationFn: (d) => webFilterApi.addCategory(d),
    onSuccess: () => qc.invalidateQueries(['wf_categories'])
  });

  const deleteCategory = useMutation({
    mutationFn: (id) => webFilterApi.deleteCategory(id),
    onSuccess: () => qc.invalidateQueries(['wf_categories'])
  });

  // Handlers
  const handleConfigToggle = (key, val) => updateConfig.mutate({ [key]: val });
  
  const handleAddDomain = (e) => {
    e.preventDefault();
    if (!newDomain.trim()) return;
    addDomain.mutate({ domain_pattern: newDomain.trim(), category_name: newReason || 'User Blocked', action: 'BLOCK' });
    setNewDomain('');
    setNewReason('');
  };

  const filteredDomains = domains.filter(d => d.domain_pattern.toLowerCase().includes(search.toLowerCase()));

  // Category Icon Map
  const catIcons = { adult: '🔞', gambling: '🎰', malware: '☠️', phishing: '🎣', social: '📱', streaming: '🎬', games: '🎮' };
  const getCatIcon = (name) => {
    for (const [k, v] of Object.entries(catIcons)) {
      if (name.toLowerCase().includes(k)) return v;
    }
    return '📂';
  };

  return (
    <div className="module-page" style={{ animation: 'fadeIn 0.4s ease-out' }}>
      {/* Header */}
      <div className="page-header" style={{
        background: 'linear-gradient(135deg, rgba(30,58,138,0.1) 0%, rgba(15,23,42,0.1) 100%)',
        padding: 'var(--sp-6)', borderRadius: 'var(--radius)', borderBottom: '1px solid var(--border)',
        marginBottom: 'var(--sp-6)', position: 'relative', overflow: 'hidden'
      }}>
        <div style={{ position: 'relative', zIndex: 1 }}>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 12, fontSize: '2rem' }}>
            <Globe className="animate-spin-slow" size={32} style={{ color: 'var(--primary)' }} /> 
            Web Filter Engine
          </h1>
          <p className="page-subtitle" style={{ fontSize: '1.1rem', marginTop: 8 }}>
            Advanced URL filtering, dynamic categorization, and policy enforcement
          </p>
        </div>
        <div style={{ position: 'absolute', right: 'var(--sp-6)', top: '50%', transform: 'translateY(-50%)', zIndex: 1, display: 'flex', gap: 16 }}>
           <span className={`badge ${statusData?.status === 'active' ? 'badge-success' : 'badge-danger'}`} style={{ padding: '8px 16px', fontSize: '1rem', display: 'flex', alignItems: 'center', gap: 8 }}>
            {statusData?.status === 'active' ? <CheckCircle size={18}/> : <XCircle size={18}/>}
            {statusData?.status?.toUpperCase() || 'LOADING...'}
          </span>
        </div>
      </div>

      {/* Grid Layout */}
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(300px, 1fr) 2fr', gap: 'var(--sp-6)', alignItems: 'start' }}>
        
        {/* Left Column: Settings & Stats */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-6)' }}>
          
          <div className="card" style={{ padding: 'var(--sp-5)', borderTop: '4px solid var(--primary)' }}>
            <h3 style={{ fontSize: '1.2rem', fontWeight: 700, marginBottom: 'var(--sp-5)', display: 'flex', alignItems: 'center', gap: 8 }}>
              <Settings size={20} className="text-primary"/> Global Configuration
            </h3>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: 'var(--sp-3)', background: 'var(--bg-raised)', borderRadius: 'var(--radius)' }}>
                <div>
                  <div style={{ fontWeight: 600 }}>Enable Filter Module</div>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Main ON/OFF switch</div>
                </div>
                <label className="toggle">
                  <input type="checkbox" checked={config.enabled || false} onChange={e => handleConfigToggle('enabled', e.target.checked)} />
                  <span className="toggle-slider" />
                </label>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: 'var(--sp-3)', background: 'var(--bg-raised)', borderRadius: 'var(--radius)' }}>
                <div>
                  <div style={{ fontWeight: 600 }}>Safe Search Auto-Enforce</div>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Google, Bing, YouTube</div>
                </div>
                <label className="toggle">
                  <input type="checkbox" checked={config.safe_search_enabled || false} onChange={e => handleConfigToggle('safe_search_enabled', e.target.checked)} />
                  <span className="toggle-slider" />
                </label>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: 'var(--sp-3)', background: 'var(--bg-raised)', borderRadius: 'var(--radius)' }}>
                 <div style={{ fontWeight: 600 }}>Engine Mode</div>
                 <select className="input" style={{ width: 120, padding: '4px 8px' }} value={config.mode || 'monitor'} onChange={e => handleConfigToggle('mode', e.target.value)}>
                    <option value="monitor">Monitor Only</option>
                    <option value="enforce">Enforce</option>
                 </select>
              </div>
            </div>
          </div>

          <div className="card" style={{ padding: 'var(--sp-5)', background: 'var(--bg-raised)' }}>
            <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 'var(--sp-4)' }}>Live Statistics</h3>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: 'var(--sp-3)', marginBottom: 'var(--sp-3)' }}>
              <span style={{ color: 'var(--text-muted)' }}>Active Categories</span>
              <span style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--primary)' }}>{categories.length}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Custom Domains</span>
              <span style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--warning)' }}>{domains.length}</span>
            </div>
          </div>

        </div>

        {/* Right Column: Categories and Domains */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-6)' }}>
          
          {/* Categories */}
          <div className="card" style={{ padding: 'var(--sp-5)' }}>
            <h3 style={{ fontSize: '1.2rem', fontWeight: 700, marginBottom: 'var(--sp-5)', display: 'flex', alignItems: 'center', gap: 8 }}>
              <ShieldAlert size={20} className="text-danger"/> Category Polices
            </h3>
            
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 'var(--sp-3)' }}>
              {categories.map(cat => (
                <div key={cat.id} style={{
                    padding: 'var(--sp-3)',
                    border: `1px solid ${cat.action === 'BLOCK' ? 'rgba(239, 68, 68, 0.3)' : 'var(--border)'}`,
                    borderRadius: 'var(--radius)',
                    background: cat.action === 'BLOCK' ? 'rgba(239, 68, 68, 0.05)' : 'var(--bg)',
                    display: 'flex', flexDirection: 'column', gap: 'var(--sp-2)',
                    transition: 'transform 0.2s',
                    position: 'relative'
                  }}
                  className="hover-lift"
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: '1.5rem' }}>{getCatIcon(cat.name)}</span>
                    <span className={`badge ${cat.action === 'BLOCK' ? 'badge-danger' : 'badge-success'}`} style={{ fontSize: '0.7rem' }}>
                      {cat.action}
                    </span>
                  </div>
                  <div style={{ fontWeight: 600, textTransform: 'capitalize', marginTop: 4 }}>{cat.name.replace('_', ' ')}</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Risk: {cat.risk_score}/100</div>
                  {cat.is_custom && (
                     <button onClick={() => deleteCategory.mutate(cat.id)} style={{ position:'absolute', top: 8, right: 8, background:'none', border:'none', color:'var(--text-muted)', cursor:'pointer' }}>
                       <Trash2 size={14}/>
                     </button>
                  )}
                </div>
              ))}
              
              <div 
                style={{
                  padding: 'var(--sp-3)', border: '1px dashed var(--primary)', borderRadius: 'var(--radius)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer',
                  background: 'rgba(59, 130, 246, 0.05)', color: 'var(--primary)', fontWeight: 600
                }}
                onClick={() => {
                  const name = prompt("Enter new category name:");
                  if (name) addCategory.mutate({ name, action: 'BLOCK', risk_score: 50 });
                }}
              >
                <Plus size={24} /> Add Category
              </div>
            </div>
          </div>

          {/* Domains */}
          <div className="card" style={{ padding: 'calc(var(--sp-5) * 1.5)', overflow: 'hidden' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--sp-5)' }}>
              <h3 style={{ fontSize: '1.2rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
                <Globe size={20} className="text-info"/> Domain Overrides (Whitelist/Blacklist)
              </h3>
            </div>

            <form onSubmit={handleAddDomain} style={{ display: 'flex', gap: 'var(--sp-3)', marginBottom: 'var(--sp-5)' }}>
              <input className="input" style={{ flex: 2, padding: '12px' }} placeholder="e.g. *.example.com or malicious-site.net" value={newDomain} onChange={e => setNewDomain(e.target.value)} required />
              <input className="input" style={{ flex: 1, padding: '12px' }} placeholder="Label / Reason" value={newReason} onChange={e => setNewReason(e.target.value)} />
              <button className="btn btn-primary" type="submit" disabled={addDomain.isLoading} style={{ padding: '0 24px' }}>
                <Plus size={18} style={{ marginRight: 8 }}/> Add Domain
              </button>
            </form>

            <div style={{ position: 'relative', marginBottom: 'var(--sp-4)' }}>
              <Search size={16} style={{ position: 'absolute', left: 16, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              <input className="input" style={{ width: '100%', paddingLeft: 40 }} placeholder="Search existing rules..." value={search} onChange={e => setSearch(e.target.value)} />
            </div>

            <div style={{ borderRadius: 'var(--radius)', border: '1px solid var(--border)', overflow: 'hidden' }}>
              <table className="table" style={{ width: '100%' }}>
                <thead style={{ background: 'var(--bg-raised)' }}>
                  <tr>
                    <th style={{ padding: '12px 16px', textAlign: 'left' }}>Pattern</th>
                    <th style={{ padding: '12px 16px', textAlign: 'left' }}>Reason / Category</th>
                    <th style={{ padding: '12px 16px', textAlign: 'left' }}>Action</th>
                    <th style={{ padding: '12px 16px', textAlign: 'right' }}>Remove</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredDomains.length === 0 ? (
                    <tr><td colSpan={4} style={{ textAlign: 'center', padding: 'var(--sp-6)', color: 'var(--text-muted)' }}>No domain rules found</td></tr>
                  ) : filteredDomains.map(d => (
                    <tr key={d.id} style={{ borderTop: '1px solid var(--border)' }}>
                      <td style={{ padding: '12px 16px', fontFamily: 'monospace', fontWeight: 600, color: 'var(--text-secondary)' }}>{d.domain_pattern}</td>
                      <td style={{ padding: '12px 16px', color: 'var(--text-muted)' }}>{d.category_name || '-'}</td>
                      <td style={{ padding: '12px 16px' }}>
                        <span className={`badge ${d.action === 'BLOCK' ? 'badge-danger' : 'badge-success'}`}>{d.action}</span>
                      </td>
                      <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                        <button className="icon-btn danger" onClick={() => deleteDomain.mutate(d.id)}><Trash2 size={16} /></button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

          </div>
        </div>
      </div>
      
      <style>{`
        .hover-lift:hover {
          transform: translateY(-2px);
          box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        .animate-spin-slow {
          animation: spin 8s linear infinite;
        }
        @keyframes spin { 100% { transform: rotate(360deg); } }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
      `}</style>
    </div>
  );
}
