import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { 
  FileText, Shield, Zap, Plus, Trash2, Search, 
  CheckCircle, XCircle, AlertTriangle, Fingerprint, Database 
} from 'lucide-react';
import { dlpApi } from '../../services/api';

export default function DLP() {
  const qc = useQueryClient();
  const [search, setSearch] = useState('');
  const [newRule, setNewRule] = useState({ name: '', pattern: '', severity: 'HIGH', description: '' });

  // Fetchers
  const { data: statusData } = useQuery({ queryKey: ['dlp_status'], queryFn: () => dlpApi.status().then(r => r.data) });
  const { data: config = {} } = useQuery({ queryKey: ['dlp_config'], queryFn: () => dlpApi.config().then(r => r.data) });
  const { data: rules = [] } = useQuery({ queryKey: ['dlp_rules'], queryFn: () => dlpApi.rules().then(r => r.data) });

  // Mutations
  const updateConfig = useMutation({
    mutationFn: (d) => dlpApi.updateConfig(d),
    onSuccess: () => { qc.invalidateQueries(['dlp_config']); qc.invalidateQueries(['dlp_status']); }
  });

  const addRule = useMutation({
    mutationFn: (d) => dlpApi.createRule(d),
    onSuccess: () => { 
      qc.invalidateQueries(['dlp_rules']); 
      setNewRule({ name: '', pattern: '', severity: 'HIGH', description: '' });
    }
  });

  const deleteRule = useMutation({
    mutationFn: (id) => dlpApi.deleteRule(id),
    onSuccess: () => qc.invalidateQueries(['dlp_rules'])
  });

  // Handlers
  const handleConfigToggle = (key, val) => updateConfig.mutate({ ...config, [key]: val });
  
  const handleAddRule = (e) => {
    e.preventDefault();
    if (!newRule.name.trim() || !newRule.pattern.trim()) return;
    addRule.mutate(newRule);
  };

  const filteredRules = rules.filter(r => 
    r.name.toLowerCase().includes(search.toLowerCase()) || 
    r.pattern.toLowerCase().includes(search.toLowerCase())
  );

  const getSeverityBadge = (sev) => {
    switch(sev?.toUpperCase()) {
      case 'CRITICAL': return 'badge-danger';
      case 'HIGH': return 'badge-warning';
      case 'MEDIUM': return 'badge-info';
      default: return 'badge-ghost';
    }
  };

  return (
    <div className="module-page" style={{ animation: 'fadeIn 0.5s ease-out' }}>
      {/* Header */}
      <div className="page-header" style={{
        background: 'linear-gradient(135deg, rgba(239, 68, 68, 0.08) 0%, rgba(15, 23, 42, 0.1) 100%)',
        padding: 'var(--sp-6)', borderRadius: 'var(--radius)', borderBottom: '1px solid var(--border)',
        marginBottom: 'var(--sp-6)', position: 'relative', overflow: 'hidden'
      }}>
        <div style={{ position: 'relative', zIndex: 1 }}>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 12, fontSize: '2rem' }}>
            <FileText size={32} style={{ color: 'var(--danger)' }} className="animate-pulse-slow" /> 
            Data Loss Prevention (DLP)
          </h1>
          <p className="page-subtitle" style={{ fontSize: '1.1rem', marginTop: 8 }}>
            Inspect outbound traffic for PII, Financial Data, and enforce Data Watermarking Traps.
          </p>
        </div>
        <div style={{ position: 'absolute', right: 'var(--sp-6)', top: '50%', transform: 'translateY(-50%)', zIndex: 1, display: 'flex', gap: 16 }}>
           <span className={`badge ${statusData?.status === 'active' ? 'badge-success' : 'badge-danger'}`} style={{ padding: '8px 16px', fontSize: '1rem', display: 'flex', alignItems: 'center', gap: 8 }}>
            {statusData?.status === 'active' ? <CheckCircle size={18}/> : <XCircle size={18}/>}
            {statusData?.status?.toUpperCase() || 'LOADING...'}
          </span>
        </div>
      </div>

      {/* Main Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(320px, 1fr) 2fr', gap: 'var(--sp-6)', alignItems: 'start' }}>
        
        {/* Left Column: Config Settings */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-6)' }}>
          
          <div className="card" style={{ padding: 'var(--sp-5)', borderTop: '4px solid var(--danger)' }}>
            <h3 style={{ fontSize: '1.2rem', fontWeight: 700, marginBottom: 'var(--sp-5)', display: 'flex', alignItems: 'center', gap: 8 }}>
              <Shield size={20} className="text-danger"/> Global Configuration
            </h3>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
              
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: 'var(--sp-3)', background: 'var(--bg-raised)', borderRadius: 'var(--radius)' }}>
                <div>
                  <div style={{ fontWeight: 600 }}>Enable DLP Monitoring</div>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Scan all outbound payloads</div>
                </div>
                <label className="toggle">
                  <input type="checkbox" checked={config.is_active || false} onChange={e => handleConfigToggle('is_active', e.target.checked)} />
                  <span className="toggle-slider" />
                </label>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: 'var(--sp-3)', background: 'var(--bg-raised)', borderRadius: 'var(--radius)' }}>
                <div>
                  <div style={{ fontWeight: 600 }}>Auto-Block Outbound Leaks</div>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Drop packets containing sensitive data</div>
                </div>
                <label className="toggle">
                  <input type="checkbox" checked={config.block_on_match || false} onChange={e => handleConfigToggle('block_on_match', e.target.checked)} />
                  <span className="toggle-slider" />
                </label>
              </div>

            </div>
          </div>

          <div className="card hover-lift" style={{ 
            padding: 'var(--sp-6)', 
            border: '1px solid rgba(255, 180, 0, 0.3)', 
            background: 'linear-gradient(135deg, var(--bg-card), rgba(255, 180, 0, 0.05))',
            boxShadow: config.deception_enabled ? '0 0 20px rgba(255, 180, 0, 0.1)' : 'none'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-3)', marginBottom: 'var(--sp-5)' }}>
              <div style={{ padding: 10, background: 'rgba(255, 180, 0, 0.15)', borderRadius: '50%' }}>
                <Zap size={24} style={{ color: '#ffb400' }} />
              </div>
              <div>
                <h3 style={{ color: '#ffb400', margin: 0, fontSize: '1.2rem', fontWeight: 800 }}>Causal Deception Engine</h3>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', margin: 0, marginTop: 4 }}>Patent-Pending Active Defense Strategy</p>
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: 'var(--sp-4)', background: 'var(--bg-raised)', borderRadius: 'var(--radius)', border: '1px solid rgba(255, 180, 0, 0.15)' }}>
              <div>
                <div style={{ fontWeight: 700 }}>Inject Data Watermark Traps</div>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: 4, lineHeight: 1.5 }}>
                  Instead of silently dropping suspected exfiltration, inject invisible watermarked decoy records (e.g. Fake Credit Cards) to track and prove origin intent.
                </div>
              </div>
              <label className="toggle" style={{ marginLeft: 'var(--sp-5)', flexShrink: 0 }}>
                <input
                  type="checkbox"
                  checked={config.deception_enabled ?? true}
                  onChange={e => handleConfigToggle('deception_enabled', e.target.checked)}
                />
                <span className="toggle-slider" style={{ background: config.deception_enabled ? '#ffb400' : 'var(--border)' }} />
              </label>
            </div>
            
            {config.deception_enabled && (
               <div style={{ marginTop: 'var(--sp-4)', padding: 'var(--sp-3) var(--sp-4)', background: 'rgba(255, 180, 0, 0.08)', borderRadius: 'var(--radius)', fontSize: '0.8rem', color: '#ffb400', display: 'flex', gap: 8, alignItems: 'center', fontWeight: 600 }}>
                 <Fingerprint size={16} /> Watermark Generation Active
               </div>
            )}
          </div>

          {/* Stats Summary */}
          <div className="card" style={{ padding: 'var(--sp-5)', background: 'var(--bg-raised)' }}>
             <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 'var(--sp-4)', display: 'flex', alignItems: 'center', gap: 8 }}>
                <Database size={18} /> Active Patterns
             </h3>
             <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: 'var(--sp-3)', marginBottom: 'var(--sp-3)' }}>
               <span style={{ color: 'var(--text-muted)' }}>Custom Regex Rules</span>
               <span style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--primary)' }}>{rules.length}</span>
             </div>
             <div style={{ display: 'flex', justifyContent: 'space-between' }}>
               <span style={{ color: 'var(--text-muted)' }}>Built-in Analyzers</span>
               <span style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--success)' }}>Active</span>
             </div>
          </div>

        </div>

        {/* Right Column: Regex Rules Manager */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-6)' }}>
          <div className="card" style={{ padding: 'calc(var(--sp-5) * 1.5)', overflow: 'hidden', height: '100%' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--sp-5)' }}>
              <h3 style={{ fontSize: '1.2rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
                <AlertTriangle size={20} className="text-warning"/> Custom Data Extraction Patterns
              </h3>
            </div>

            {/* Addition Form */}
            <form onSubmit={handleAddRule} style={{ display: 'grid', gridTemplateColumns: '1fr 2fr 120px auto', gap: 'var(--sp-3)', marginBottom: 'var(--sp-5)', background: 'var(--bg-raised)', padding: 'var(--sp-4)', borderRadius: 'var(--radius)', border: '1px solid var(--border)' }}>
              <input className="input" placeholder="Rule Name (e.g. Secret-Proj)" value={newRule.name} onChange={e => setNewRule({...newRule, name: e.target.value})} required />
              <input className="input" placeholder="Regex (e.g. \\bPRJ-[A-Z]{4}\\b)" value={newRule.pattern} onChange={e => setNewRule({...newRule, pattern: e.target.value})} required />
              <select className="input" value={newRule.severity} onChange={e => setNewRule({...newRule, severity: e.target.value})}>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
              <button className="btn btn-primary" type="submit" disabled={addRule.isLoading} style={{ padding: '0 20px' }}>
                <Plus size={18} style={{ marginRight: 6 }}/> Add
              </button>
            </form>

            <div style={{ position: 'relative', marginBottom: 'var(--sp-4)' }}>
              <Search size={16} style={{ position: 'absolute', left: 16, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              <input className="input" style={{ width: '100%', paddingLeft: 40 }} placeholder="Search rules..." value={search} onChange={e => setSearch(e.target.value)} />
            </div>

            <div style={{ borderRadius: 'var(--radius)', border: '1px solid var(--border)', overflow: 'auto', maxHeight: '500px' }}>
              <table className="table" style={{ width: '100%' }}>
                <thead style={{ background: 'var(--bg-raised)', position: 'sticky', top: 0, zIndex: 1 }}>
                  <tr>
                    <th style={{ padding: '12px 16px', textAlign: 'left' }}>Rule Identifier</th>
                    <th style={{ padding: '12px 16px', textAlign: 'left' }}>Regex Pattern</th>
                    <th style={{ padding: '12px 16px', textAlign: 'center' }}>Severity</th>
                    <th style={{ padding: '12px 16px', textAlign: 'right' }}>Remove</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredRules.length === 0 ? (
                    <tr><td colSpan={4} style={{ textAlign: 'center', padding: 'var(--sp-6)', color: 'var(--text-muted)' }}>No custom rules found.</td></tr>
                  ) : filteredRules.map(r => (
                    <tr key={r.id} style={{ borderTop: '1px solid var(--border)' }}>
                      <td style={{ padding: '12px 16px', fontWeight: 600, color: 'var(--text-secondary)' }}>{r.name}</td>
                      <td style={{ padding: '12px 16px', fontFamily: 'monospace', color: 'var(--text-muted)', fontSize: '0.9rem' }}>
                         <code style={{ background: 'var(--bg-raised)', padding: '2px 6px', borderRadius: 4 }}>{r.pattern}</code>
                      </td>
                      <td style={{ padding: '12px 16px', textAlign: 'center' }}>
                        <span className={`badge ${getSeverityBadge(r.severity)}`}>{r.severity}</span>
                      </td>
                      <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                        <button className="icon-btn danger" onClick={() => deleteRule.mutate(r.id)}>
                          <Trash2 size={16} />
                        </button>
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
        .hover-lift {
          transition: transform 0.2s, box-shadow 0.2s;
        }
        .hover-lift:hover {
          transform: translateY(-2px);
          box-shadow: 0 6px 16px rgba(0,0,0,0.15) !important;
        }
        .animate-pulse-slow {
          animation: pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite;
        }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .7; } }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
      `}</style>
    </div>
  );
}
