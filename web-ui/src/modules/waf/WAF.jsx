import { useState, useEffect, useRef } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Globe2, Cpu, Database, Play, RefreshCw, Upload,
  CheckCircle, Shield, Zap, Activity, Eye, Download, ShieldAlert,
  Server, Lock, AlertTriangle, PlayCircle
} from 'lucide-react';
import { wafApi } from '../../services/api';

/* ── Components ────────────────────────────────────────── */

function ToggleSwitch({ label, enabled, onChange, disabled }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: 'var(--sp-4)', borderBottom: '1px solid var(--border)' }}>
      <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)', fontWeight: 500 }}>{label}</span>
      <label className="switch" style={{ opacity: disabled ? 0.5 : 1, cursor: disabled ? 'not-allowed' : 'pointer', position: 'relative', display: 'inline-block', width: '40px', height: '20px' }}>
        <input 
          type="checkbox" 
          checked={enabled} 
          onChange={(e) => !disabled && onChange(e.target.checked)}
          disabled={disabled}
          style={{ opacity: 0, width: 0, height: 0 }}
        />
        <span style={{
          position: 'absolute', top: 0, left: 0, right: 0, bottom: 0,
          backgroundColor: enabled ? 'var(--accent)' : 'var(--bg-raised)',
          borderRadius: '20px', transition: '.4s',
        }}>
          <span style={{
            position: 'absolute', content: '""', height: '14px', width: '14px',
            left: enabled ? '22px' : '3px', bottom: '3px',
            backgroundColor: 'white', borderRadius: '50%', transition: '.4s'
          }} />
        </span>
      </label>
    </div>
  );
}

function LiveMonitor() {
  const [events, setEvents] = useState([]);
  const ws = useRef(null);

  useEffect(() => {
    const token = localStorage.getItem('ngfw_token');
    const wsUrl = (import.meta.env.VITE_API_URL || 'http://192.168.109.137:8000').replace(/^http/, 'ws');
    
    ws.current = new WebSocket(`${wsUrl}/api/v1/waf/live?token=${token}`);
    
    ws.current.onmessage = (msg) => {
      try {
        const data = JSON.parse(msg.data);
        setEvents(prev => [data, ...prev].slice(0, 50));
      } catch (e) {
        console.error("WebSocket message error:", e);
      }
    };

    return () => {
      if (ws.current) ws.current.close();
    };
  }, []);

  return (
    <div className="card" style={{ height: 400, display: 'flex', flexDirection: 'column' }}>
      <div className="section-header" style={{ borderBottom: '1px solid var(--border)', paddingBottom: 'var(--sp-3)' }}>
        <div className="section-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Activity size={17} style={{ color: 'var(--danger)' }} />
          Live Threat Feed
        </div>
      </div>
      <div style={{ flex: 1, overflowY: 'auto', padding: 'var(--sp-3)', display: 'flex', flexDirection: 'column', gap: 'var(--sp-2)' }}>
        {events.length === 0 ? (
          <div style={{ color: 'var(--text-muted)', textAlign: 'center', marginTop: 40, fontSize: 'var(--text-sm)' }}>
             Monitoring traffic in real-time... No threats detected recently.
          </div>
        ) : (
          events.map((ev, i) => (
            <div key={i} style={{ 
              padding: 'var(--sp-3)', 
              borderRadius: 'var(--radius-sm)', 
              background: 'var(--bg-raised)',
              borderLeft: `3px solid ${ev.action === 'BLOCK' ? 'var(--danger)' : 'var(--warning)'}`,
              fontSize: 'var(--text-xs)'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                <strong style={{ color: 'var(--text-primary)' }}>{ev.src_ip}</strong>
                <span className={`badge ${ev.action === 'BLOCK' ? 'badge-danger' : 'badge-warning'}`}>{ev.action}</span>
              </div>
              <div style={{ color: 'var(--text-secondary)', marginBottom: 4 }}>
                 Path: <code style={{ color: 'var(--accent)' }}>{ev.path}</code>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)' }}>
                 <span>Triggers: {ev.triggers?.join(', ') || 'Unknown'}</span>
                 <span>Score: {ev.risk_score}</span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function ShadowAutopilot() {
  const [hours, setHours] = useState(72);
  const queryClient = useQueryClient();

  const { data: status } = useQuery({
    queryKey: ['waf-shadow-status'], queryFn: () => wafApi.shadowModeStatus().then(r => r.data),
    refetchInterval: 3000,
  });

  const startMut = useMutation({ 
    mutationFn: (h) => wafApi.startShadowMode(h),
    onSuccess: () => {
      queryClient.invalidateQueries(['waf-shadow-status']);
      queryClient.invalidateQueries(['waf-status']);
    }
  });

  const exportMut = useMutation({
    mutationFn: () => wafApi.exportShadowSchema(),
    onSuccess: (res) => {
      // Create a downloadable JSON file
      const blob = new Blob([JSON.stringify(res.data.schema, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `autopilot_schema_${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
    }
  });

  const isLearning = status?.status === 'learning';

  return (
    <div className="card" style={{ padding: 'var(--sp-5)' }}>
       <div className="section-title" style={{ marginBottom: 'var(--sp-4)', display: 'flex', alignItems: 'center', gap: 8 }}>
          <Eye size={20} style={{ color: 'var(--accent)' }} /> 
          Shadow Autopilot (Zero-Trust Gen)
       </div>
       <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', marginBottom: 'var(--sp-5)', lineHeight: 1.6 }}>
         Put the WAF into a silent profiling mode. It will learn the structure of your application's legitimate traffic, 
         including API routes, parameters, and payload limits. After the observation window, you can export a precise 
         Zero-Trust JSON Schema to enforce perfect security devoid of false positives.
       </p>

       <div style={{ background: 'var(--bg-raised)', padding: 'var(--sp-4)', borderRadius: 'var(--radius-md)', marginBottom: 'var(--sp-5)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 'var(--sp-2)' }}>
            <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>Autopilot Status: 
              <strong style={{ color: isLearning ? 'var(--warning)' : 'var(--text-muted)', marginLeft: 8 }}>
                {isLearning ? 'OBSERVING TRAFFIC' : 'IDLE'}
              </strong>
            </span>
          </div>
          {isLearning && (
            <>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', marginBottom: 4 }}>
                 <span>Progress: {status?.progress_percent || 0}%</span>
                 <span>{status?.hours_remaining || 0} Hours Remaining</span>
              </div>
              <div style={{ width: '100%', height: 6, background: 'rgba(255,255,255,0.1)', borderRadius: 3, overflow: 'hidden' }}>
                 <div style={{ width: `${status?.progress_percent || 0}%`, height: '100%', background: 'var(--warning)', transition: 'width 1s' }} />
              </div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', marginTop: 8 }}>
                 Endpoints Discovered: <strong style={{color: 'var(--accent)'}}>{status?.endpoints_learned || 0}</strong>
              </div>
            </>
          )}
       </div>

       <div style={{ display: 'flex', gap: 'var(--sp-4)', alignItems: 'flex-end' }}>
          <div style={{ flex: 1 }}>
             <label style={{ display: 'block', fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 6 }}>Observation Window (Hours)</label>
             <input type="number" className="input" value={hours} onChange={e => setHours(e.target.value)} disabled={isLearning} style={{ width: '100%' }} />
          </div>
          <button className="btn btn-primary" style={{ flex: 1, justifyContent: 'center' }} onClick={() => startMut.mutate(hours)} disabled={isLearning || startMut.isPending}>
             <PlayCircle size={16} /> 
             {startMut.isPending ? 'Starting...' : isLearning ? 'Learning Active' : 'Start Autopilot'}
          </button>
          <button className="btn btn-secondary" style={{ flex: 1, justifyContent: 'center' }} onClick={() => exportMut.mutate()} disabled={exportMut.isPending || status?.endpoints_learned === 0}>
             <Download size={16} />
             Export Schema
          </button>
       </div>
    </div>
  );
}

// ── Main Layout ──────────────────────────────────────────

export default function WAF() {
  const [activeTab, setActiveTab] = useState('overview');
  const queryClient = useQueryClient();

  const { data: status } = useQuery({
    queryKey: ['waf-status'], queryFn: () => wafApi.status().then(r => r.data),
    retry: false, refetchInterval: 5000
  });

  const toggleMut = useMutation({
    mutationFn: ({ feature, enabled }) => wafApi.toggleWaapFeature(feature, enabled),
    onSuccess: () => queryClient.invalidateQueries(['waf-status'])
  });

  const handleToggle = (feature, enabled) => {
    toggleMut.mutate({ feature, enabled });
  };

  const tabs = [
    { id: 'overview', label: 'Dashboard & Monitor', icon: <Activity size={16} /> },
    { id: 'waap', label: 'WAAP Shields', icon: <Shield size={16} /> },
    { id: 'autopilot', label: 'Shadow Autopilot', icon: <Eye size={16} /> },
  ];

  return (
    <div className="module-page">
      <div className="page-header">
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Globe2 size={24} style={{ color: 'var(--accent)' }} />
            Enterprise WAAP Engine
          </h1>
          <p className="page-subtitle">Web Application & API Protection • AI-Driven Security</p>
        </div>
        <span className={`badge ${status?.waf_enabled ? 'badge-success' : 'badge-danger'}`} style={{ fontSize: 'var(--text-sm)', padding: '6px 12px' }}>
          {status?.waf_enabled ? '● ENGINE ACTIVE' : '○ DISABLED'}
        </span>
      </div>

      <div style={{ 
        display: 'flex', gap: 'var(--sp-4)', marginBottom: 'var(--sp-6)',
        borderBottom: '1px solid var(--border)', paddingBottom: 'var(--sp-2)'
      }}>
        {tabs.map(t => (
          <button
            key={t.id}
            onClick={() => setActiveTab(t.id)}
            style={{
              padding: 'var(--sp-2) var(--sp-4)', background: 'transparent', 
              border: 'none', color: activeTab === t.id ? 'var(--accent)' : 'var(--text-secondary)',
              borderBottom: activeTab === t.id ? '2px solid var(--accent)' : '2px solid transparent',
              cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8,
              fontSize: 'var(--text-sm)', fontWeight: activeTab === t.id ? 600 : 400,
              transition: 'all 0.2s'
            }}
          >
            {t.icon} {t.label}
          </button>
        ))}
      </div>

      {activeTab === 'overview' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--sp-5)' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-5)' }}>
             <div className="card" style={{ padding: 'var(--sp-5)' }}>
                <div className="section-title" style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 'var(--sp-4)' }}>
                   <Zap size={18} style={{ color: 'var(--accent)' }} /> System Modules
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--sp-4)' }}>
                   <div className="info-item">
                     <span className="info-item-label">Deployment Mode</span>
                     <span className="info-item-value">{status?.mode?.toUpperCase() || 'ENFORCE'}</span>
                   </div>
                   <div className="info-item">
                     <span className="info-item-label">NLP Deep Learning</span>
                     <span className="info-item-value" style={{ color: status?.features?.nlp ? 'var(--success)' : 'var(--text-muted)' }}>
                        {status?.features?.nlp ? 'Online' : 'Offline'}
                     </span>
                   </div>
                   <div className="info-item">
                     <span className="info-item-label">Behavioral Bot Det.</span>
                     <span className="info-item-value" style={{ color: status?.features?.bot_detection ? 'var(--success)' : 'var(--text-muted)' }}>
                        {status?.features?.bot_detection ? 'Online' : 'Offline'}
                     </span>
                   </div>
                   <div className="info-item">
                     <span className="info-item-label">Graph Neural Network</span>
                     <span className="info-item-value" style={{ color: status?.features?.gnn ? 'var(--success)' : 'var(--text-muted)' }}>
                        {status?.features?.gnn ? 'Online' : 'Offline'}
                     </span>
                   </div>
                </div>
             </div>
             
             <div className="card" style={{ padding: 'var(--sp-5)' }}>
                <div className="section-title" style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 'var(--sp-3)' }}>
                   <Server size={18} style={{ color: 'var(--accent)' }} /> Protected Ports
                </div>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                   {status?.monitored_ports?.map(p => (
                      <span key={p} className="badge badge-info" style={{ fontSize: 13, padding: '4px 10px' }}>Port {p}</span>
                   )) || <span className="badge badge-info">80, 443</span>}
                </div>
             </div>
          </div>
          <LiveMonitor />
        </div>
      )}

      {activeTab === 'waap' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(300px, 1fr) 1fr', gap: 'var(--sp-5)' }}>
          <div className="card" style={{ overflow: 'hidden' }}>
            <div className="section-header" style={{ borderBottom: '1px solid var(--border)' }}>
              <div className="section-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <ShieldAlert size={17} style={{ color: 'var(--accent)' }} /> 
                Feature Control Panel
              </div>
            </div>
            
            <ToggleSwitch label="API Schema Validation" enabled={status?.features?.waap_api_schema} onChange={v => handleToggle('api_schema', v)} />
            <ToggleSwitch label="Advanced Fingerprinting" enabled={status?.features?.waap_fingerprint} onChange={v => handleToggle('fingerprint', v)} />
            <ToggleSwitch label="Account Takeover (ATO) Protection" enabled={status?.features?.waap_ato} onChange={v => handleToggle('ato', v)} />
            <ToggleSwitch label="Adaptive Rate Limiter" enabled={status?.features?.waap_rate_limit} onChange={v => handleToggle('rate_limit', v)} />
            
            {/* The python GNN toggle already exists in python via `/gnn/toggle`, we reuse handleToggle for simplicity if unified upstream later, but right now GNN uses `/gnn/toggle`. Let's just hook it up via wafApi.toggleGnn */}
            <ToggleSwitch label="GNN (Graph Neural Network)" enabled={status?.features?.gnn} onChange={v => wafApi.toggleGnn(v).then(()=>queryClient.invalidateQueries(['waf-status']))} />
          </div>

          <div className="card" style={{ padding: 'var(--sp-5)' }}>
             <div className="section-title" style={{ marginBottom: 'var(--sp-4)', display: 'flex', alignItems: 'center', gap: 8 }}>
                <AlertTriangle size={17} style={{ color: 'var(--warning)' }} /> Rate Limit Configurations
             </div>
             <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', marginBottom: 'var(--sp-5)' }}>
               Manage the thresholds for the Adaptive Rate Limiter. If adaptive is enabled, the GNN will dynamically shift these limits based on server load and bot aggressiveness.
             </p>
             {/* Read-only representation for now, or minimal inputs */}
             <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'var(--bg-raised)', padding: 'var(--sp-3)', borderRadius: 'var(--radius-sm)' }}>
                   <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>Global Rate Limit (req/min)</span>
                   <span className="badge badge-info">2000</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'var(--bg-raised)', padding: 'var(--sp-3)', borderRadius: 'var(--radius-sm)' }}>
                   <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>IP Rate Limit (req/min)</span>
                   <span className="badge badge-info">150</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'var(--bg-raised)', padding: 'var(--sp-3)', borderRadius: 'var(--radius-sm)' }}>
                   <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>User Segment Rate Limit (req/min)</span>
                   <span className="badge badge-info">500</span>
                </div>
             </div>
          </div>
        </div>
      )}

      {activeTab === 'autopilot' && (
         <div style={{ maxWidth: 800 }}>
            <ShadowAutopilot />
         </div>
      )}

    </div>
  );
}
