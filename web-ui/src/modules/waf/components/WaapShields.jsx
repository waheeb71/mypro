import { ShieldAlert, AlertTriangle } from 'lucide-react';
import FeatureToggle from './FeatureToggle';

export default function WaapShields({ status, handleToggle, handleGnnToggle }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(300px, 1fr) 1fr', gap: 'var(--sp-5)' }}>
      <div className="card" style={{ overflow: 'hidden' }}>
        <div className="section-header" style={{ borderBottom: '1px solid var(--border)' }}>
          <div className="section-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <ShieldAlert size={17} style={{ color: 'var(--accent)' }} /> 
            Feature Control Panel
          </div>
        </div>
        
        <FeatureToggle label="API Schema Validation" enabled={status?.features?.waap_api_schema} onChange={v => handleToggle('api_schema', v)} />
        <FeatureToggle label="Advanced Fingerprinting" enabled={status?.features?.waap_fingerprint} onChange={v => handleToggle('fingerprint', v)} />
        <FeatureToggle label="Account Takeover (ATO) Protection" enabled={status?.features?.waap_ato} onChange={v => handleToggle('ato', v)} />
        <FeatureToggle label="Adaptive Rate Limiter" enabled={status?.features?.waap_rate_limit} onChange={v => handleToggle('rate_limit', v)} />
        
        <FeatureToggle label="GNN (Graph Neural Network)" enabled={status?.features?.gnn} onChange={v => handleGnnToggle(v)} />
        <FeatureToggle label="Self-Learning Engine" enabled={status?.features?.self_learning} onChange={v => handleToggle('self_learning', v)} />
        <FeatureToggle label="Intent-Proving Deception Engine" enabled={status?.features?.deception_engine} onChange={v => handleToggle('deception_engine', v)} />
      </div>

      <div className="card" style={{ padding: 'var(--sp-5)' }}>
         <div className="section-title" style={{ marginBottom: 'var(--sp-4)', display: 'flex', alignItems: 'center', gap: 8 }}>

            <AlertTriangle size={17} style={{ color: 'var(--warning)' }} /> Rate Limit Configurations
         </div>
         <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', marginBottom: 'var(--sp-5)' }}>
           Manage the thresholds for the Adaptive Rate Limiter. If adaptive is enabled, the GNN will dynamically shift these limits based on server load and bot aggressiveness.
         </p>
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
  );
}
