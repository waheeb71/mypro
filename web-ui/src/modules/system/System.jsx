import { useQuery } from '@tanstack/react-query';
import { Settings, Cpu, HardDrive, Zap, RefreshCw, CheckCircle } from 'lucide-react';
import { systemApi } from '../../services/api';

const DEMO = {
  status: 'operational', uptime_seconds: 842640,
  cpu_usage: 18.4, memory_usage: 41.2,
  active_connections: 2481, rules_count: 6,
  ml_models_loaded: true, ha_state: 'MASTER',
};

function uptime(s) {
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return `${d}d ${h}h ${m}m`;
}

function GaugeBar({ value, color }) {
  return (
    <div style={{ background: 'var(--bg-overlay)', borderRadius: 4, height: 8, overflow: 'hidden' }}>
      <div style={{ width: `${value}%`, height: '100%', background: color, borderRadius: 4, transition: 'width 0.5s' }} />
    </div>
  );
}

export default function System() {
  const { data: status = DEMO } = useQuery({
    queryKey: ['system-status'], queryFn: () => systemApi.status().then(r => r.data),
    retry: false, placeholderData: DEMO, refetchInterval: 4000,
  });
  const { data: modules } = useQuery({
    queryKey: ['modules'], queryFn: () => systemApi.modules().then(r => r.data),
    retry: false,
  });

  return (
    <div className="module-page">
      <div className="page-header">
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Settings size={24} style={{ color: 'var(--accent)' }} /> System
          </h1>
          <p className="page-subtitle">Health, Uptime, HA State, Module Management</p>
        </div>
        <span className="badge badge-success" style={{ fontSize: 'var(--text-sm)' }}>
          <CheckCircle size={13} /> {status?.status?.toUpperCase()}
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--sp-5)' }}>
        {/* Resource Usage */}
        <div className="card" style={{ padding: 'var(--sp-5)' }}>
          <div className="section-title" style={{ marginBottom: 'var(--sp-5)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <Cpu size={17} style={{ color: 'var(--accent)' }} /> Resource Usage
          </div>
          {[
            { label: 'CPU', value: status?.cpu_usage, color: 'var(--accent)' },
            { label: 'Memory', value: status?.memory_usage, color: 'var(--warning)' },
          ].map(({ label, value, color }) => (
            <div key={label} style={{ marginBottom: 'var(--sp-4)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 'var(--sp-2)' }}>
                <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>{label}</span>
                <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color }}>{value?.toFixed(1)}%</span>
              </div>
              <GaugeBar value={value} color={color} />
            </div>
          ))}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--sp-4)', marginTop: 'var(--sp-4)' }}>
            {[
              { l: 'Uptime',      v: uptime(status?.uptime_seconds || 0) },
              { l: 'HA State',    v: status?.ha_state || 'MASTER' },
              { l: 'Connections', v: status?.active_connections?.toLocaleString() },
              { l: 'ML Models',   v: status?.ml_models_loaded ? '✓ Loaded' : '✗ Missing' },
            ].map(({ l, v }) => (
              <div key={l} className="info-item">
                <span className="info-item-label">{l}</span>
                <span className="info-item-value">{v}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Module States */}
        <div className="card" style={{ overflow: 'hidden' }}>
          <div className="section-header">
            <div className="section-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Zap size={17} style={{ color: 'var(--warning)' }} /> Modules
            </div>
          </div>
          {(modules ? Object.entries(modules) : [
            ['firewall', { enabled: true }], ['waf', { enabled: true }],
            ['ids_ips', { enabled: true }], ['vpn', { enabled: false }],
            ['dns_security', { enabled: true }], ['email_security', { enabled: true }],
            ['ssl_inspection', { enabled: false }], ['proxy', { enabled: true }],
          ]).map(([name, cfg]) => (
            <div key={name} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: 'var(--sp-3) var(--sp-5)', borderBottom: '1px solid var(--border)' }}>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>{name}</span>
              <span className={`badge ${cfg?.enabled !== false ? 'badge-success' : 'badge-info'}`}>
                {cfg?.enabled !== false ? 'Active' : 'Off'}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Update Controls */}
      <div className="card" style={{ padding: 'var(--sp-5)' }}>
        <div className="section-title" style={{ marginBottom: 'var(--sp-4)', display: 'flex', alignItems: 'center', gap: 8 }}>
          <HardDrive size={17} style={{ color: 'var(--info)' }} /> OTA Update
        </div>
        <div style={{ display: 'flex', gap: 'var(--sp-3)' }}>
          <button className="btn btn-ghost" onClick={() => systemApi.checkUpdate()}>
            <RefreshCw size={14} /> Check for Updates
          </button>
          <button className="btn btn-primary" onClick={() => systemApi.applyUpdate({ branch: 'main', run_migrations: true, restart_service: true })}>
            Install Update
          </button>
        </div>
      </div>
    </div>
  );
}
