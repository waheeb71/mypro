import { useQuery } from '@tanstack/react-query';
import { Settings, Cpu, HardDrive, Zap, RefreshCw, CheckCircle, Server } from 'lucide-react';
import { systemApi, interfacesApi, haApi } from '../../services/api';

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
  const { data: interfaces = [] } = useQuery({
    queryKey: ['system-interfaces'], queryFn: () => interfacesApi.list().then(r => r.data),
    retry: false, placeholderData: []
  });

  return (
    <div className="module-page" style={{ paddingBottom: '2rem' }}>
      <div className="page-header">
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Settings size={24} style={{ color: 'var(--accent)' }} /> System
          </h1>
          <p className="page-subtitle">Health, Uptime, Hardware Interfaces, Module Management</p>
        </div>
        <span className="badge badge-success" style={{ fontSize: 'var(--text-sm)' }}>
          <CheckCircle size={13} /> {status?.status?.toUpperCase()}
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)', gap: 'var(--sp-5)' }}>
        {/* Resource Usage & Uptime */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-5)' }}>
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
                  { l: 'Connections', v: status?.active_connections?.toLocaleString() || '0' },
                  { l: 'ML Models',   v: status?.ml_models_loaded ? '✓ Loaded' : '✗ Missing' },
                ].map(({ l, v }) => (
                  <div key={l} className="info-item">
                    <span className="info-item-label">{l}</span>
                    <span className="info-item-value">{v}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Hardware Interfaces Table */}
            <div className="card" style={{ padding: 'var(--sp-5)' }}>
              <div className="section-title" style={{ marginBottom: 'var(--sp-4)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Zap size={17} style={{ color: 'var(--info)' }} /> Hardware Interfaces
                </div>
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>Active: {interfaces.filter(i => i.is_up).length}</span>
              </div>
              
              <div style={{ overflowX: 'auto', maxHeight: '300px' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: 'var(--text-sm)' }}>
                      <thead>
                          <tr style={{ borderBottom: '1px solid var(--border)', color: 'var(--text-secondary)' }}>
                              <th style={{ padding: '8px 0' }}>Port</th>
                              <th>IP Address</th>
                              <th>Speed</th>
                              <th>Target Role</th>
                          </tr>
                      </thead>
                      <tbody>
                          {interfaces.length > 0 ? interfaces.map((intf) => (
                              <tr key={intf.name} style={{ borderBottom: '1px solid var(--border)' }}>
                                  <td style={{ padding: '10px 0', fontFamily: 'var(--font-mono)', fontWeight: 500 }}>
                                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                          <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: intf.is_up ? 'var(--success)' : 'var(--error-color)' }} />
                                          {intf.name}
                                      </div>
                                  </td>
                                  <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>{intf.ip_address || '-'}</td>
                                  <td>{intf.speed > 0 ? `${intf.speed} Mbps` : 'N/A'}</td>
                                  <td>
                                      <select 
                                         defaultValue={intf.role}
                                         onChange={(e) => interfacesApi.assign({ port: intf.name, role: e.target.value })}
                                         style={{ background: 'var(--bg-overlay)', border: '1px solid var(--border)', color: 'var(--text-primary)', padding: '2px 6px', borderRadius: '4px', fontSize: '11px' }}>
                                          <option value="UNASSIGNED">Unassigned</option>
                                          <option value="WAN">WAN</option>
                                          <option value="LAN">LAN</option>
                                          <option value="DMZ">DMZ</option>
                                          <option value="MGMT">MGMT</option>
                                          <option value="HA">HA Sync</option>
                                      </select>
                                  </td>
                              </tr>
                          )) : (
                              <tr><td colSpan="4" style={{ padding: '12px 0', textAlign: 'center', color: 'var(--text-secondary)' }}>Loading hardware interfaces...</td></tr>
                          )}
                      </tbody>
                  </table>
              </div>
            </div>
        </div>

        {/* Module States (Right Column) */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-5)' }}>
            <div className="card" style={{ overflow: 'hidden' }}>
              <div className="section-header">
                <div className="section-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Zap size={17} style={{ color: 'var(--warning)' }} /> Modules Pipeline Status
                </div>
              </div>
              <div style={{ maxHeight: 'calc(100% - 44px)', overflowY: 'auto' }}>
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

      {/* HA Sync Controls */}
      <div className="card" style={{ padding: 'var(--sp-5)', marginTop: 'var(--sp-5)' }}>
        <div className="section-title" style={{ marginBottom: 'var(--sp-4)', display: 'flex', alignItems: 'center', gap: 8 }}>
          <Server size={17} style={{ color: 'var(--success)' }} /> High Availability (HA) Sync
        </div>
        <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', marginBottom: 'var(--sp-4)' }}>
            Force a manual state synchronization across the active cluster. This will mirror active connections, user identity maps, and AI memory.
        </p>
        <div style={{ display: 'flex', gap: 'var(--sp-3)' }}>
          <button className="btn btn-primary" onClick={() => haApi.sync().then(() => alert('HA Sync Triggered Successfully')).catch(e => alert('HA Sync Failed: ' + e.message))}>
            <RefreshCw size={14} /> Force Sync Now
          </button>
        </div>
      </div>
    </div>
  );
}
