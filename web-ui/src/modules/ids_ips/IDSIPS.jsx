import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Activity, AlertTriangle, Clock, TrendingUp, ShieldAlert, Settings, Zap } from 'lucide-react';
import { idsApi } from '../../services/api';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';

const DEMO_ALERTS = [
  { id: 1, sig_id: 2010935, category: 'SQL Injection',       severity: 'critical', src_ip: '45.142.120.x', dst_ip: '10.0.0.15', proto: 'TCP', time: '00:38:12' },
  { id: 2, sig_id: 2001219, category: 'SSH Brute Force',     severity: 'critical', src_ip: '195.206.x.x',  dst_ip: '10.0.0.1',  proto: 'TCP', time: '00:37:50' },
  { id: 3, sig_id: 2100498, category: 'ICMP Flood',          severity: 'warning',  src_ip: '89.234.x.x',   dst_ip: '10.0.0.2',  proto: 'ICMP', time: '00:37:11' },
  { id: 4, sig_id: 2013504, category: 'DNS Exfiltration',    severity: 'warning',  src_ip: '103.56.x.x',   dst_ip: '8.8.8.8',   proto: 'UDP', time: '00:36:45' },
  { id: 5, sig_id: 2019401, category: 'Shellcode Detected',  severity: 'critical', src_ip: '5.101.x.x',    dst_ip: '10.0.0.25', proto: 'TCP', time: '00:35:22' },
  { id: 6, sig_id: 2016025, category: 'CVE-2021-44228 Log4j',severity: 'critical', src_ip: '91.121.x.x',   dst_ip: '10.0.0.3',  proto: 'TCP', time: '00:34:08' },
];

const TIMELINE = [
  { t: '00:33', alerts: 3 }, { t: '00:34', alerts: 7 }, { t: '00:35', alerts: 5 },
  { t: '00:36', alerts: 12 }, { t: '00:37', alerts: 9 }, { t: '00:38', alerts: 6 },
  { t: '00:39', alerts: 4 },
];

function SeverityBadge({ s }) {
  const cls = s === 'critical' ? 'badge-danger' : s === 'warning' ? 'badge-warning' : 'badge-info';
  return <span className={`badge ${cls}`}>{s}</span>;
}

const DEFAULT_CONFIG = {
  is_active: true,
  mode: 'blocking',
  enable_l3_anomaly: true,
  enable_l7_dpi: true,
  deception_enabled: true,
  anomaly_threshold: 0.5,
};

export default function IDSIPS() {
  const [tab, setTab] = useState('alerts');
  const qc = useQueryClient();

  const { data: alerts = DEMO_ALERTS } = useQuery({
    queryKey: ['ids-alerts'],
    queryFn: () => idsApi.alerts().then(r => r.data),
    retry: false,
    placeholderData: DEMO_ALERTS,
    refetchInterval: 5000,
  });

  const { data: config = DEFAULT_CONFIG } = useQuery({
    queryKey: ['ids-config'],
    queryFn: () => idsApi.getConfig().then(r => r.data),
    retry: false,
    placeholderData: DEFAULT_CONFIG,
  });

  const updateConfigMutation = useMutation({
    mutationFn: (d) => idsApi.updateConfig(d),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ids-config'] }),
  });

  const cfg = config ?? DEFAULT_CONFIG;

  return (
    <div className="module-page">
      <div className="page-header">
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Activity size={24} style={{ color: 'var(--accent)' }} />
            IDS / IPS
          </h1>
          <p className="page-subtitle">Intrusion Detection &amp; Prevention — Snort/Suricata Signatures</p>
        </div>
        <div style={{ display: 'flex', gap: 'var(--sp-3)' }}>
          <span className="badge badge-danger" style={{ fontSize: 'var(--text-sm)' }}>4 Critical</span>
          <span className="badge badge-warning" style={{ fontSize: 'var(--text-sm)' }}>2 Warning</span>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 'var(--sp-2)', borderBottom: '1px solid var(--border)', paddingBottom: 'var(--sp-2)' }}>
        {['alerts', 'settings'].map(t => (
          <button key={t} onClick={() => setTab(t)}
            className={`btn ${tab === t ? 'btn-primary' : 'btn-ghost'}`}
            style={{ textTransform: 'capitalize' }}>
            {t === 'settings' ? <><Settings size={14} /> Settings</> : t}
          </button>
        ))}
      </div>

      {tab === 'alerts' && (
        <>
          {/* Timeline Chart */}
          <div className="card" style={{ padding: 'var(--sp-5)' }}>
            <div className="section-title" style={{ marginBottom: 'var(--sp-4)', display: 'flex', alignItems: 'center', gap: 8 }}>
              <TrendingUp size={17} style={{ color: 'var(--accent)' }} /> Alert Timeline — Last 7 min
            </div>
            <ResponsiveContainer width="100%" height={160}>
              <AreaChart data={TIMELINE}>
                <defs>
                  <linearGradient id="alertGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#ff4d6a" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#ff4d6a" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="t" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip
                  contentStyle={{ background: 'var(--bg-raised)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }}
                  itemStyle={{ color: 'var(--danger)' }}
                  labelStyle={{ color: 'var(--text-secondary)' }}
                />
                <Area type="monotone" dataKey="alerts" stroke="#ff4d6a" fill="url(#alertGrad)" strokeWidth={2} dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Alerts Table */}
          <div className="card" style={{ overflow: 'hidden' }}>
            <div className="section-header">
              <div className="section-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <ShieldAlert size={17} style={{ color: 'var(--danger)' }} /> Signature Alerts
              </div>
              <span className="tag">{alerts.length} events</span>
            </div>
            <table className="table">
              <thead>
                <tr>
                  <th>Sig ID</th>
                  <th>Category</th>
                  <th>Severity</th>
                  <th>Source IP</th>
                  <th>Dest IP</th>
                  <th>Proto</th>
                  <th><Clock size={12} /> Time</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map(a => (
                  <tr key={a.id}>
                    <td><span className="tag">{a.sig_id}</span></td>
                    <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{a.category}</td>
                    <td><SeverityBadge s={a.severity} /></td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--danger)' }}>{a.src_ip}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>{a.dst_ip}</td>
                    <td><span className="tag">{a.proto}</span></td>
                    <td style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>{a.time}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {tab === 'settings' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
          {/* Standard Config */}
          <div className="card" style={{ padding: 'var(--sp-6)' }}>
            <h3 style={{ marginBottom: 'var(--sp-5)', fontWeight: 700 }}>Engine Configuration</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-5)' }}>
              {/* Engine Mode */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div style={{ fontWeight: 700 }}>Engine Mode</div>
                  <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>Switch between passive monitoring and active blocking</div>
                </div>
                <select className="input" style={{ width: 160 }}
                  value={cfg.mode}
                  onChange={e => updateConfigMutation.mutate({ ...cfg, mode: e.target.value })}>
                  <option value="blocking">Blocking</option>
                  <option value="monitoring">Monitoring only</option>
                </select>
              </div>

              {/* L3 Anomaly */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div style={{ fontWeight: 700 }}>L3 Anomaly Detection</div>
                  <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>Isolation Forest model for low-level network anomalies</div>
                </div>
                <label className="toggle">
                  <input type="checkbox" checked={cfg.enable_l3_anomaly}
                    onChange={() => updateConfigMutation.mutate({ ...cfg, enable_l3_anomaly: !cfg.enable_l3_anomaly })} />
                  <span className="toggle-slider" />
                </label>
              </div>

              {/* L7 DPI */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div style={{ fontWeight: 700 }}>L7 Deep Packet Inspection</div>
                  <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>XGBoost/RF payload classifier for application-layer attacks</div>
                </div>
                <label className="toggle">
                  <input type="checkbox" checked={cfg.enable_l7_dpi}
                    onChange={() => updateConfigMutation.mutate({ ...cfg, enable_l7_dpi: !cfg.enable_l7_dpi })} />
                  <span className="toggle-slider" />
                </label>
              </div>

              {/* Anomaly Threshold */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div style={{ fontWeight: 700 }}>Anomaly Block Threshold</div>
                  <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>ML anomaly score above which to block (0.0 – 1.0)</div>
                </div>
                <input className="input" type="number" style={{ width: 100 }} step={0.05} min={0} max={1}
                  value={cfg.anomaly_threshold}
                  onChange={e => updateConfigMutation.mutate({ ...cfg, anomaly_threshold: parseFloat(e.target.value) })} />
              </div>
            </div>
          </div>

          {/* Causal Deception Engine Card */}
          <div className="card" style={{ padding: 'var(--sp-6)', border: '1px solid rgba(255,180,0,0.3)', background: 'linear-gradient(135deg, var(--bg-card), rgba(255,180,0,0.04))' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-3)', marginBottom: 'var(--sp-5)' }}>
              <div style={{ padding: 8, background: 'rgba(255,180,0,0.15)', borderRadius: '50%' }}>
                <Zap size={18} style={{ color: '#ffb400' }} />
              </div>
              <div>
                <h3 style={{ color: '#ffb400', margin: 0 }}>Causal Deception Engine</h3>
                <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: 0 }}>Patent-Pending Active Defense — Network Causal Traps</p>
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: 'var(--sp-4)', background: 'var(--bg-raised)', borderRadius: 'var(--radius)', border: '1px solid rgba(255,180,0,0.15)' }}>
              <div>
                <div style={{ fontWeight: 700 }}>Network Banner Tarpits</div>
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 4 }}>
                  When an attacker triggers a signature or ML anomaly, instead of silently dropping the packet,
                  the engine responds with a dynamically generated fake protocol banner (Fake SSH, Fake MySQL)
                  to capture the attacker's tools and prove malicious intent with 100% certainty.
                </div>
              </div>
              <label className="toggle" style={{ marginLeft: 'var(--sp-5)', flexShrink: 0 }}>
                <input
                  type="checkbox"
                  checked={cfg.deception_enabled ?? true}
                  onChange={() => updateConfigMutation.mutate({ ...cfg, deception_enabled: !cfg.deception_enabled })}
                />
                <span className="toggle-slider" />
              </label>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--sp-3)', marginTop: 'var(--sp-4)' }}>
              <div style={{ padding: 'var(--sp-3)', background: 'var(--bg-raised)', borderRadius: 'var(--radius)', border: '1px dashed rgba(255,180,0,0.2)' }}>
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 4 }}>TRAP TYPE: PORT PROBE</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: '#ffb400' }}>SSH-2.0-OpenSSH_7.2p2 (VULNERABLE)</div>
              </div>
              <div style={{ padding: 'var(--sp-3)', background: 'var(--bg-raised)', borderRadius: 'var(--radius)', border: '1px dashed rgba(255,180,0,0.2)' }}>
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 4 }}>TRAP TYPE: DB PROBE</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: '#ffb400' }}>5.5.99-MariaDB-log (HONEYPOT)</div>
              </div>
            </div>

            <div style={{ marginTop: 'var(--sp-4)', padding: 'var(--sp-3) var(--sp-4)', background: 'rgba(255,180,0,0.08)', borderRadius: 'var(--radius)', fontSize: 'var(--text-xs)', color: '#ffb400', display: 'flex', gap: 8, alignItems: 'center' }}>
              <Zap size={12} />
              <span>Powered by the <strong>Unified Causal Deception Engine</strong> — Network traps feed the same cross-module intent verification pool.</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
