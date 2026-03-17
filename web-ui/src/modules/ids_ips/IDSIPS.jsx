import { useQuery } from '@tanstack/react-query';
import { Activity, AlertTriangle, Clock, TrendingUp, ShieldAlert } from 'lucide-react';
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

export default function IDSIPS() {
  const { data: alerts = DEMO_ALERTS } = useQuery({
    queryKey: ['ids-alerts'],
    queryFn: () => idsApi.alerts().then(r => r.data),
    retry: false,
    placeholderData: DEMO_ALERTS,
    refetchInterval: 5000,
  });

  return (
    <div className="module-page">
      <div className="page-header">
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Activity size={24} style={{ color: 'var(--accent)' }} />
            IDS / IPS
          </h1>
          <p className="page-subtitle">Intrusion Detection & Prevention — Snort/Suricata Signatures</p>
        </div>
        <div style={{ display: 'flex', gap: 'var(--sp-3)' }}>
          <span className="badge badge-danger" style={{ fontSize: 'var(--text-sm)' }}>4 Critical</span>
          <span className="badge badge-warning" style={{ fontSize: 'var(--text-sm)' }}>2 Warning</span>
        </div>
      </div>

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
    </div>
  );
}
