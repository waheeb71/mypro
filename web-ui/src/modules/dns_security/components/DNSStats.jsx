/**
 * DNSStats.jsx — Bar chart of top-blocked domains + detailed hit table.
 */
import { BarChart2, AlertTriangle } from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from 'recharts';

const CHART_COLORS = ['#ff4d6a', '#ff8c42', '#ffb400', '#4fc3f7', '#81c995', '#cf6cc9', '#4dd0e1', '#aed581', '#f06292', '#ffcc02'];

function ActionBadge({ action }) {
  return (
    <span className={`badge ${action === 'BLOCK' ? 'badge-danger' : 'badge-success'}`}>{action}</span>
  );
}

export default function DNSStats({ stats }) {
  const barData = (stats.top_blocked || []).slice(0, 8).map(r => ({
    name: r.domain_pattern.length > 20 ? r.domain_pattern.slice(0, 18) + '…' : r.domain_pattern,
    count: r.blocked_count,
    action: r.action,
  }));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-6)' }}>

      {/* ── Bar Chart ── */}
      <div className="card" style={{ padding: 'var(--sp-6)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 'var(--sp-5)', fontWeight: 700, fontSize: '1.1rem' }}>
          <BarChart2 size={20} style={{ color: 'var(--accent)' }} /> Top Blocked Domains
        </div>
        {barData.length === 0 ? (
          <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 'var(--sp-8)' }}>
            No block events recorded yet.
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={barData} layout="vertical" margin={{ left: 10, right: 30 }}>
              <XAxis type="number" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis
                type="category" dataKey="name" width={160}
                tick={{ fill: 'var(--text-primary)', fontSize: 11, fontFamily: 'var(--font-mono)' }}
                axisLine={false} tickLine={false}
              />
              <Tooltip
                contentStyle={{ background: 'var(--bg-raised)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }}
                itemStyle={{ color: 'var(--danger)' }}
                labelStyle={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}
              />
              <Bar dataKey="count" radius={[0, 6, 6, 0]}>
                {barData.map((_, i) => <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>

      {/* ── Top-Hit Table ── */}
      <div className="card" style={{ overflow: 'hidden' }}>
        <div style={{ padding: 'var(--sp-4) var(--sp-5)', borderBottom: '1px solid var(--border)', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
          <AlertTriangle size={16} style={{ color: 'var(--danger)' }} /> Top Hit Rules (Last 10)
        </div>
        <table className="table" style={{ width: '100%' }}>
          <thead style={{ background: 'var(--bg-raised)' }}>
            <tr>
              <th style={{ padding: '12px 16px' }}>#</th>
              <th style={{ padding: '12px 16px' }}>Domain Pattern</th>
              <th style={{ padding: '12px 16px' }}>Action</th>
              <th style={{ padding: '12px 16px', textAlign: 'right' }}>Blocked Count</th>
              <th style={{ padding: '12px 16px' }}>Last Triggered</th>
            </tr>
          </thead>
          <tbody>
            {(stats.top_blocked || []).length === 0 && (
              <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 'var(--sp-6)' }}>No data yet.</td></tr>
            )}
            {(stats.top_blocked || []).map((r, i) => (
              <tr key={i} style={{ borderTop: '1px solid var(--border)' }}>
                <td style={{ padding: '12px 16px', color: 'var(--text-muted)', fontWeight: 700 }}>{i + 1}</td>
                <td style={{ padding: '12px 16px', fontFamily: 'var(--font-mono)', fontSize: '0.88rem', fontWeight: 600 }}>{r.domain_pattern}</td>
                <td style={{ padding: '12px 16px' }}><ActionBadge action={r.action} /></td>
                <td style={{ padding: '12px 16px', textAlign: 'right', fontWeight: 800, color: 'var(--danger)', fontSize: '1.1rem' }}>{r.blocked_count}</td>
                <td style={{ padding: '12px 16px', fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                  {r.last_triggered ? new Date(r.last_triggered).toLocaleString() : '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
