/**
 * EmailStats.jsx — Visual charts and decision breakdowns.
 */
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip as RechartsTooltip, BarChart, Bar, XAxis, YAxis } from 'recharts';
import { BarChart2, ShieldAlert } from 'lucide-react';

const COLORS = { allow: 'var(--success)', quarantine: '#ffb400', block: 'var(--danger)' };

export default function EmailStats({ stats }) {
  const decisions = [
    { name: 'Allow', value: stats.decision_breakdown?.allow || 0, fill: COLORS.allow },
    { name: 'Quarantine', value: stats.decision_breakdown?.quarantine || 0, fill: COLORS.quarantine },
    { name: 'Block', value: stats.decision_breakdown?.block || 0, fill: COLORS.block },
  ].filter(d => d.value > 0);

  const topSenders = (stats.top_blocked_senders || []).map(s => ({
    name: s.sender.length > 25 ? s.sender.slice(0, 23) + '…' : s.sender,
    full: s.sender,
    count: s.count,
  }));

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: 'var(--sp-5)' }}>
      {/* ── Decision Breakdown ── */}
      <div className="card" style={{ padding: 'var(--sp-6)', display: 'flex', flexDirection: 'column' }}>
        <h3 style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 'var(--sp-5)', fontWeight: 700 }}>
          <ShieldAlert size={18} style={{ color: 'var(--accent)' }} /> Decision Breakdown
        </h3>
        {decisions.length === 0 ? (
          <div style={{ textAlign: 'center', color: 'var(--text-muted)', margin: 'auto' }}>No data available</div>
        ) : (
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie data={decisions} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={60} outerRadius={80} stroke="none">
                  {decisions.map((entry, index) => <Cell key={`cell-${index}`} fill={entry.fill} />)}
                </Pie>
                <RechartsTooltip contentStyle={{ background: 'var(--bg-raised)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 13 }} itemStyle={{ color: 'var(--text-primary)' }} />
              </PieChart>
            </ResponsiveContainer>
            <div style={{ display: 'flex', gap: 'var(--sp-4)', marginTop: 'var(--sp-4)' }}>
              {decisions.map(d => (
                <div key={d.name} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span style={{ display: 'inline-block', width: 10, height: 10, borderRadius: '50%', background: d.fill }} />
                  <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>{d.name} ({d.value})</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* ── Top Blocked Senders ── */}
      <div className="card" style={{ padding: 'var(--sp-6)' }}>
        <h3 style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 'var(--sp-5)', fontWeight: 700 }}>
          <BarChart2 size={18} style={{ color: 'var(--danger)' }} /> Top Blocked Senders
        </h3>
        {topSenders.length === 0 ? (
          <div style={{ textAlign: 'center', color: 'var(--text-muted)', margin: 'auto', padding: 'var(--sp-8)' }}>No blocked senders yet.</div>
        ) : (
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={topSenders} layout="vertical" margin={{ left: 10, right: 30 }}>
              <XAxis type="number" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="name" width={180} tick={{ fill: 'var(--text-primary)', fontSize: 11, fontFamily: 'var(--font-mono)' }} axisLine={false} tickLine={false} />
              <RechartsTooltip cursor={{ fill: 'var(--bg-raised)' }} contentStyle={{ background: 'var(--bg-overlay)', border: '1px solid var(--border)', borderRadius: 8 }} />
              <Bar dataKey="count" fill="var(--danger)" radius={[0, 4, 4, 0]} barSize={20} />
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
