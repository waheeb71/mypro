/**
 * EmailLogs.jsx — Paginated inspection logs table.
 */
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { emailApi } from '../../../services/api';
import { RefreshCw, Filter, List, AlertCircle } from 'lucide-react';

const DECISION_COLORS = { 'allow': 'var(--success)', 'quarantine': '#ffb400', 'block': 'var(--danger)' };

export default function EmailLogs() {
  const [filter, setFilter] = useState('');
  
  const { data: logs = [], isFetching, refetch } = useQuery({
    queryKey: ['email_logs', filter],
    queryFn: () => emailApi.logs(filter ? { decision: filter } : {}).then(r => r.data),
    refetchInterval: 15000,
  });

  return (
    <div className="card" style={{ overflow: 'hidden' }}>
      <div style={{ padding: 'var(--sp-4) var(--sp-5)', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h3 style={{ display: 'flex', alignItems: 'center', gap: 8, fontWeight: 700 }}>
          <List size={18} style={{ color: 'var(--accent)' }} /> Inspection Logs
        </h3>
        <div style={{ display: 'flex', gap: 'var(--sp-3)', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, background: 'var(--bg-raised)', padding: '4px 12px', borderRadius: 20 }}>
            <Filter size={14} style={{ color: 'var(--text-muted)' }} />
            <select style={{ background: 'transparent', border: 'none', color: 'var(--text-primary)', outline: 'none', fontSize: '0.85rem' }} value={filter} onChange={e => setFilter(e.target.value)}>
              <option value="">All Decisions</option>
              <option value="allow">Allowed</option>
              <option value="quarantine">Quarantined</option>
              <option value="block">Blocked</option>
            </select>
          </div>
          <button className="icon-btn" onClick={() => refetch()} title="Refresh"><RefreshCw size={15} className={isFetching ? "spin" : ""} /></button>
        </div>
      </div>

      <div style={{ overflowX: 'auto', maxHeight: 600, overflowY: 'auto' }}>
        <table className="table" style={{ width: '100%' }}>
          <thead style={{ position: 'sticky', top: 0, background: 'var(--bg-raised)', zIndex: 1 }}>
            <tr>
              <th>Time</th>
              <th>Sender</th>
              <th>Subject</th>
              <th>Risk</th>
              <th>Detections</th>
              <th>Decision</th>
            </tr>
          </thead>
          <tbody>
            {logs.length === 0 && (
              <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 'var(--sp-8)' }}>No logs found.</td></tr>
            )}
            {logs.map(log => (
              <tr key={log.id} style={{ borderTop: '1px solid var(--border)' }}>
                <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                  {new Date(log.inspected_at).toLocaleString()}
                </td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>
                  {log.sender || '<unknown>'}
                  <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: 2 }}>{log.src_ip}</div>
                </td>
                <td style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: '0.9rem' }}>
                  {log.subject || '(No Subject)'}
                </td>
                <td>
                  <span style={{ fontWeight: 700, color: log.risk_score > 0.7 ? 'var(--danger)' : log.risk_score > 0.4 ? 'var(--warning)' : 'var(--success)' }}>
                    {log.risk_score.toFixed(2)}
                  </span>
                </td>
                <td>
                  <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                    {log.is_phishing && <span className="tag" style={{ background: 'rgba(239,68,68,0.1)', color: 'var(--danger)', fontSize: '0.7rem' }}>Phishing</span>}
                    {log.is_spam && <span className="tag" style={{ background: 'rgba(245,158,11,0.1)', color: 'var(--warning)', fontSize: '0.7rem' }}>Spam</span>}
                    {log.has_malicious_url && <span className="tag" style={{ background: 'rgba(239,68,68,0.1)', color: 'var(--danger)', fontSize: '0.7rem' }}>Bad URL</span>}
                    {log.brand_spoof && <span className="tag" style={{ background: 'rgba(168,85,247,0.1)', color: '#a855f7', fontSize: '0.7rem' }}>Spoof: {log.brand_spoof}</span>}
                  </div>
                </td>
                <td>
                  <span className="badge" style={{ background: `${DECISION_COLORS[log.decision]}22`, color: DECISION_COLORS[log.decision], border: `1px solid ${DECISION_COLORS[log.decision]}44`, textTransform: 'capitalize' }}>
                    {log.decision}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
