import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { optimizerApi } from '../../services/api';
import {
  BrainCircuit, Zap, Trash2, GitMerge, RefreshCw,
  CheckCircle, AlertTriangle, Info, ArrowUpDown, ShieldOff,
} from 'lucide-react';

/* ── Maps: s.action → UI config ────────────────────────────── */
const ACTION_CONFIG = {
  delete: {
    Icon: Trash2,
    iconColor: 'var(--text-secondary)',
    borderColor: 'var(--text-secondary)',
    badgeClass: 'badge-info',
    label: 'DEAD RULE',
    canAccept: true,
  },
  shadowed: {
    Icon: ShieldOff,
    iconColor: 'var(--error-color)',
    borderColor: 'var(--error-color)',
    badgeClass: 'badge-danger',
    label: 'SHADOWED RULE',
    canAccept: true,
  },
  merge: {
    Icon: GitMerge,
    iconColor: 'var(--info)',
    borderColor: 'var(--info)',
    badgeClass: 'badge-info',
    label: 'MERGE CANDIDATE',
    canAccept: false,   // merge requires manual admin work, not auto-delete
  },
  reorder: {
    Icon: ArrowUpDown,
    iconColor: 'var(--accent)',
    borderColor: 'var(--accent)',
    badgeClass: 'badge-warn',
    label: 'REORDER SUGGESTION',
    canAccept: false,
  },
};

/* ── Confidence → color ─────────────────────────────────────── */
const confidenceColor = (c) =>
  c >= 0.9 ? 'var(--error-color)' : c >= 0.75 ? 'var(--warning)' : 'var(--info)';

/* ── Unique key per suggestion ──────────────────────────────── */
const suggestionKey = (s) => {
  if (s.rule_id != null) return `${s.action}-${s.rule_id}`;
  if (s.rules)           return `${s.action}-${s.rules.join('_')}`;
  if (s.new_order)       return `${s.action}-reorder`;
  return `${s.action}-${Math.random()}`;
};

export default function Optimizer() {
  const qc = useQueryClient();
  const [dismissed, setDismissed] = useState(new Set());
  const [accepted, setAccepted]   = useState(new Set());

  const { data: report, isFetching, refetch } = useQuery({
    queryKey: ['optimizer-report'],
    queryFn: () => optimizerApi.analyze().then(r => r.data),
    enabled: false,      // Manual trigger only — Human-in-the-Loop
    retry: false,
  });

  const applyMut = useMutation({
    mutationFn: (ids) => optimizerApi.apply(ids),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['optimizer-report'] });
      setAccepted(new Set());
      setDismissed(new Set());
      alert('Optimization applied. Firewall rules updated successfully.');
    },
    onError: (e) => alert('Apply failed: ' + e.message),
  });

  const allSuggestions = report?.suggestions || [];
  const suggestions = allSuggestions.filter(s => !dismissed.has(suggestionKey(s)));

  // Collect rule IDs to delete from accepted "delete" or "shadowed" suggestions
  const acceptedDeleteIds = allSuggestions
    .filter(s => accepted.has(suggestionKey(s)) && (s.action === 'delete' || s.action === 'shadowed') && s.rule_id != null)
    .map(s => s.rule_id);

  const toggleAccept = (key) =>
    setAccepted(prev => { const n = new Set(prev); n.has(key) ? n.delete(key) : n.add(key); return n; });

  const dismiss = (key) =>
    setDismissed(prev => new Set([...prev, key]));

  return (
    <div style={{ padding: 'var(--sp-5)' }}>

      {/* ── Header ── */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--sp-6)', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <h2 style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--accent)', margin: 0 }}>
            <BrainCircuit size={22} /> Smart Policy Optimizer
          </h2>
          <p style={{ color: 'var(--text-secondary)', marginTop: 4, marginBottom: 0 }}>
            Mathematically analyzes your ruleset for shadowed rules, dead policies, and merge opportunities.
            <strong style={{ color: 'var(--accent)' }}> You approve every change.</strong>
          </p>
        </div>
        <button className="btn btn-primary" onClick={() => refetch()} disabled={isFetching}>
          {isFetching ? <><RefreshCw size={14} className="spin" /> Analyzing…</> : <><Zap size={14} /> Run Analysis</>}
        </button>
      </div>

      {/* ── Stats Bar ── */}
      {report && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 'var(--sp-4)', marginBottom: 'var(--sp-6)' }}>
          {[
            { label: 'Rules Analyzed', value: report.total_rules_analyzed, color: 'var(--text-primary)' },
            { label: 'Issues Found',   value: report.total_suggestions,    color: suggestions.length > 0 ? 'var(--warning)' : 'var(--success)' },
            { label: 'Calc Time',      value: `${report.calculation_time_ms} ms`, color: 'var(--info)' },
            { label: 'Accepted',       value: accepted.size,               color: 'var(--success)' },
          ].map(({ label, value, color }) => (
            <div key={label} className="card" style={{ padding: 'var(--sp-4)', textAlign: 'center' }}>
              <div style={{ fontSize: '1.8rem', fontWeight: 700, color, fontFamily: 'var(--font-mono)' }}>{value}</div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', marginTop: 4 }}>{label}</div>
            </div>
          ))}
        </div>
      )}

      {/* ── Empty States ── */}
      {!report && !isFetching && (
        <div style={{ textAlign: 'center', padding: '60px 0', color: 'var(--text-secondary)' }}>
          <BrainCircuit size={48} style={{ opacity: 0.2, marginBottom: 16 }} />
          <p>Click <strong>Run Analysis</strong> to mathematically scan the active ruleset.</p>
        </div>
      )}
      {suggestions.length === 0 && report && (
        <div style={{ textAlign: 'center', padding: '60px 0', color: 'var(--success)' }}>
          <CheckCircle size={48} style={{ marginBottom: 16 }} />
          <p style={{ margin: 0, fontWeight: 600 }}>Ruleset is fully optimized. No issues found!</p>
        </div>
      )}

      {/* ── Suggestion Cards ── */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-3)' }}>
        {suggestions.map(s => {
          const key = suggestionKey(s);
          const cfg = ACTION_CONFIG[s.action] || ACTION_CONFIG.delete;
          const { Icon, iconColor, borderColor, badgeClass, label, canAccept } = cfg;
          const isAccepted = accepted.has(key);

          return (
            <div key={key} className="card" style={{
              padding: 'var(--sp-4) var(--sp-5)',
              borderLeft: `4px solid ${borderColor}`,
              opacity: isAccepted ? 0.65 : 1,
              display: 'flex', alignItems: 'flex-start', gap: 'var(--sp-4)',
              transition: 'opacity 0.2s',
            }}>
              <Icon size={20} style={{ color: iconColor, flexShrink: 0, marginTop: 3 }} />

              <div style={{ flex: 1, minWidth: 0 }}>
                {/* Badges row */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 6 }}>
                  <span className={`badge ${badgeClass}`} style={{ fontSize: 10 }}>{label}</span>

                  {/* Rule ID chips */}
                  {s.rule_id != null && (
                    <code style={{ fontSize: 11, background: 'var(--bg-overlay)', padding: '1px 6px', borderRadius: 3 }}>
                      Rule #{s.rule_id}
                    </code>
                  )}
                  {s.shadowed_by != null && (
                    <code style={{ fontSize: 11, background: 'var(--bg-overlay)', padding: '1px 6px', borderRadius: 3, color: 'var(--error-color)' }}>
                      shadowed by #{s.shadowed_by}
                    </code>
                  )}
                  {s.rules && (
                    <code style={{ fontSize: 11, background: 'var(--bg-overlay)', padding: '1px 6px', borderRadius: 3 }}>
                      Rules #{s.rules.join(', #')}
                    </code>
                  )}

                  {/* Confidence indicator */}
                  <span style={{
                    marginLeft: 'auto', fontSize: 10, fontFamily: 'var(--font-mono)',
                    color: confidenceColor(s.confidence), fontWeight: 600,
                  }}>
                    {Math.round(s.confidence * 100)}% confidence
                  </span>
                </div>

                {/* Reason text */}
                <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-primary)', lineHeight: 1.6 }}>
                  {s.reason}
                </p>

                {/* Reorder preview */}
                {s.new_order && (
                  <div style={{ marginTop: 8, fontSize: 11, color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                    New order: [{s.new_order.join(' → ')}]
                  </div>
                )}
              </div>

              {/* Action buttons */}
              <div style={{ display: 'flex', gap: 8, flexShrink: 0, alignItems: 'center' }}>
                {canAccept && (
                  <button
                    className={`btn ${isAccepted ? 'btn-primary' : 'btn-ghost'}`}
                    style={{ padding: '4px 10px', fontSize: 12 }}
                    onClick={() => toggleAccept(key)}
                    title={isAccepted ? 'Click to deselect' : 'Accept this suggestion'}
                  >
                    {isAccepted ? <><CheckCircle size={12} /> Accepted</> : 'Accept'}
                  </button>
                )}
                <button
                  className="btn btn-ghost"
                  style={{ padding: '4px 8px', color: 'var(--text-secondary)', fontSize: 13 }}
                  onClick={() => dismiss(key)}
                  title="Dismiss"
                >✕</button>
              </div>
            </div>
          );
        })}
      </div>

      {/* ── Sticky Apply Bar ── */}
      {accepted.size > 0 && (
        <div style={{
          position: 'sticky', bottom: 16, marginTop: 'var(--sp-5)',
          background: 'var(--bg-card)', border: '1px solid var(--accent)',
          borderRadius: 8, padding: 'var(--sp-4) var(--sp-5)',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          boxShadow: '0 4px 20px rgba(0,0,0,0.5)',
        }}>
          <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>
            <CheckCircle size={16} style={{ verticalAlign: 'middle', marginRight: 6, color: 'var(--success)' }} />
            {accepted.size} suggestion{accepted.size > 1 ? 's' : ''} accepted
            {acceptedDeleteIds.length > 0 && (
              <span style={{ color: 'var(--text-secondary)', fontSize: 12, marginLeft: 8 }}>
                ({acceptedDeleteIds.length} rule{acceptedDeleteIds.length > 1 ? 's' : ''} will be deleted)
              </span>
            )}
          </span>
          <button
            className="btn btn-primary"
            disabled={applyMut.isPending || acceptedDeleteIds.length === 0}
            onClick={() => {
              if (window.confirm(
                `Delete ${acceptedDeleteIds.length} rule(s): [${acceptedDeleteIds.join(', ')}]?\n\nThis will update base.yaml. The engine will hot-reload.`
              )) {
                applyMut.mutate(acceptedDeleteIds);
              }
            }}
          >
            {applyMut.isPending ? 'Applying…' : `Apply ${acceptedDeleteIds.length} Deletion(s) →`}
          </button>
        </div>
      )}
    </div>
  );
}
