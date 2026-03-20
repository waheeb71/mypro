import { Eye, Download, PlayCircle, StopCircle, AlertTriangle, X } from 'lucide-react';
import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { wafApi } from '../../../services/api';

/* ── Confirmation Modal ──────────────────────────────── */
function ConfirmStopModal({ onConfirm, onCancel, endpointsLearned }) {
  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 1000,
      background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}>
      <div style={{
        background: 'var(--bg-secondary)', border: '1px solid var(--border)',
        borderRadius: 'var(--radius-lg)', padding: 'var(--sp-6)',
        maxWidth: 420, width: '90%', animation: 'fadeIn 0.2s ease',
        boxShadow: '0 25px 60px rgba(0,0,0,0.5)'
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--sp-4)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: 'var(--warning)' }}>
            <AlertTriangle size={22} />
            <strong style={{ fontSize: 'var(--text-base)' }}>Stop Autopilot?</strong>
          </div>
          <button onClick={onCancel} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: 4 }}>
            <X size={18} />
          </button>
        </div>

        <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', lineHeight: 1.7, marginBottom: 'var(--sp-5)' }}>
          The Autopilot will stop observing traffic. You won't lose the data already collected —
          the <strong style={{ color: 'var(--accent)' }}>{endpointsLearned} endpoints</strong> profiled so far can still be exported as a Zero-Trust Schema.
        </p>

        <div style={{ display: 'flex', gap: 'var(--sp-3)', justifyContent: 'flex-end' }}>
          <button onClick={onCancel} className="btn btn-ghost">
            Cancel
          </button>
          <button onClick={onConfirm} className="btn btn-danger" style={{ background: 'var(--danger)', color: '#fff' }}>
            <StopCircle size={15} /> Stop Learning
          </button>
        </div>
      </div>
    </div>
  );
}

/* ── Main Component ──────────────────────────────────── */
export default function ShadowAutopilot() {
  const [hours, setHours] = useState(72);
  const [showStopModal, setShowStopModal] = useState(false);
  const queryClient = useQueryClient();

  const { data: status } = useQuery({
    queryKey: ['waf-shadow-status'],
    queryFn: () => wafApi.shadowModeStatus().then(r => r.data),
    refetchInterval: 3000,
  });

  const startMut = useMutation({ 
    mutationFn: (h) => wafApi.startShadowMode(h),
    onSuccess: () => {
      queryClient.invalidateQueries(['waf-shadow-status']);
      queryClient.invalidateQueries(['waf-status']);
    }
  });

  const stopMut = useMutation({
    mutationFn: () => wafApi.stopShadowMode(),
    onSuccess: () => {
      setShowStopModal(false);
      queryClient.invalidateQueries(['waf-shadow-status']);
      queryClient.invalidateQueries(['waf-status']);
    }
  });

  const exportMut = useMutation({
    mutationFn: () => wafApi.exportShadowSchema(),
    onSuccess: (res) => {
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
  const endpointsLearned = status?.endpoints_learned || 0;

  return (
    <>
      {showStopModal && (
        <ConfirmStopModal
          onConfirm={() => stopMut.mutate()}
          onCancel={() => setShowStopModal(false)}
          endpointsLearned={endpointsLearned}
        />
      )}

      <div className="card" style={{ padding: 'var(--sp-5)' }}>
        <div className="section-title" style={{ marginBottom: 'var(--sp-4)', display: 'flex', alignItems: 'center', gap: 8 }}>
          <Eye size={20} style={{ color: 'var(--accent)' }} />
          Shadow Autopilot — Zero-Trust Schema Generator
        </div>
        <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', marginBottom: 'var(--sp-5)', lineHeight: 1.7 }}>
          Put the WAF into a silent profiling mode. It silently learns the structure of your 
          application's legitimate traffic — API routes, headers, payload sizes — then generates 
          a precise Zero-Trust JSON Schema that eliminates false positives.
        </p>

        {/* Status Card */}
        <div style={{ background: 'var(--bg-raised)', padding: 'var(--sp-4)', borderRadius: 'var(--radius-md)', marginBottom: 'var(--sp-5)', border: `1px solid ${isLearning ? 'var(--warning)' : 'var(--border)'}` }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: isLearning ? 'var(--sp-3)' : 0 }}>
            <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>
              Autopilot Status:&nbsp;
              <strong style={{ color: isLearning ? 'var(--warning)' : 'var(--text-muted)' }}>
                {isLearning ? '⏳ OBSERVING TRAFFIC' : endpointsLearned > 0 ? '✅ DONE — Ready to Export' : '○ IDLE'}
              </strong>
            </span>
            {isLearning && (
              <span className="badge badge-warning" style={{ animation: 'pulse 2s infinite' }}>
                LIVE
              </span>
            )}
          </div>

          {isLearning && (
            <>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', marginBottom: 6 }}>
                <span>Progress: <strong>{status?.progress_percent || 0}%</strong></span>
                <span>⏱ {status?.hours_remaining || 0} hours remaining</span>
              </div>
              <div style={{ width: '100%', height: 6, background: 'rgba(255,255,255,0.08)', borderRadius: 4, overflow: 'hidden', marginBottom: 10 }}>
                <div style={{
                  width: `${status?.progress_percent || 0}%`, height: '100%',
                  background: 'linear-gradient(90deg, var(--accent), var(--warning))',
                  transition: 'width 1.5s ease-in-out', borderRadius: 4
                }} />
              </div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
                🗺 Endpoints Discovered:&nbsp;
                <strong style={{ color: 'var(--accent)', fontSize: 'var(--text-sm)' }}>{endpointsLearned}</strong>
              </div>
            </>
          )}

          {!isLearning && endpointsLearned > 0 && (
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', marginTop: 8 }}>
              🗺 Endpoints Profiled:&nbsp;
              <strong style={{ color: 'var(--accent)' }}>{endpointsLearned}</strong>
              &nbsp;— Export the schema below to apply as Zero-Trust enforcement.
            </div>
          )}
        </div>

        {/* Controls */}
        <div style={{ display: 'flex', gap: 'var(--sp-3)', alignItems: 'flex-end', flexWrap: 'wrap' }}>
          {!isLearning && (
            <div style={{ flex: '0 0 140px' }}>
              <label style={{ display: 'block', fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 6 }}>
                Window (hours)
              </label>
              <input
                type="number" className="input" value={hours}
                onChange={e => setHours(Number(e.target.value))}
                min={1} max={720}
                style={{ width: '100%' }}
              />
            </div>
          )}

          {!isLearning ? (
            <button
              className="btn btn-primary"
              onClick={() => startMut.mutate(hours)}
              disabled={startMut.isPending}
              style={{ flex: 1, justifyContent: 'center' }}
            >
              <PlayCircle size={16} />
              {startMut.isPending ? 'Starting...' : 'Start Autopilot'}
            </button>
          ) : (
            <button
              className="btn btn-danger"
              onClick={() => setShowStopModal(true)}
              disabled={stopMut.isPending}
              style={{ flex: 1, justifyContent: 'center', background: 'var(--danger)', color: '#fff', border: '1px solid var(--danger)' }}
            >
              <StopCircle size={16} />
              {stopMut.isPending ? 'Stopping...' : 'Stop Learning'}
            </button>
          )}

          <button
            className="btn btn-secondary"
            onClick={() => exportMut.mutate()}
            disabled={exportMut.isPending || endpointsLearned === 0}
            style={{ flex: 1, justifyContent: 'center' }}
          >
            <Download size={16} />
            {exportMut.isPending ? 'Exporting...' : `Export Schema (${endpointsLearned} routes)`}
          </button>
        </div>
      </div>
    </>
  );
}
