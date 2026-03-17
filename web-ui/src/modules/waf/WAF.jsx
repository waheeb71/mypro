import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import {
  Globe2, Cpu, Database, Play, RefreshCw, Upload, ToggleRight,
  CheckCircle, AlertTriangle, BarChart2
} from 'lucide-react';
import { wafApi } from '../../services/api';

// Demo data
const DEMO_STATUS = {
  waf_enabled: true, mode: 'block',
  features: {
    preprocessing: true, nlp: true, bot_detection: true, gnn: true,
    anomaly: true, threat_intel: true, honeypot: false,
    waap_api_schema: true, waap_fingerprint: true, waap_ato: false, waap_rate_limit: true,
  }
};
const DEMO_GNN = {
  gnn_enabled: true, model_loaded_in_waf: true, detection_threshold: 0.72,
  session_log: { file_size_mb: 4.2, buffer_count: 1840, total_flushed: 12400 }
};
const DEMO_TRAIN = { state: 'idle', message: 'No active training job.' };

function FeatureRow({ label, enabled }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: 'var(--sp-3) var(--sp-5)', borderBottom: '1px solid var(--border)' }}>
      <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>{label}</span>
      {enabled
        ? <span className="badge badge-success"><CheckCircle size={11} /> On</span>
        : <span className="badge badge-info">Off</span>
      }
    </div>
  );
}

export default function WAF() {
  const [trainEpochs, setTrainEpochs] = useState(30);

  const { data: status = DEMO_STATUS } = useQuery({
    queryKey: ['waf-status'], queryFn: () => wafApi.status().then(r => r.data),
    retry: false, placeholderData: DEMO_STATUS,
  });
  const { data: gnn = DEMO_GNN } = useQuery({
    queryKey: ['waf-gnn-status'], queryFn: () => wafApi.gnnStatus().then(r => r.data),
    retry: false, placeholderData: DEMO_GNN, refetchInterval: 5000,
  });
  const { data: trainStatus = DEMO_TRAIN } = useQuery({
    queryKey: ['waf-training'], queryFn: () => wafApi.trainingStatus().then(r => r.data),
    retry: false, placeholderData: DEMO_TRAIN, refetchInterval: 3000,
  });

  const trainMut = useMutation({ mutationFn: () => wafApi.startTraining({ epochs: trainEpochs }) });
  const flushMut = useMutation({ mutationFn: () => wafApi.flushLogs() });

  const features = status?.features || {};

  return (
    <div className="module-page">
      <div className="page-header">
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Globe2 size={24} style={{ color: 'var(--accent)' }} />
            Web Application Firewall
          </h1>
          <p className="page-subtitle">WAAP • GNN Threat Detection • Rate Limiting</p>
        </div>
        <span className={`badge ${status?.waf_enabled ? 'badge-success' : 'badge-danger'}`} style={{ fontSize: 'var(--text-sm)' }}>
          {status?.waf_enabled ? '● Enabled' : '○ Disabled'} — {status?.mode?.toUpperCase() || 'BLOCK'}
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--sp-5)' }}>
        {/* Features */}
        <div className="card" style={{ overflow: 'hidden' }}>
          <div className="section-header">
            <div className="section-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <ToggleRight size={17} style={{ color: 'var(--accent)' }} /> Feature Flags
            </div>
          </div>
          {Object.entries(features).map(([k, v]) => (
            <FeatureRow key={k} label={k.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())} enabled={v} />
          ))}
        </div>

        {/* GNN Panel */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-5)' }}>
          <div className="card" style={{ padding: 'var(--sp-5)' }}>
            <div className="section-title" style={{ marginBottom: 'var(--sp-4)', display: 'flex', alignItems: 'center', gap: 8 }}>
              <Cpu size={17} style={{ color: 'var(--accent)' }} /> GNN Model Status
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--sp-4)' }}>
              {[
                { l: 'Model Loaded', v: gnn?.model_loaded_in_waf ? '✓ Yes' : '✗ No' },
                { l: 'GNN Enabled', v: gnn?.gnn_enabled ? '✓ Yes' : '✗ No' },
                { l: 'Threshold', v: gnn?.detection_threshold },
                { l: 'Log Size', v: `${gnn?.session_log?.file_size_mb} MB` },
                { l: 'Buffer', v: gnn?.session_log?.buffer_count?.toLocaleString() },
                { l: 'Total Flushed', v: gnn?.session_log?.total_flushed?.toLocaleString() },
              ].map(({ l, v }) => (
                <div key={l} className="info-item">
                  <span className="info-item-label">{l}</span>
                  <span className="info-item-value">{String(v)}</span>
                </div>
              ))}
            </div>
            <div style={{ display: 'flex', gap: 'var(--sp-3)', marginTop: 'var(--sp-5)' }}>
              <button className="btn btn-ghost" onClick={() => flushMut.mutate()} disabled={flushMut.isPending}>
                <Database size={14} /> Flush Logs
              </button>
              <button className="btn btn-ghost">
                <Upload size={14} /> Activate Model
              </button>
            </div>
          </div>

          {/* Training */}
          <div className="card" style={{ padding: 'var(--sp-5)' }}>
            <div className="section-title" style={{ marginBottom: 'var(--sp-4)', display: 'flex', alignItems: 'center', gap: 8 }}>
              <BarChart2 size={17} style={{ color: 'var(--warning)' }} /> GNN Training
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-3)', marginBottom: 'var(--sp-4)' }}>
              <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>Epochs:</span>
              <input
                className="input"
                type="number"
                value={trainEpochs}
                min={5} max={200}
                onChange={e => setTrainEpochs(Number(e.target.value))}
                style={{ width: 80 }}
              />
            </div>
            <div style={{
              background: 'var(--bg-raised)',
              borderRadius: 'var(--radius-md)',
              padding: 'var(--sp-3)',
              fontFamily: 'var(--font-mono)',
              fontSize: 'var(--text-xs)',
              color: 'var(--text-secondary)',
              marginBottom: 'var(--sp-4)',
              minHeight: 56,
            }}>
              {trainStatus?.state === 'running'
                ? `⚡ Training in progress… Epoch ${trainStatus?.current_epoch || '?'}/${trainEpochs}`
                : trainStatus?.message
              }
            </div>
            <button
              className="btn btn-primary"
              onClick={() => trainMut.mutate()}
              disabled={trainMut.isPending || trainStatus?.state === 'running'}
            >
              {trainMut.isPending ? <RefreshCw size={14} className="spin" /> : <Play size={14} />}
              {trainStatus?.state === 'running' ? 'Training…' : 'Start Training'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
