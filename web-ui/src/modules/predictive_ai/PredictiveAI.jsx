import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Zap, Brain, Activity, Upload, CheckCircle, XCircle,
  AlertTriangle, RefreshCw, Layers, ShieldCheck, Cpu
} from 'lucide-react';
import { aiApi } from '../../services/api';

// ── Helpers ──────────────────────────────────────────────────────────────────

function fmtDate(iso) {
  if (!iso) return 'Never';
  return new Date(iso).toLocaleString();
}

function ModelStatusBadge({ status }) {
  if (status === 'Loaded') return <span className="badge badge-success">● Loaded</span>;
  if (status?.includes('Waiting')) return <span className="badge badge-info">○ Waiting</span>;
  return <span className="badge badge-danger">{status}</span>;
}

// ── Main Component ───────────────────────────────────────────────────────────

export default function PredictiveAI() {
  const qc = useQueryClient();
  const [tab, setTab] = useState('models');
  const [uploading, setUploading] = useState(null);

  // Queries
  const { data: config } = useQuery({
    queryKey: ['ai_config'],
    queryFn: () => aiApi.config().then(r => r.data)
  });

  const { data: modelsData, isLoading: modelsLoading, refetch: refetchModels } = useQuery({
    queryKey: ['ai_models'],
    queryFn: () => aiApi.models().then(r => r.data),
    refetchInterval: 20000
  });

  const updateMutation = useMutation({
    mutationFn: (d) => aiApi.updateConfig(d),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ai_config'] })
  });

  const uploadMutation = useMutation({
    mutationFn: ({ id, file }) => aiApi.uploadModel(id, file),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['ai_models'] });
      setUploading(null);
    }
  });

  const handleFileUpload = (modelId, event) => {
    const file = event.target.files[0];
    if (file) {
      setUploading(modelId);
      uploadMutation.mutate({ id: modelId, file });
    }
  };

  const cfg = config ?? {};
  const models = modelsData?.models ?? [];

  return (
    <div className="module-page">
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Zap size={24} style={{ color: 'var(--warning)' }} /> Predictive AI
          </h1>
          <p className="page-subtitle">Deep learning and reinforcement learning agents for proactive threat mitigation</p>
        </div>
        <div style={{ display: 'flex', gap: 'var(--sp-3)', alignItems: 'center' }}>
          <button className="btn btn-ghost" onClick={() => refetchModels()}>
            <RefreshCw size={15} className={modelsLoading ? 'spin' : ''} /> Refresh
          </button>
          <span className={`badge ${cfg.is_active ? 'badge-success' : 'badge-info'}`}>
            {cfg.is_active ? '● AI Enabled' : '○ AI Disabled'}
          </span>
        </div>
      </div>

      {/* Hero Stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 'var(--sp-4)' }}>
        <div className="card" style={{ padding: 'var(--sp-5)', background: 'var(--bg-card)', borderLeft: '4px solid var(--warning)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 4 }}>ACTIVE MODELS</div>
              <div style={{ fontSize: '1.8rem', fontWeight: 800 }}>{models.filter(m => m.status === 'Loaded').length} / {models.length}</div>
            </div>
            <Brain size={32} style={{ opacity: 0.1, color: 'var(--warning)' }} />
          </div>
        </div>
        <div className="card" style={{ padding: 'var(--sp-5)', background: 'var(--bg-card)', borderLeft: '4px solid var(--accent)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 4 }}>DECISION LATENCY</div>
              <div style={{ fontSize: '1.8rem', fontWeight: 800 }}>0.42 ms</div>
            </div>
            <Activity size={32} style={{ opacity: 0.1, color: 'var(--accent)' }} />
          </div>
        </div>
        <div className="card" style={{ padding: 'var(--sp-5)', background: 'var(--bg-card)', borderLeft: '4px solid var(--success)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 4 }}>AUTONOMOUS ACTIONS</div>
              <div style={{ fontSize: '1.8rem', fontWeight: 800 }}>{cfg.auto_apply_rl_policy ? 'ON' : 'OFF'}</div>
            </div>
            <ShieldCheck size={32} style={{ opacity: 0.1, color: 'var(--success)' }} />
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 'var(--sp-2)', borderBottom: '1px solid var(--border)', paddingBottom: 'var(--sp-2)' }}>
        {['models', 'settings'].map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`btn ${tab === t ? 'btn-primary' : 'btn-ghost'}`}
            style={{ textTransform: 'capitalize' }}
          >
            {t}
          </button>
        ))}
      </div>

      {/* Content */}
      {tab === 'models' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 'var(--sp-4)' }}>
          {models.map(model => (
            <div key={model.id} className="card" style={{ padding: 'var(--sp-5)' }}>
              <div style={{ display: 'flex', gap: 'var(--sp-5)', alignItems: 'center' }}>
                <div style={{
                  width: 50, height: 50, borderRadius: 'var(--radius)',
                  background: 'var(--bg-raised)', display: 'flex', alignItems: 'center', justifyContent: 'center',
                  color: model.status === 'Loaded' ? 'var(--warning)' : 'var(--text-muted)'
                }}>
                  {model.layer?.includes('7') ? <Layers size={24} /> : <Cpu size={24} />}
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <h3 style={{ fontSize: '1.1rem', fontWeight: 700 }}>{model.name}</h3>
                    <ModelStatusBadge status={model.status} />
                  </div>
                  <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', marginBottom: 8 }}>{model.description}</div>
                  <div style={{ display: 'flex', gap: 'var(--sp-3)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    <span>Deployment: <strong style={{ color: 'var(--text-secondary)' }}>{model.layer}</strong></span>
                    <span>•</span>
                    <span>Supports: <span style={{ fontFamily: 'var(--font-mono)' }}>{model.supported_extensions?.join(', ')}</span></span>
                  </div>
                </div>
                <div style={{ textAlign: 'right', minWidth: 200 }}>
                  <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 8 }}>
                    Last Deploy: {fmtDate(model.last_updated)}
                  </div>
                  <div style={{ display: 'flex', gap: 'var(--sp-2)', justifyContent: 'flex-end' }}>
                    <label className={`btn ${uploading === model.id ? 'btn-ghost' : 'btn-ghost'}`} style={{ cursor: 'pointer', fontSize: 'var(--text-xs)' }}>
                      <input type="file" style={{ display: 'none' }} onChange={e => handleFileUpload(model.id, e)} accept={model.supported_extensions?.join(',')} />
                      {uploading === model.id ? <RefreshCw size={14} className="spin" /> : <Upload size={14} />}
                      {uploading === model.id ? 'Uploading...' : 'Update Binary'}
                    </label>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {tab === 'settings' && (
        <div className="card" style={{ padding: 'var(--sp-6)' }}>
          <h3 style={{ marginBottom: 'var(--sp-4)' }}>AI Engine Parameters</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-5)' }}>
            {[
              { id: 'is_active', label: 'Engine Master Switch', desc: 'Enable global machine learning pipeline' },
              { id: 'enable_forecaster', label: 'Attack Forecaster', desc: 'Pre-allocate resources based on predicted attack patterns' },
              { id: 'alert_on_high_risk', label: 'High-Confidence Alerts', desc: 'Trigger system alerts when AI confidence exceeds 95%' },
              { id: 'enable_rl_agent', label: 'RL Policy Tuner', desc: 'Allow Reinforcement Learning agent to optimize firewall rules' },
              { id: 'auto_apply_rl_policy', label: 'Autonomous Enforcement', desc: 'Allow AI to modify firewall policies without human approval' },
            ].map(f => (
              <div key={f.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div style={{ fontWeight: 700 }}>{f.label}</div>
                  <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{f.desc}</div>
                </div>
                <label className="toggle">
                  <input
                    type="checkbox"
                    checked={cfg[f.id]}
                    onChange={() => updateMutation.mutate({ ...cfg, [f.id]: !cfg[f.id] })}
                  />
                  <span className="toggle-slider" />
                </label>
              </div>
            ))}
          </div>

          <div style={{ marginTop: 'var(--sp-6)', padding: 'var(--sp-4)', background: 'var(--bg-overlay)', borderRadius: 'var(--radius)', borderLeft: '4px solid var(--warning)' }}>
            <div style={{ display: 'flex', gap: 'var(--sp-3)', alignItems: 'center' }}>
              <AlertTriangle size={20} style={{ color: 'var(--warning)' }} />
              <div>
                <strong style={{ display: 'block', fontSize: 'var(--text-sm)' }}>Critical Control Warning</strong>
                <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 4 }}>
                  Enabling **Autonomous Enforcement** allows the RL agent to mutate system policies.
                  Ensure models are thoroughly validated in Monitor mode first.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
