import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { mlCoreApi } from '../../services/api';
import { BrainCircuit, Save, RefreshCw } from 'lucide-react';

export default function MLCoreSettings() {
  const qc = useQueryClient();

  const { data: config, isLoading } = useQuery({
    queryKey: ['ml-core-config'],
    queryFn: () => mlCoreApi.config().then(r => r.data)
  });

  const updateMut = useMutation({
    mutationFn: (newCfg) => mlCoreApi.updateConfig(newCfg),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['ml-core-config'] });
      alert('ML Core Configuration Updated!');
    }
  });

  if (isLoading) return <div className="settings-loading"><RefreshCw className="spin" /> Loading AI engine parameters...</div>;

  const handleSubmit = (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const newConfig = {
      correlation_threshold: parseFloat(fd.get('correlation_threshold')),
      time_window_seconds: parseInt(fd.get('time_window_seconds')),
      enable_deep_learning: fd.get('enable_deep_learning') === 'on'
    };
    updateMut.mutate(newConfig);
  };

  return (
    <div style={{ padding: 'var(--sp-4)' }}>
      <div style={{ marginBottom: 'var(--sp-6)' }}>
        <h2 style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--accent)' }}>
          <BrainCircuit size={20} /> Machine Learning Core API
        </h2>
        <p style={{ color: 'var(--text-secondary)' }}>Configure global correlation thresholds for the Predictive AI model.</p>
      </div>

      <form onSubmit={handleSubmit} className="card" style={{ padding: 'var(--sp-5)', maxWidth: '600px' }}>
        <div style={{ marginBottom: 'var(--sp-4)' }}>
          <label style={{ display: 'block', marginBottom: '8px', color: 'var(--text-primary)' }}>Correlation Threshold (0.0 to 1.0)</label>
          <input 
            name="correlation_threshold" 
            type="number" 
            step="0.05" 
            min="0" max="1"
            className="settings-input settings-number" 
            defaultValue={config?.correlation_threshold || 0.85} 
            required 
          />
          <p className="settings-nested-hint" style={{ marginTop: 4 }}>Lowering this makes the AI more sensitive (may increase false positives).</p>
        </div>

        <div style={{ marginBottom: 'var(--sp-4)' }}>
          <label style={{ display: 'block', marginBottom: '8px', color: 'var(--text-primary)' }}>Time Window Memory (Seconds)</label>
          <input 
            name="time_window_seconds" 
            type="number" 
            className="settings-input settings-number" 
            defaultValue={config?.time_window_seconds || 300} 
            required 
          />
          <p className="settings-nested-hint" style={{ marginTop: 4 }}>How long the context API remembers previous events for correlation caching.</p>
        </div>

        <div style={{ marginBottom: 'var(--sp-5)' }}>
          <label className="settings-toggle" style={{ display: 'inline-flex', alignItems: 'center', gap: 10 }}>
            <span style={{ color: 'var(--text-primary)' }}>Enable Deep Learning Offloading Engine</span>
            <input 
              name="enable_deep_learning" 
              type="checkbox" 
              defaultChecked={config?.enable_deep_learning ?? true} 
            />
            <span className="slider"></span>
          </label>
        </div>

        <button type="submit" className="btn btn-primary" disabled={updateMut.isPending}>
          <Save size={16} /> Save ML configuration
        </button>
      </form>
    </div>
  );
}
