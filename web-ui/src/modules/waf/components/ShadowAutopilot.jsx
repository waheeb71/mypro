import { Eye, Download, PlayCircle } from 'lucide-react';
import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { wafApi } from '../../../services/api';

export default function ShadowAutopilot() {
  const [hours, setHours] = useState(72);
  const queryClient = useQueryClient();

  const { data: status } = useQuery({
    queryKey: ['waf-shadow-status'], queryFn: () => wafApi.shadowModeStatus().then(r => r.data),
    refetchInterval: 3000,
  });

  const startMut = useMutation({ 
    mutationFn: (h) => wafApi.startShadowMode(h),
    onSuccess: () => {
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

  return (
    <div className="card" style={{ padding: 'var(--sp-5)' }}>
       <div className="section-title" style={{ marginBottom: 'var(--sp-4)', display: 'flex', alignItems: 'center', gap: 8 }}>
          <Eye size={20} style={{ color: 'var(--accent)' }} /> 
          Shadow Autopilot (Zero-Trust Gen)
       </div>
       <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', marginBottom: 'var(--sp-5)', lineHeight: 1.6 }}>
         Put the WAF into a silent profiling mode. It will learn the structure of your application's legitimate traffic, 
         including API routes, parameters, and payload limits. After the observation window, you can export a precise 
         Zero-Trust JSON Schema to enforce perfect security devoid of false positives.
       </p>

       <div style={{ background: 'var(--bg-raised)', padding: 'var(--sp-4)', borderRadius: 'var(--radius-md)', marginBottom: 'var(--sp-5)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 'var(--sp-2)' }}>
            <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>Autopilot Status: 
              <strong style={{ color: isLearning ? 'var(--warning)' : 'var(--text-muted)', marginLeft: 8 }}>
                {isLearning ? 'OBSERVING TRAFFIC' : 'IDLE'}
              </strong>
            </span>
          </div>
          {isLearning && (
            <>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', marginBottom: 4 }}>
                 <span>Progress: {status?.progress_percent || 0}%</span>
                 <span>{status?.hours_remaining || 0} Hours Remaining</span>
              </div>
              <div style={{ width: '100%', height: 6, background: 'rgba(255,255,255,0.1)', borderRadius: 3, overflow: 'hidden' }}>
                 <div style={{ width: `${status?.progress_percent || 0}%`, height: '100%', background: 'var(--warning)', transition: 'width 1s' }} />
              </div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', marginTop: 8 }}>
                 Endpoints Discovered: <strong style={{color: 'var(--accent)'}}>{status?.endpoints_learned || 0}</strong>
              </div>
            </>
          )}
       </div>

       <div style={{ display: 'flex', gap: 'var(--sp-4)', alignItems: 'flex-end' }}>
          <div style={{ flex: 1 }}>
             <label style={{ display: 'block', fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 6 }}>Observation Window (Hours)</label>
             <input type="number" className="input" value={hours} onChange={e => setHours(e.target.value)} disabled={isLearning} style={{ width: '100%' }} />
          </div>
          <button className="btn btn-primary" style={{ flex: 1, justifyContent: 'center' }} onClick={() => startMut.mutate(hours)} disabled={isLearning || startMut.isPending}>
             <PlayCircle size={16} /> 
             {startMut.isPending ? 'Starting...' : isLearning ? 'Learning Active' : 'Start Autopilot'}
          </button>
          <button className="btn btn-secondary" style={{ flex: 1, justifyContent: 'center' }} onClick={() => exportMut.mutate()} disabled={exportMut.isPending || status?.endpoints_learned === 0}>
             <Download size={16} />
             Export Schema
          </button>
       </div>
    </div>
  );
}
