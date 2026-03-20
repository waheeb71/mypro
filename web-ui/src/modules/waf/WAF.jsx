import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Globe2, Shield, Activity, Eye, Play } from 'lucide-react';
import { wafApi } from '../../services/api';

// Components
import OverviewTab from './components/OverviewTab';
import WaapShields from './components/WaapShields';
import ShadowAutopilot from './components/ShadowAutopilot';
export default function WAF() {
  const [activeTab, setActiveTab] = useState('overview');
  const queryClient = useQueryClient();
  const { data: status } = useQuery({
    queryKey: ['waf-status'], queryFn: () => wafApi.status().then(r => r.data),
    retry: false, refetchInterval: 5000
  });

  const toggleMut = useMutation({
    mutationFn: ({ feature, enabled }) => wafApi.toggleWaapFeature(feature, enabled),
    onSuccess: () => queryClient.invalidateQueries(['waf-status'])
  });

  const handleToggle = (feature, enabled) => toggleMut.mutate({ feature, enabled });
  const handleGnnToggle = (enabled) => wafApi.toggleGnn(enabled).then(() => queryClient.invalidateQueries(['waf-status']));

  const tabs = [
    { id: 'overview', label: 'Dashboard & Monitor', icon: <Activity size={16} /> },
    { id: 'waap', label: 'WAAP Shields', icon: <Shield size={16} /> },
    { id: 'autopilot', label: 'Shadow Autopilot', icon: <Eye size={16} /> },
  ];

  return (
    <div className="module-page">
      <div className="page-header">
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Globe2 size={24} style={{ color: 'var(--accent)' }} />
            Enterprise WAAP Engine
          </h1>
          <p className="page-subtitle">Web Application & API Protection • AI-Driven Security</p>
        </div>
        <span className={`badge ${status?.waf_enabled ? 'badge-success' : 'badge-danger'}`} style={{ fontSize: 'var(--text-sm)', padding: '6px 12px' }}>
          {status?.waf_enabled ? '● ENGINE ACTIVE' : '○ DISABLED'}
        </span>
      </div>

      <div style={{ 
        display: 'flex', gap: 'var(--sp-4)', marginBottom: 'var(--sp-6)',
        borderBottom: '1px solid var(--border)', paddingBottom: 'var(--sp-2)'
      }}>
        {tabs.map(t => (
          <button
            key={t.id}
            onClick={() => setActiveTab(t.id)}
            style={{
              padding: 'var(--sp-2) var(--sp-4)', background: 'transparent', 
              border: 'none', color: activeTab === t.id ? 'var(--accent)' : 'var(--text-secondary)',
              borderBottom: activeTab === t.id ? '2px solid var(--accent)' : '2px solid transparent',
              cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8,
              fontSize: 'var(--text-sm)', fontWeight: activeTab === t.id ? 600 : 400,
              transition: 'all 0.2s'
            }}
          >
            {t.icon} {t.label}
          </button>
        ))}
      </div>

      {activeTab === 'overview' && <OverviewTab status={status} />}
      {activeTab === 'waap' && <WaapShields status={status} handleToggle={handleToggle} handleGnnToggle={handleGnnToggle} />}
      {activeTab === 'autopilot' && <div style={{ maxWidth: 800 }}><ShadowAutopilot /></div>}
    </div>
  );
}
