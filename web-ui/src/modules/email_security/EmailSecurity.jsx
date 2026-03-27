import { useState } from 'react';
import { useEmail } from './hooks/useEmail';

import EmailHeader from './components/EmailHeader';
import EmailStats from './components/EmailStats';
import EmailLogs from './components/EmailLogs';
import EmailSettings from './components/EmailSettings';
import EmailWhitelist from './components/EmailWhitelist';

export default function EmailSecurity() {
  const [tab, setTab] = useState('overview');
  
  const { 
    status, config, stats, whitelist, 
    updateConfig, addToWhitelist, removeFromWhitelist 
  } = useEmail();

  const TABS = ['overview', 'logs', 'config', 'whitelist'];

  return (
    <div className="module-page">
      <EmailHeader status={status} stats={stats} config={config} />

      <div style={{ display: 'flex', gap: 'var(--sp-2)', borderBottom: '1px solid var(--border)', paddingBottom: 'var(--sp-2)', marginBottom: 'var(--sp-6)' }}>
        {TABS.map(t => (
          <button key={t} onClick={() => setTab(t)}
            className={`btn ${tab === t ? 'btn-primary' : 'btn-ghost'}`}
            style={{ textTransform: 'capitalize', fontSize: 'var(--text-sm)', padding: '6px 16px' }}>
            {t}
          </button>
        ))}
      </div>

      <div style={{ paddingBottom: 'var(--sp-8)' }}>
        {tab === 'overview' && <EmailStats stats={stats} />}
        {tab === 'logs' && <EmailLogs />}
        {tab === 'config' && <EmailSettings config={config} updateConfig={updateConfig} />}
        {tab === 'whitelist' && <EmailWhitelist whitelist={whitelist} addToWhitelist={addToWhitelist} removeFromWhitelist={removeFromWhitelist} />}
      </div>
    </div>
  );
}
