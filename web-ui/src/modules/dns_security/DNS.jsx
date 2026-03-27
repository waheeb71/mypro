/**
 * DNS.jsx — Entry point for the DNS Security module.
 *
 * Architecture:
 *   hooks/useDNS.js          → All React-Query data fetching & mutations
 *   components/DNSHeader.jsx  → Page header + KPI stat cards
 *   components/DNSFilterRules.jsx → CRUD table for domain filter rules
 *   components/DNSStats.jsx   → Bar chart + top-blocked table
 *   components/DNSSettings.jsx → Engine toggles + numeric params
 */
import { useState } from 'react';
import { Shield, BarChart2, Settings } from 'lucide-react';
import { useDNS } from './hooks/useDNS';
import DNSHeader        from './components/DNSHeader';
import DNSFilterRules   from './components/DNSFilterRules';
import DNSStats         from './components/DNSStats';
import DNSSettings      from './components/DNSSettings';

const TABS = [
  { key: 'rules',    label: 'Filter Rules', icon: <Shield size={15} /> },
  { key: 'stats',    label: 'Statistics',   icon: <BarChart2 size={15} /> },
  { key: 'settings', label: 'Settings',     icon: <Settings size={15} /> },
];

export default function DNS() {
  const [tab, setTab] = useState('rules');
  const { config, stats, rules, updateConfig, createRule, updateRule, deleteRule } = useDNS();

  return (
    <div className="module-page" style={{ animation: 'fadeIn 0.4s ease-out' }}>
      {/* Shared header + KPI cards */}
      <DNSHeader config={config} stats={stats} />

      {/* Tab navigation */}
      <div style={{
        display: 'flex', gap: 'var(--sp-2)',
        borderBottom: '1px solid var(--border)',
        marginBottom: 'var(--sp-5)',
        paddingBottom: 'var(--sp-2)',
      }}>
        {TABS.map(({ key, label, icon }) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={`btn ${tab === key ? 'btn-primary' : 'btn-ghost'}`}
            style={{ display: 'flex', alignItems: 'center', gap: 7 }}
          >
            {icon}{label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === 'rules' && (
        <DNSFilterRules
          rules={rules}
          createRule={createRule}
          updateRule={updateRule}
          deleteRule={deleteRule}
        />
      )}

      {tab === 'stats' && <DNSStats stats={stats} />}

      {tab === 'settings' && <DNSSettings config={config} updateConfig={updateConfig} />}

      <style>{`
        @keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
      `}</style>
    </div>
  );
}
