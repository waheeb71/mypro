/**
 * DNSSettings.jsx — Engine toggles, numeric parameters, and TLD editor.
 */
import { Settings, Zap, SlidersHorizontal } from 'lucide-react';

function Toggle({ checked, onChange }) {
  return (
    <label className="toggle">
      <input type="checkbox" checked={!!checked} onChange={onChange} />
      <span className="toggle-slider" />
    </label>
  );
}

const ENGINES = [
  {
    key: 'enable_dga_detection',
    label: 'DGA Detection',
    desc: 'Detect Domain Generation Algorithm domains using Shannon Entropy analysis',
    icon: '🎲',
  },
  {
    key: 'enable_tunneling_detection',
    label: 'DNS Tunneling Detection',
    desc: 'Block DNS tunneling tools (iodine, dnscat2) via label-length & query-type heuristics',
    icon: '🚇',
  },
  {
    key: 'enable_threat_intel',
    label: 'Threat Intelligence',
    desc: 'Match domains against embedded and external IOC feeds',
    icon: '🔍',
  },
  {
    key: 'enable_rate_limiting',
    label: 'Rate Limiting',
    desc: 'Flag source IPs exceeding the configured queries-per-minute threshold',
    icon: '⏱️',
  },
  {
    key: 'enable_tld_blocking',
    label: 'Suspicious TLD Blocking',
    desc: 'Block queries to high-risk TLDs (.tk, .ml, .onion, .xyz …)',
    icon: '🚫',
  },
];

export default function DNSSettings({ config, updateConfig }) {
  const mutate = (key, val) => updateConfig.mutate({ ...config, [key]: val });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-6)' }}>

      {/* ── Module Master Switch ── */}
      <div className="card" style={{ padding: 'var(--sp-6)', borderTop: '4px solid var(--accent)' }}>
        <h3 style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 'var(--sp-5)', fontWeight: 700, fontSize: '1.15rem' }}>
          <Settings size={20} style={{ color: 'var(--accent)' }} /> Module Status
        </h3>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: 'var(--sp-4)', background: 'var(--bg-raised)', borderRadius: 'var(--radius)' }}>
          <div>
            <div style={{ fontWeight: 700 }}>DNS Security Engine — Master Switch</div>
            <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginTop: 4 }}>
              Enable or disable the entire DNS inspection pipeline
            </div>
          </div>
          <Toggle checked={config.is_active} onChange={() => mutate('is_active', !config.is_active)} />
        </div>
      </div>

      {/* ── Detection Engines ── */}
      <div className="card" style={{ padding: 'var(--sp-6)' }}>
        <h3 style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 'var(--sp-5)', fontWeight: 700, fontSize: '1.15rem' }}>
          <Zap size={20} style={{ color: '#ffb400' }} /> Detection Engines
        </h3>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-1)' }}>
          {ENGINES.map(({ key, label, desc, icon }) => (
            <div key={key} style={{
              display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              padding: 'var(--sp-4)', borderRadius: 'var(--radius)',
              background: config[key] ? 'rgba(59,130,246,0.04)' : 'transparent',
              border: `1px solid ${config[key] ? 'rgba(59,130,246,0.15)' : 'transparent'}`,
              transition: 'background 0.2s, border 0.2s',
            }}>
              <div style={{ display: 'flex', gap: 12, alignItems: 'flex-start' }}>
                <span style={{ fontSize: '1.4rem', lineHeight: 1 }}>{icon}</span>
                <div>
                  <div style={{ fontWeight: 700 }}>{label}</div>
                  <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginTop: 3 }}>{desc}</div>
                </div>
              </div>
              <Toggle checked={config[key]} onChange={() => mutate(key, !config[key])} />
            </div>
          ))}
        </div>
      </div>

      {/* ── Numeric Parameters ── */}
      <div className="card" style={{ padding: 'var(--sp-6)' }}>
        <h3 style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 'var(--sp-5)', fontWeight: 700, fontSize: '1.15rem' }}>
          <SlidersHorizontal size={20} style={{ color: 'var(--success)' }} /> Engine Parameters
        </h3>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-5)' }}>

          {[
            { key: 'dga_entropy_threshold', label: 'DGA Entropy Threshold', desc: 'Shannon entropy score above which a domain is flagged as DGA (default: 3.8)', type: 'number', step: 0.1, min: 2, max: 5 },
            { key: 'tunneling_query_threshold', label: 'Tunneling Query Threshold', desc: 'Max repeated queries to the same domain before flagging DNS tunneling', type: 'number', step: 5, min: 10, max: 500 },
            { key: 'rate_limit_per_minute', label: 'Rate Limit (queries / min)', desc: 'Maximum DNS queries per minute per source IP before alerting', type: 'number', step: 10, min: 10, max: 1000 },
          ].map(({ key, label, desc, ...inputProps }) => (
            <div key={key} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: 'var(--sp-4)', background: 'var(--bg-raised)', borderRadius: 'var(--radius)' }}>
              <div>
                <div style={{ fontWeight: 700 }}>{label}</div>
                <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginTop: 3 }}>{desc}</div>
              </div>
              <input
                className="input" style={{ width: 100 }}
                defaultValue={config[key]}
                key={config[key]}
                onBlur={e => {
                  const val = inputProps.step < 1 ? parseFloat(e.target.value) : parseInt(e.target.value);
                  mutate(key, val);
                }}
                onChange={() => {}}
                {...inputProps}
              />
            </div>
          ))}

          {/* Suspicious TLDs editor */}
          <div style={{ padding: 'var(--sp-4)', background: 'var(--bg-raised)', borderRadius: 'var(--radius)' }}>
            <div style={{ fontWeight: 700, marginBottom: 4 }}>Suspicious TLDs</div>
            <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: 'var(--sp-3)' }}>
              Comma-separated list of top-level domains to block (e.g. .tk,.onion,.xyz)
            </div>
            <input
              className="input"
              style={{ fontFamily: 'var(--font-mono)', fontSize: '0.88rem', width: '100%' }}
              defaultValue={config.suspicious_tlds}
              key={config.suspicious_tlds}
              onBlur={e => mutate('suspicious_tlds', e.target.value)}
              onChange={() => {}}
            />
          </div>
        </div>
      </div>

    </div>
  );
}
