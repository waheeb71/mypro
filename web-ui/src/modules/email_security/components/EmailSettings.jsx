/**
 * EmailSettings.jsx — Switches, ports, and risk thresholds.
 */
import { Settings, SlidersHorizontal, Layers } from 'lucide-react';

function Toggle({ checked, onChange }) {
  return (
    <label className="toggle">
      <input type="checkbox" checked={!!checked} onChange={onChange} />
      <span className="toggle-slider" />
    </label>
  );
}

export default function EmailSettings({ config, updateConfig }) {
  const mutate = (key, val) => updateConfig.mutate({ [key]: val });
  const mutateSub = (section, key, val) => {
    const updated = { ...config[section], [key]: val };
    updateConfig.mutate({ [section]: updated });
  };

  const SCANNERS = [
    { key: 'phishing', label: 'Phishing Detector (ML/NLP)', desc: 'Detects urgency patterns, brand spoofing, and lexical anomalies', color: 'var(--accent)' },
    { key: 'url_scanner', label: 'Malicious URL Scanner', desc: 'Checks extracted links against threat intel and URL shorteners', color: 'var(--warning)' },
    { key: 'spam_filter', label: 'Spam Filter (Bilingual)', desc: 'Identifies spam keywords, hidden text, and ALL CAPS tricks', color: '#ffb400' },
    { key: 'attachment_guard', label: 'Attachment Guard', desc: 'Blocks executables and measures high-entropy packed files', color: 'var(--danger)' },
    { key: 'sender_reputation', label: 'Sender Reputation', desc: 'Validates DMARC, SPF, and checks disposable domains', color: 'var(--success)' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-6)' }}>
      {/* ── General ── */}
      <div className="card" style={{ padding: 'var(--sp-6)', borderTop: '4px solid var(--accent)' }}>
        <h3 style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 'var(--sp-5)', fontWeight: 700 }}>
          <Settings size={20} style={{ color: 'var(--accent)' }} /> Enforcement Policy
        </h3>
        <div style={{ display: 'flex', gap: 'var(--sp-4)' }}>
          <div style={{ flex: 1, padding: 'var(--sp-4)', background: 'var(--bg-raised)', borderRadius: 'var(--radius)' }}>
            <div style={{ fontWeight: 700, marginBottom: 8 }}>Inspection Mode</div>
            <select className="input" style={{ width: '100%' }} value={config.mode} onChange={e => mutate('mode', e.target.value)}>
              <option value="enforce">Enforce (Block & Quarantine)</option>
              <option value="monitor">Monitor (Log Only - No Blocks)</option>
              <option value="learning">Learning Mode (Silent)</option>
            </select>
          </div>
          <div style={{ flex: 1, padding: 'var(--sp-4)', background: 'var(--bg-raised)', borderRadius: 'var(--radius)' }}>
            <div style={{ fontWeight: 700, marginBottom: 8 }}>Monitored POP3/IMAP/SMTP Ports</div>
            <input className="input" style={{ width: '100%' }}
              defaultValue={config.monitored_ports?.join(', ')}
              onBlur={e => mutate('monitored_ports', e.target.value.split(',').map(s => parseInt(s.trim())))}
            />
          </div>
        </div>
      </div>

      {/* ── 5-Layer AI Engines ── */}
      <div className="card" style={{ padding: 'var(--sp-6)' }}>
        <h3 style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 'var(--sp-5)', fontWeight: 700 }}>
          <Layers size={20} style={{ color: 'var(--success)' }} /> Detection Engines
        </h3>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-1)' }}>
          {SCANNERS.map(({ key, label, desc, color }) => (
            <div key={key} style={{
              display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              padding: 'var(--sp-4)', borderRadius: 'var(--radius)',
              background: config[key]?.enabled ? `${color}11` : 'transparent',
              border: `1px solid ${config[key]?.enabled ? `${color}33` : 'transparent'}`,
              transition: 'background 0.2s, border 0.2s',
            }}>
              <div>
                <div style={{ fontWeight: 700, color: config[key]?.enabled ? color : 'var(--text-primary)' }}>{label}</div>
                <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginTop: 4 }}>{desc}</div>
              </div>
              <Toggle checked={config[key]?.enabled} onChange={() => mutateSub(key, 'enabled', !config[key]?.enabled)} />
            </div>
          ))}
        </div>
      </div>

      {/* ── Risk Thresholds ── */}
      <div className="card" style={{ padding: 'var(--sp-6)' }}>
        <h3 style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 'var(--sp-5)', fontWeight: 700 }}>
          <SlidersHorizontal size={20} style={{ color: '#ffb400' }} /> Risk Thresholds (0.00 – 1.00)
        </h3>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-3)' }}>
          {[
            { key: 'allow', label: 'Allow Below', desc: 'Scores below this threshold are delivered normally', color: 'var(--success)' },
            { key: 'quarantine', label: 'Quarantine At', desc: 'Scores reaching this threshold are pushed to Junk/Quarantine', color: '#ffb400' },
            { key: 'block', label: 'Firm Block At', desc: 'Scores reaching this threshold are immediately dropped via SMTP REJECT', color: 'var(--danger)' },
          ].map(({ key, label, desc, color }) => (
            <div key={key} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: 'var(--sp-4)', background: 'var(--bg-raised)', borderRadius: 'var(--radius)' }}>
              <div>
                <div style={{ fontWeight: 700, color }}>{label}</div>
                <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginTop: 3 }}>{desc}</div>
              </div>
              <input
                type="number" className="input" style={{ width: 100, textAlign: 'right', fontWeight: 700, fontFamily: 'var(--font-mono)' }}
                step="0.05" min="0" max="1"
                defaultValue={config.thresholds?.[key]}
                onBlur={e => mutateSub('thresholds', key, parseFloat(e.target.value))}
              />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
