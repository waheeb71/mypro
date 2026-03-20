export default function ToggleSwitch({ label, enabled, onChange, disabled }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: 'var(--sp-4)', borderBottom: '1px solid var(--border)' }}>
      <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)', fontWeight: 500 }}>{label}</span>
      <label className="switch" style={{ opacity: disabled ? 0.5 : 1, cursor: disabled ? 'not-allowed' : 'pointer', position: 'relative', display: 'inline-block', width: '40px', height: '20px' }}>
        <input 
          type="checkbox" 
          checked={enabled} 
          onChange={(e) => !disabled && onChange(e.target.checked)}
          disabled={disabled}
          style={{ opacity: 0, width: 0, height: 0 }}
        />
        <span style={{
          position: 'absolute', top: 0, left: 0, right: 0, bottom: 0,
          backgroundColor: enabled ? 'var(--accent)' : 'var(--bg-raised)',
          borderRadius: '20px', transition: '.4s',
        }}>
          <span style={{
            position: 'absolute', content: '""', height: '14px', width: '14px',
            left: enabled ? '22px' : '3px', bottom: '3px',
            backgroundColor: 'white', borderRadius: '50%', transition: '.4s'
          }} />
        </span>
      </label>
    </div>
  );
}
