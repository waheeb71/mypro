import { Activity } from 'lucide-react';
import { useState, useEffect, useRef } from 'react';

export default function LiveMonitor() {
  const [events, setEvents] = useState([]);
  const ws = useRef(null);

  useEffect(() => {
    const token = localStorage.getItem('ngfw_token');
    const wsUrl = (import.meta.env.VITE_API_URL || 'http://192.168.109.137:8000').replace(/^http/, 'ws');
    
    ws.current = new WebSocket(`${wsUrl}/api/v1/waf/live?token=${token}`);
    
    ws.current.onmessage = (msg) => {
      try {
        const data = JSON.parse(msg.data);
        setEvents(prev => [data, ...prev].slice(0, 50));
      } catch (e) {
        console.error("WebSocket message error:", e);
      }
    };

    return () => {
      if (ws.current) ws.current.close();
    };
  }, []);

  return (
    <div className="card" style={{ height: 400, display: 'flex', flexDirection: 'column' }}>
      <div className="section-header" style={{ borderBottom: '1px solid var(--border)', paddingBottom: 'var(--sp-3)' }}>
        <div className="section-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Activity size={17} style={{ color: 'var(--danger)' }} />
          Live Threat Feed
        </div>
      </div>
      <div style={{ flex: 1, overflowY: 'auto', padding: 'var(--sp-3)', display: 'flex', flexDirection: 'column', gap: 'var(--sp-2)' }}>
        {events.length === 0 ? (
          <div style={{ color: 'var(--text-muted)', textAlign: 'center', marginTop: 40, fontSize: 'var(--text-sm)' }}>
             Monitoring traffic in real-time... No threats detected recently.
          </div>
        ) : (
          events.map((ev, i) => (
            <div key={i} style={{ 
              padding: 'var(--sp-3)', 
              borderRadius: 'var(--radius-sm)', 
              background: 'var(--bg-raised)',
              borderLeft: `3px solid ${ev.action === 'BLOCK' ? 'var(--danger)' : 'var(--warning)'}`,
              fontSize: 'var(--text-xs)'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                <strong style={{ color: 'var(--text-primary)' }}>{ev.src_ip}</strong>
                <span className={`badge ${ev.action === 'BLOCK' ? 'badge-danger' : 'badge-warning'}`}>{ev.action}</span>
              </div>
              <div style={{ color: 'var(--text-secondary)', marginBottom: 4 }}>
                 Path: <code style={{ color: 'var(--accent)' }}>{ev.path}</code>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)' }}>
                 <span>Triggers: {ev.triggers?.join(', ') || 'Unknown'}</span>
                 <span>Score: {ev.risk_score}</span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
