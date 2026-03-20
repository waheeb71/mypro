import { useEffect, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Shield, AlertTriangle, Activity, Zap, TrendingUp, TrendingDown,
  Clock, ChevronRight, Globe2, ShieldOff, Server
} from 'lucide-react';
import { systemApi, wafApi } from '../../services/api';
import './Dashboard.css';

// ── GEO lookup table for well-known IPs (approx positions) ─
const GEO_DB = {
  'CN': [35.86, 104.19], 'RU': [61.52, 105.31], 'US': [37.09, -95.71],
  'BR': [-14.24, -51.93], 'IN': [20.59, 78.96], 'GB': [55.38, -3.43],
  'DE': [51.17, 10.45], 'KR': [35.91, 127.76], 'JP': [36.20, 138.25],
  'TR': [38.96, 35.24], 'FR': [46.23, 2.21], 'XX': [0, 0],
};
const SERVER = GEO_DB['US'];

function ipToApproxGeo(ip = '') {
  const s = ip.split('.');
  const first = parseInt(s[0] || '0', 10);
  if (first >= 1 && first <= 50) return GEO_DB['CN'];
  if (first >= 51 && first <= 100) return GEO_DB['RU'];
  if (first >= 173 && first <= 199) return GEO_DB['US'];
  if (first >= 200 && first <= 220) return GEO_DB['BR'];
  if (first >= 80 && first <= 95) return GEO_DB['DE'];
  return GEO_DB['TR'];
}

// ── Static fallback arcs (demo mode) ──────────────────────
const STATIC_ARCS = [
  { srcLat: 37.77,  srcLng: -122.41, dstLat: 51.5,  dstLng: -0.12,  color: '#ff4d6a' },
  { srcLat: 39.93,  srcLng: 116.38,  dstLat: 40.71, dstLng: -74.0,  color: '#ff4d6a' },
  { srcLat: 55.75,  srcLng:  37.62,  dstLat: 48.85, dstLng:   2.35, color: '#ffab40' },
  { srcLat: 28.6,   srcLng:  77.2,   dstLat: 35.68, dstLng: 139.69, color: '#00c8ff' },
  { srcLat: -23.5,  srcLng: -46.6,   dstLat: 40.41, dstLng:  -3.7,  color: '#ff4d6a' },
  { srcLat: 24.46,  srcLng:  54.37,  dstLat: 37.77, dstLng: -122.41,color: '#ffab40' },
];

// ── Globe Component ────────────────────────────────────────
function AttackGlobe({ arcs = STATIC_ARCS }) {
  const mountRef = useRef(null);
  const globeRef = useRef(null);

  useEffect(() => {
    let instance;
    import('globe.gl').then((mod) => {
      if (!mountRef.current) return;
      const Globe = mod.default;
      instance = Globe()(mountRef.current);
      instance
        .globeImageUrl('//unpkg.com/three-globe/example/img/earth-night.jpg')
        .backgroundImageUrl('//unpkg.com/three-globe/example/img/night-sky.png')
        .arcsData(arcs)
        .arcColor('color')
        .arcDashLength(0.35)
        .arcDashGap(0.15)
        .arcDashAnimateTime(1800)
        .arcStroke(0.6)
        .arcAltitude(0.2)
        .atmosphereColor('#00c8ff')
        .atmosphereAltitude(0.13)
        .width(mountRef.current.clientWidth)
        .height(mountRef.current.clientHeight);
      globeRef.current = instance;
    });

    return () => { globeRef.current?._destructor?.(); };
  }, []);  // Only re-mount when component mounts

  // Update arc data without remounting
  useEffect(() => {
    if (globeRef.current) globeRef.current.arcsData(arcs);
  }, [arcs]);

  return <div ref={mountRef} style={{ width: '100%', height: '100%', minHeight: 380, cursor: 'grab' }} />;
}

// ── Alert Item ─────────────────────────────────────────────
function AlertItem({ alert }) {
  const cfg = {
    critical: { icon: <ShieldOff size={14} />, bg: 'var(--danger-dim)',  color: 'var(--danger)'  },
    warning:  { icon: <AlertTriangle size={14}/>, bg: 'var(--warning-dim)',color: 'var(--warning)' },
    info:     { icon: <Activity size={14} />,   bg: 'var(--info-dim)',   color: 'var(--info)'    },
  }[alert.severity] || { icon: <Activity size={14}/>, bg: 'var(--bg-raised)', color: 'var(--text-muted)' };

  return (
    <div className={`alert-item ${alert.severity}`}>
      <div className="alert-icon" style={{ background: cfg.bg, color: cfg.color }}>{cfg.icon}</div>
      <div className="alert-body">
        <div className="alert-title">{alert.title}</div>
        <div className="alert-meta">
          <span>{alert.src}</span><span>·</span><span>{alert.time}</span>
        </div>
      </div>
      <ChevronRight size={14} style={{ color: 'var(--text-muted)', flexShrink: 0, marginTop: 4 }} />
    </div>
  );
}

// ── Module Status Row ──────────────────────────────────────
function ModuleStatus({ label, active, icon: Icon }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: 'var(--sp-3) var(--sp-4)', borderBottom: '1px solid var(--border)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <Icon size={14} style={{ color: active ? 'var(--success)' : 'var(--text-muted)' }} />
        <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>{label}</span>
      </div>
      <span className={`badge ${active ? 'badge-success' : 'badge-info'}`} style={{ fontSize: '10px' }}>
        {active ? 'Active' : 'Disabled'}
      </span>
    </div>
  );
}

// ── Dashboard Page ─────────────────────────────────────────
export default function Dashboard() {
  const [liveArcs, setLiveArcs] = useState(STATIC_ARCS);
  const [liveAlerts, setLiveAlerts] = useState([]);
  const wsRef = useRef(null);

  const { data: sysStatus } = useQuery({
    queryKey: ['system-status'],
    queryFn: () => systemApi.status().then(r => r.data),
    refetchInterval: 5000, retry: false,
  });
  const { data: wafStatus } = useQuery({
    queryKey: ['waf-status'],
    queryFn: () => wafApi.status().then(r => r.data),
    refetchInterval: 8000, retry: false,
  });

  // Connect to WAF Live WebSocket for real-time threat arcs
  useEffect(() => {
    const token = localStorage.getItem('ngfw_token');
    const wsUrl = (import.meta.env.VITE_API_URL || 'http://192.168.109.137:8000').replace(/^http/, 'ws');
    wsRef.current = new WebSocket(`${wsUrl}/api/v1/waf/live?token=${token}`);

    wsRef.current.onmessage = (msg) => {
      try {
        const ev = JSON.parse(msg.data);
        const [srcLat, srcLng] = ipToApproxGeo(ev.src_ip);
        const [dstLat, dstLng] = SERVER;
        const color = ev.action === 'BLOCK' ? '#ff4d6a' : '#ffab40';

        // Add arc to globe (keep last 30)
        setLiveArcs(prev => [
          { srcLat, srcLng, dstLat, dstLng, color },
          ...prev.slice(0, 29)
        ]);

        // Add alert card (keep last 12)
        setLiveAlerts(prev => [{
          id: Date.now(),
          severity: ev.action === 'BLOCK' ? 'critical' : 'warning',
          title: ev.triggers?.[0] || 'Threat Detected',
          src: ev.src_ip || '?.?.?.?',
          time: 'just now'
        }, ...prev.slice(0, 11)]);

      } catch (e) { /* ignore parse errors */ }
    };

    return () => wsRef.current?.close();
  }, []);

  const displayAlerts = liveAlerts.length > 0 ? liveAlerts : [
    { id: 1, severity: 'critical', title: 'SQL Injection Attempt',  src: '195.206.107.x', time: '0s ago' },
    { id: 2, severity: 'critical', title: 'Brute Force SSH',         src: '45.142.120.x',  time: '4s ago' },
    { id: 3, severity: 'warning',  title: 'Port Scan Detected',      src: '89.234.157.x',  time: '12s ago'},
    { id: 4, severity: 'warning',  title: 'DNS Tunneling',           src: '103.56.53.x',   time: '28s ago'},
    { id: 5, severity: 'info',     title: 'Geo-Block Applied',       src: '5.101.40.x',    time: '41s ago'},
    { id: 6, severity: 'critical', title: 'XSS Payload Blocked',     src: '217.138.200.x', time: '1m ago' },
  ];

  const STATS = [
    { label: 'Threats Blocked',    value: sysStatus?.threats_blocked  || '14,832', delta: '+42', up: true,  icon: Shield,   iconClass: 'stat-icon-red'    },
    { label: 'Active Connections', value: sysStatus?.active_conns     || '2,481',  delta: '+14', up: true,  icon: Activity, iconClass: 'stat-icon-cyan'   },
    { label: 'Rules Matched',      value: sysStatus?.rules_matched    || '9,604',  delta: '-2%', up: false, icon: Zap,      iconClass: 'stat-icon-orange' },
    { label: 'System Uptime',      value: sysStatus?.uptime_pct       || '99.9%',  delta: 'stable', up: false, icon: Clock, iconClass: 'stat-icon-green'  },
  ];

  const modules = [
    { label: 'WAF / WAAP Engine',        active: wafStatus?.waf_enabled,            icon: Shield  },
    { label: 'GNN Threat Detection',     active: wafStatus?.features?.gnn,          icon: Activity },
    { label: 'NLP Payload Analysis',     active: wafStatus?.features?.nlp,          icon: Zap     },
    { label: 'Rate Limiter',             active: wafStatus?.features?.waap_rate_limit, icon: Server},
    { label: 'ATO Protection',           active: wafStatus?.features?.waap_ato,     icon: ShieldOff },
  ];

  return (
    <div className="dashboard">
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Security Operations Center</h1>
          <p className="page-subtitle">Real-time threat monitoring • Enterprise NGFW Console</p>
        </div>
        <div className="topbar-live">
          <div className="topbar-live-dot pulse" />
          <span style={{ color: 'var(--success)', fontSize: 'var(--text-sm)' }}>
            {sysStatus?.status === 'operational' ? 'All Systems Operational' : 'Monitoring…'}
          </span>
        </div>
      </div>

      {/* Stat Cards */}
      <div className="stats-grid">
        {STATS.map((s) => (
          <div key={s.label} className="card card-hover stat-card">
            <div className="stat-card-header">
              <span className="stat-label">{s.label}</span>
              <div className={`stat-icon ${s.iconClass}`}><s.icon size={17} /></div>
            </div>
            <div className="stat-value">{s.value}</div>
            <div className={`stat-delta ${s.up ? 'stat-delta-up' : 'stat-delta-down'}`}>
              {s.up ? <TrendingUp size={12} /> : <TrendingDown size={12} />}
              {s.delta} last 5 min
            </div>
          </div>
        ))}
      </div>

      {/* Globe + Alerts */}
      <div className="main-grid">
        <div className="card globe-container">
          <div className="globe-header">
            <div className="section-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Globe2 size={18} style={{ color: 'var(--accent)' }} />
              Live Attack Map
            </div>
            <span className="badge badge-danger">{liveAlerts.length || 14} Active</span>
          </div>
          <div className="globe-inner">
            <AttackGlobe arcs={liveArcs} />
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-5)' }}>
          {/* Live Alerts */}
          <div className="card alerts-panel" style={{ flex: 1 }}>
            <div className="globe-header">
              <div className="section-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <AlertTriangle size={18} style={{ color: 'var(--warning)' }} />
                Live Alerts
              </div>
              <span className="badge badge-warning">{liveAlerts.length || 8} New</span>
            </div>
            <div className="alerts-list" style={{ maxHeight: 250, overflowY: 'auto' }}>
              {displayAlerts.map(a => <AlertItem key={a.id} alert={a} />)}
            </div>
          </div>

          {/* Module Status */}
          <div className="card" style={{ overflow: 'hidden' }}>
            <div className="globe-header" style={{ borderBottom: '1px solid var(--border)' }}>
              <div className="section-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Server size={16} style={{ color: 'var(--accent)' }} />
                Module Health
              </div>
            </div>
            {modules.map(m => <ModuleStatus key={m.label} {...m} />)}
          </div>
        </div>
      </div>
    </div>
  );
}
