import { useEffect, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Shield, AlertTriangle, Activity, Zap, TrendingUp, TrendingDown,
  Clock, ChevronRight, Globe2
} from 'lucide-react';
import { systemApi } from '../../services/api';
import './Dashboard.css';

// ── Mock attack arcs for the demo globe ───────────────────
const MOCK_ARCS = [
  { srcLat:  37.77, srcLng: -122.41, dstLat: 51.5,   dstLng: -0.12,  color: '#ff4d6a' },
  { srcLat:  39.93, srcLng: 116.38,  dstLat: 40.71,  dstLng: -74.0,  color: '#ff4d6a' },
  { srcLat:  55.75, srcLng:  37.62,  dstLat: 48.85,  dstLng:   2.35, color: '#ffab40' },
  { srcLat:  28.6,  srcLng:  77.2,   dstLat: 35.68,  dstLng: 139.69, color: '#00c8ff' },
  { srcLat: -23.5,  srcLng: -46.6,   dstLat: 40.41,  dstLng:  -3.7,  color: '#ff4d6a' },
  { srcLat:  24.46, srcLng:  54.37,  dstLat: 37.77,  dstLng: -122.41,color: '#ffab40' },
  { srcLat:  35.68, srcLng: 139.69,  dstLat: 51.5,   dstLng:  -0.12, color: '#00c8ff' },
];

const MOCK_ALERTS = [
  { id: 1, severity: 'critical', title: 'SQL Injection Attempt', src: '195.206.107.x', time: '0s ago' },
  { id: 2, severity: 'critical', title: 'Brute Force SSH',        src: '45.142.120.x',  time: '4s ago' },
  { id: 3, severity: 'warning',  title: 'Port Scan Detected',     src: '89.234.157.x',  time: '12s ago' },
  { id: 4, severity: 'warning',  title: 'DNS Tunneling',          src: '103.56.53.x',   time: '28s ago' },
  { id: 5, severity: 'info',     title: 'Geo-Block Applied',      src: '5.101.40.x',    time: '41s ago' },
  { id: 6, severity: 'critical', title: 'XSS Payload Blocked',    src: '217.138.200.x', time: '1m ago'  },
  { id: 7, severity: 'warning',  title: 'Rate Limit Exceeded',    src: '91.121.53.x',   time: '1m ago'  },
  { id: 8, severity: 'info',     title: 'VPN Login Success',      src: '10.0.0.4',      time: '2m ago'  },
];

const STATS = [
  { label: 'Threats Blocked',    value: '14,832', delta: '+42', up: true,  icon: Shield,       iconClass: 'stat-icon-red' },
  { label: 'Active Connections', value: '2,481',  delta: '+14', up: true,  icon: Activity,     iconClass: 'stat-icon-cyan' },
  { label: 'Rules Matched',      value: '9,604',  delta: '-2%', up: false, icon: Zap,          iconClass: 'stat-icon-orange' },
  { label: 'System Uptime',      value: '99.9%',  delta: 'stable', up: false, icon: Clock,    iconClass: 'stat-icon-green' },
];

// ── Globe Component ────────────────────────────────────────
function AttackGlobe() {
  const mountRef = useRef(null);
  const globeRef = useRef(null);

  useEffect(() => {
    let Globe;
    let instance;

    import('globe.gl').then((mod) => {
      Globe = mod.default;
      if (!mountRef.current) return;

      instance = Globe()(mountRef.current);
      instance
        .globeImageUrl('//unpkg.com/three-globe/example/img/earth-night.jpg')
        .backgroundImageUrl('//unpkg.com/three-globe/example/img/night-sky.png')
        .arcsData(MOCK_ARCS)
        .arcColor('color')
        .arcDashLength(0.4)
        .arcDashGap(0.2)
        .arcDashAnimateTime(2000)
        .arcStroke(0.5)
        .arcAltitude(0.15)
        .atmosphereColor('#00c8ff')
        .atmosphereAltitude(0.12)
        .width(mountRef.current.clientWidth)
        .height(mountRef.current.clientHeight);

      globeRef.current = instance;
    });

    return () => {
      if (globeRef.current) {
        globeRef.current._destructor?.();
      }
    };
  }, []);

  return (
    <div
      ref={mountRef}
      style={{ width: '100%', height: '100%', minHeight: 380, cursor: 'grab' }}
    />
  );
}

// ── Alert Item ────────────────────────────────────────────
function AlertItem({ alert }) {
  const icons = {
    critical: <AlertTriangle size={14} />,
    warning:  <TrendingUp size={14} />,
    info:     <Activity size={14} />,
  };
  const iconBg = {
    critical: 'var(--danger-dim)',
    warning:  'var(--warning-dim)',
    info:     'var(--info-dim)',
  };
  const iconColor = {
    critical: 'var(--danger)',
    warning:  'var(--warning)',
    info:     'var(--info)',
  };

  return (
    <div className={`alert-item ${alert.severity}`}>
      <div
        className="alert-icon"
        style={{ background: iconBg[alert.severity], color: iconColor[alert.severity] }}
      >
        {icons[alert.severity]}
      </div>
      <div className="alert-body">
        <div className="alert-title">{alert.title}</div>
        <div className="alert-meta">
          <span>{alert.src}</span>
          <span>·</span>
          <span>{alert.time}</span>
        </div>
      </div>
      <ChevronRight size={14} style={{ color: 'var(--text-muted)', flexShrink: 0, marginTop: 4 }} />
    </div>
  );
}

// ── Dashboard Page ─────────────────────────────────────────
export default function Dashboard() {
  const { data: status } = useQuery({
    queryKey: ['system-status'],
    queryFn: () => systemApi.status().then(r => r.data),
    refetchInterval: 5000,
    retry: false,
  });

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
            {status?.status === 'operational' ? 'All Systems Operational' : 'Monitoring…'}
          </span>
        </div>
      </div>

      {/* Stat Cards */}
      <div className="stats-grid">
        {STATS.map((s) => (
          <div key={s.label} className="card card-hover stat-card">
            <div className="stat-card-header">
              <span className="stat-label">{s.label}</span>
              <div className={`stat-icon ${s.iconClass}`}>
                <s.icon size={17} />
              </div>
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
            <span className="badge badge-danger">14 Active</span>
          </div>
          <div className="globe-inner">
            <AttackGlobe />
          </div>
        </div>

        <div className="card alerts-panel">
          <div className="globe-header">
            <div className="section-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <AlertTriangle size={18} style={{ color: 'var(--warning)' }} />
              Live Alerts
            </div>
            <span className="badge badge-warning">8 New</span>
          </div>
          <div className="alerts-list">
            {MOCK_ALERTS.map(a => <AlertItem key={a.id} alert={a} />)}
          </div>
        </div>
      </div>
    </div>
  );
}
