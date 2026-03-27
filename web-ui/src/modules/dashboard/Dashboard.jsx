import { useEffect, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
// eslint-disable-next-line no-unused-vars
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, AlertTriangle, Activity, Zap, TrendingUp, TrendingDown,
  Clock, ChevronRight, Globe2, ShieldOff, Server, Lock,
  FileSearch, Bug, Mail, Radio
} from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { systemApi, wafApi, idsApi, dlpApi, webFilterApi, malwareApi, dnsApi } from '../../services/api';
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
  { srcLat: 37.77, srcLng: -122.41, dstLat: 51.5, dstLng: -0.12, color: '#ef4444' }, // red
  { srcLat: 39.93, srcLng: 116.38, dstLat: 40.71, dstLng: -74.0, color: '#ef4444' },
  { srcLat: 55.75, srcLng: 37.62, dstLat: 48.85, dstLng: 2.35, color: '#f59e0b' }, // amber
  { srcLat: 28.6, srcLng: 77.2, dstLat: 35.68, dstLng: 139.69, color: '#3b82f6' }, // blue
  { srcLat: -23.5, srcLng: -46.6, dstLat: 40.41, dstLng: -3.7, color: '#ef4444' },
  { srcLat: 24.46, srcLng: 54.37, dstLat: 37.77, dstLng: -122.41, color: '#f59e0b' },
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
        .arcDashAnimateTime(2000)
        .arcStroke(0.8)
        .arcAltitude(0.2)
        .atmosphereColor('#3b82f6')
        .atmosphereAltitude(0.15)
        .width(mountRef.current.clientWidth)
        .height(mountRef.current.clientHeight);
      globeRef.current = instance;
    });

    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (globeRef.current) globeRef.current.arcsData(arcs);
  }, [arcs]);

  return <div ref={mountRef} style={{ width: '100%', height: '100%', minHeight: 380, cursor: 'grab' }} />;
}

// ── Alert Item ─────────────────────────────────────────────
const AlertItem = ({ alert }) => {
  const cfg = {
    critical: { icon: <ShieldOff size={14} />, boxClass: 'alert-critical' },
    warning: { icon: <AlertTriangle size={14} />, boxClass: 'alert-warning' },
    info: { icon: <Activity size={14} />, boxClass: 'alert-info' },
  }[alert.severity] || { icon: <Activity size={14} />, boxClass: 'alert-default' };

  return (
    <motion.div 
      initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, scale: 0.9 }}
      className={`alert-item ${cfg.boxClass}`}
    >
      <div className="alert-icon">{cfg.icon}</div>
      <div className="alert-body">
        <div className="alert-title">{alert.title}</div>
        <div className="alert-meta">
          <span>{alert.src}</span><span>·</span><span>{alert.time}</span>
        </div>
      </div>
      <ChevronRight size={14} className="alert-arrow" />
    </motion.div>
  );
};

// ── Dashboard Page ─────────────────────────────────────────
export default function Dashboard() {
  const [liveArcs, setLiveArcs] = useState(STATIC_ARCS);
  const [liveAlerts, setLiveAlerts] = useState([]);
  const wsRef = useRef(null);

  // Poll system status
  const { data: sysStatus } = useQuery({ queryKey: ['dash_sys_status'], queryFn: () => systemApi.status().then(r => r.data), refetchInterval: 5000 });

  // Poll modules status in parallel
  const fetchModules = async () => {
    const [waf, ids, dlp, wf, mal, dns] = await Promise.allSettled([
      wafApi.status(), idsApi.status(), dlpApi.status(), webFilterApi.status(), malwareApi.status(), dnsApi.status()
    ]);
    return {
      waf: waf.status === 'fulfilled' ? waf.value.data : null,
      ids: ids.status === 'fulfilled' ? ids.value.data : null,
      dlp: dlp.status === 'fulfilled' ? dlp.value.data : null,
      wf: wf.status === 'fulfilled' ? wf.value.data : null,
      mal: mal.status === 'fulfilled' ? mal.value.data : null,
      dns: dns.status === 'fulfilled' ? dns.value.data : null,
    };
  };
  const { data: mods } = useQuery({ queryKey: ['dash_mods_health'], queryFn: fetchModules, refetchInterval: 10000 });

  // Setup WebSocket for WAF Live
  useEffect(() => {
    const token = localStorage.getItem('CyberNexus_token');
    const wsUrl = (import.meta.env.VITE_API_URL || 'http://192.168.109.137:8000').replace(/^http/, 'ws');
    wsRef.current = new WebSocket(`${wsUrl}/api/v1/waf/live?token=${token}`);

    wsRef.current.onmessage = (msg) => {
      try {
        const ev = JSON.parse(msg.data);
        const [srcLat, srcLng] = ipToApproxGeo(ev.src_ip);
        const color = ev.action === 'BLOCK' ? '#ef4444' : '#f59e0b';
        
        setLiveArcs(prev => [{ srcLat, srcLng, dstLat: SERVER[0], dstLng: SERVER[1], color }, ...prev.slice(0, 29)]);
        setLiveAlerts(prev => [{
          id: Date.now(),
          severity: ev.action === 'BLOCK' ? 'critical' : 'warning',
          title: ev.triggers?.[0] || 'Threat Detected',
          src: ev.src_ip || '?.?.?.?',
          time: 'just now'
        }, ...prev.slice(0, 11)]);
      } catch { /* ignore */ }
    };
    return () => wsRef.current?.close();
  }, []);

  // Generate fake traffic data for the chart if no real data is streamed
  const [trafficData, setTrafficData] = useState(() => Array.from({length: 20}, (_, i) => ({ time: `-${20-i}s`, reqs: Math.floor(Math.random()*500+200), blocks: Math.floor(Math.random()*50) })));
  
  useEffect(() => {
    const intv = setInterval(() => {
      setTrafficData(prev => {
        const newReqs = Math.max(100, prev[prev.length-1].reqs + (Math.random()*100 - 50));
        const newBlocks = Math.max(0, prev[prev.length-1].blocks + (Math.random()*10 - 5));
        return [...prev.slice(1), { time: 'now', reqs: Math.floor(newReqs), blocks: Math.floor(newBlocks) }];
      });
    }, 2000);
    return () => clearInterval(intv);
  }, []);

  const alertsToShow = liveAlerts.length > 0 ? liveAlerts : [
    { id: 1, severity: 'critical', title: 'SQL Injection Attempt', src: '195.206.107.x', time: '0s ago' },
    { id: 2, severity: 'critical', title: 'Brute Force SSH', src: '45.142.120.x', time: '4s ago' },
    { id: 3, severity: 'warning', title: 'Port Scan Detected', src: '89.234.157.x', time: '12s ago' },
    { id: 4, severity: 'info', title: 'Protocol Anomaly', src: '103.56.53.x', time: '28s ago' },
    { id: 5, severity: 'info', title: 'Geo-Block Applied', src: '5.101.40.x', time: '41s ago' },
  ];

  const STAT_CARDS = [
    { label: 'Threats Blocked', value: sysStatus?.threats_blocked || '24,832', delta: '+12%', up: true, icon: Shield, clr: 'neon-red' },
    { label: 'Active Sessions', value: sysStatus?.active_conns || '3,481', delta: '+5%', up: true, icon: Activity, clr: 'neon-cyan' },
    { label: 'Rules Matched', value: sysStatus?.rules_matched || '11,604', delta: '-1%', up: false, icon: Zap, clr: 'neon-amber' },
    { label: 'Uptime', value: sysStatus?.uptime_pct || '99.9%', delta: 'stable', up: true, icon: Clock, clr: 'neon-green' },
  ];

  const MODULES_HEALTH = [
    { id: 'waf', name: 'WAF Engine', icon: Lock, status: mods?.waf ? mods.waf.status : 'active' },
    { id: 'ids', name: 'IDS/IPS', icon: Radio, status: mods?.ids ? mods.ids.status : 'active' },
    { id: 'dlp', name: 'DLP Analysis', icon: FileSearch, status: mods?.dlp ? mods.dlp.status : 'active' },
    { id: 'wf', name: 'Web Filter', icon: Globe2, status: mods?.wf ? mods.wf.status : 'active' },
    { id: 'mal', name: 'Malware AV', icon: Bug, status: mods?.mal ? mods.mal.status : 'warning' },
    { id: 'dns', name: 'DNS Security', icon: Server, status: mods?.dns ? mods.dns.status : 'active' },
  ];

  // Framer motion variants
  const containerVars = { hidden: { opacity: 0 }, show: { opacity: 1, transition: { staggerChildren: 0.1 } } };
  const itemVars = { hidden: { opacity: 0, y: 20 }, show: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 300, damping: 24 } } };

  return (
    <motion.div className="dashboard-root" initial="hidden" animate="show" variants={containerVars}>
      
      {/* Header */}
      <motion.div className="dash-header flex-between" variants={itemVars}>
        <div>
          <h1 className="dash-title">Security Operations Center</h1>
          <p className="dash-subtitle">Enterprise CyberNexus Global Monitoring</p>
        </div>
        <div className="dash-status-pill">
          <div className="dash-pulse-dot" />
          <span>{sysStatus?.status === 'error' ? 'System Degraded' : 'All Systems Operational'}</span>
        </div>
      </motion.div>

      {/* Top Stats Grid */}
      <motion.div className="dash-stats-grid" variants={itemVars}>
        {STAT_CARDS.map(s => (
          <div key={s.label} className={`dash-stat-card ${s.clr}`}>
            <div className="flex-between stat-top">
              <span className="stat-label">{s.label}</span>
              <div className="stat-icon-wrapper"><s.icon size={18} /></div>
            </div>
            <div className="stat-body">
              <div className="stat-value">{s.value}</div>
              <div className={`stat-delta flex-center-left ${s.up ? 'up' : 'down'}`}>
                {s.up ? <TrendingUp size={14}/> : <TrendingDown size={14}/>} {s.delta}
              </div>
            </div>
          </div>
        ))}
      </motion.div>

      {/* Main Content Area */}
      <div className="dash-main-grid">
        
        {/* LEFT COLUMN */}
        <div className="dash-col-left">
          
          {/* Globe */}
          <motion.div className="dash-panel glass-panel globe-panel" variants={itemVars}>
            <div className="panel-header flex-between">
              <div className="panel-title"><Globe2 size={18}/> Live Threat Map</div>
              <span className="badge-glow pulse-red">{liveAlerts.length || 12} Active Vectors</span>
            </div>
            <div className="globe-wrapper">
              <AttackGlobe arcs={liveArcs} />
              <div className="globe-overlay" />
            </div>
          </motion.div>

          {/* Traffic Chart */}
          <motion.div className="dash-panel glass-panel" variants={itemVars}>
            <div className="panel-header">
              <div className="panel-title"><Activity size={18}/> Network Throughput (L7)</div>
            </div>
            <div className="chart-wrapper">
              <ResponsiveContainer width="100%" height={240}>
                <AreaChart data={trafficData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorReqs" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.4}/>
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="colorBlocks" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4}/>
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                  <XAxis dataKey="time" stroke="rgba(255,255,255,0.3)" fontSize={12} tickLine={false} axisLine={false} />
                  <YAxis stroke="rgba(255,255,255,0.3)" fontSize={12} tickLine={false} axisLine={false} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: 'rgba(15, 23, 42, 0.9)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px', backdropFilter: 'blur(10px)' }}
                    itemStyle={{ color: '#fff', fontSize: '13px' }}
                  />
                  <Area type="monotone" dataKey="reqs" stroke="#3b82f6" strokeWidth={2} fillOpacity={1} fill="url(#colorReqs)" name="Requests/s" />
                  <Area type="monotone" dataKey="blocks" stroke="#ef4444" strokeWidth={2} fillOpacity={1} fill="url(#colorBlocks)" name="Blocks/s" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </motion.div>

          {/* Sub Grid (Modules) */}
          <motion.div className="dash-modules-grid" variants={itemVars}>
            {MODULES_HEALTH.map(m => (
              <div key={m.id} className="module-health-card glass-panel">
                <div className="flex-between">
                  <div className="flex-center-left gap-2"><m.icon size={16} className="text-muted"/> {m.name}</div>
                  <div className={`status-dot ${m.status === 'active' ? 'bg-success' : m.status === 'warning' ? 'bg-warning' : 'bg-danger'}`} />
                </div>
                <div className="text-xs text-muted mt-2 capitalize">{m.status || 'Active'} State</div>
              </div>
            ))}
          </motion.div>

        </div>

        {/* RIGHT COLUMN */}
        <div className="dash-col-right flex-col">
          
          <motion.div className="dash-panel glass-panel flex-1 flex-col" variants={itemVars}>
            <div className="panel-header flex-between mb-4">
              <div className="panel-title"><AlertTriangle size={18} className="text-warning"/> Live Feed</div>
              <span className="text-xs text-muted">{alertsToShow.length} events</span>
            </div>
            
            <div className="alerts-feed flex-1 custom-scrollbar">
              <AnimatePresence mode="popLayout">
                {alertsToShow.map(a => <AlertItem key={a.id} alert={a} />)}
              </AnimatePresence>
            </div>
          </motion.div>

        </div>

      </div>

    </motion.div>
  );
}
