import { NavLink, Outlet } from 'react-router-dom';
import {
  LayoutDashboard, Shield, ShieldOff, Globe, Wifi, Lock, Mail,
  Search, Activity, Database, Network, Settings, LogOut, User, Zap
} from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import './Shell.css';

const NAV_ITEMS = [
  { to: '/',              icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/firewall',      icon: Shield,           label: 'Firewall Rules' },
  { to: '/ip-blocklist',  icon: ShieldOff,        label: 'IP Blocklist' },
  { to: '/waf',           icon: Globe,            label: 'WAF' },
  { to: '/ids-ips',       icon: Activity,         label: 'IDS / IPS' },
  { to: '/dns',           icon: Network,          label: 'DNS Security' },
  { to: '/vpn',           icon: Lock,             label: 'VPN' },
  { to: '/email',         icon: Mail,             label: 'Email Security' },
  { to: '/http',          icon: Search,           label: 'HTTP Inspect' },
  { to: '/ssl',           icon: Wifi,             label: 'SSL Inspect' },
  { to: '/ai',            icon: Zap,              label: 'Predictive AI' },
  { to: '/system',        icon: Settings,         label: 'System' },
  { to: '/settings',      icon: Database,         label: 'Raw Configs' },
  { to: '/users',         icon: User,             label: 'Users & RBAC' },
];

export default function Shell() {
  const { user, logout } = useAuth();

  return (
    <>
      {/* ── Sidebar ── */}
      <aside className="sidebar">
        <NavLink to="/" className="sidebar-logo">
          <div className="sidebar-logo-icon">
            <Shield size={18} color="#fff" />
          </div>
          <span className="sidebar-logo-text">NGFW Console</span>
        </NavLink>

        <nav className="sidebar-nav">
          {NAV_ITEMS.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
            >
              <Icon className="nav-item-icon" size={20} />
              <span className="nav-item-label">{label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-footer">
          <button className="nav-item" onClick={logout} style={{ width: '100%', background: 'none', border: 'none', cursor: 'pointer' }}>
            <LogOut className="nav-item-icon" size={20} />
            <span className="nav-item-label">Logout</span>
          </button>
        </div>
      </aside>

      {/* ── Top Bar ── */}
      <header className="topbar">
        <div className="topbar-title">Enterprise NGFW</div>
        <div className="topbar-right">
          <div className="topbar-live">
            <div className="topbar-live-dot pulse" />
            Live
          </div>
          <div className="topbar-user">
            <User size={14} />
            <span>{user?.username}</span>
            <span className="badge badge-accent" style={{ marginLeft: 4 }}>{user?.role}</span>
          </div>
        </div>
      </header>

      {/* ── Page Content ── */}
      <main className="main-content">
        <Outlet />
      </main>
    </>
  );
}
