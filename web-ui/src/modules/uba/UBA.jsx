import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  User, Activity, ShieldAlert, Settings, Search,
  RefreshCw, TrendingUp, AlertCircle, Clock, Database,
  UserCheck, UserX, Plus, FileText, BarChart3, Zap
} from 'lucide-react';
import { ubaApi } from '../../services/api';

// ── Helpers ──────────────────────────────────────────────────────────────────

function fmtScore(score) {
  if (score === undefined || score === null) return '0%';
  return `${(score * 100).toFixed(0)}%`;
}

function getRiskColor(level) {
  switch (level?.toLowerCase()) {
    case 'critical': return 'var(--danger)';
    case 'high':     return 'var(--warning)';
    case 'medium':   return 'var(--accent)';
    case 'low':      return 'var(--success)';
    default:         return 'var(--text-muted)';
  }
}

// ── Main Component ───────────────────────────────────────────────────────────

export default function UBA() {
  const qc = useQueryClient();
  const [tab, setTab] = useState('dashboard');
  const [selectedUser, setSelectedUser] = useState(null);
  const [userSearch, setUserSearch] = useState('');

  // Queries
  const { data: status } = useQuery({
    queryKey: ['uba_status'],
    queryFn: () => ubaApi.status().then(r => r.data),
    refetchInterval: 15000
  });

  const { data: alerts } = useQuery({
    queryKey: ['uba_alerts'],
    queryFn: () => ubaApi.alerts().then(r => r.data),
    refetchInterval: 10000
  });

  const { data: usersData } = useQuery({
    queryKey: ['uba_users', userSearch],
    queryFn: () => ubaApi.users({ limit: 10, username: userSearch }).then(r => r.data)
  });

  const { data: profile } = useQuery({
    queryKey: ['uba_profile', selectedUser],
    queryFn: () => ubaApi.userProfile(selectedUser).then(r => r.data),
    enabled: !!selectedUser
  });

  const resetMutation = useMutation({
    mutationFn: (name) => ubaApi.resetUser(name),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['uba_users'] });
      qc.invalidateQueries({ queryKey: ['uba_profile', selectedUser] });
    }
  });

  const { data: ubaConfig } = useQuery({
    queryKey: ['uba_config'],
    queryFn: () => ubaApi.getConfig().then(r => r.data)
  });

  const updateConfigMutation = useMutation({
    mutationFn: (d) => ubaApi.updateConfig(d),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['uba_config'] })
  });

  return (
    <div className="module-page">
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <UserCheck size={24} style={{ color: 'var(--accent)' }} /> User Behavior Analytics
          </h1>
          <p className="page-subtitle">Inside threat detection and behavioral profiling using ML baselines</p>
        </div>
        <div style={{ display: 'flex', gap: 'var(--sp-3)', alignItems: 'center' }}>
          <span className={`badge ${status?.status === 'active' ? 'badge-success' : 'badge-info'}`}>
            {status?.status === 'active' ? '● Engine Running' : '○ Engine Loading'}
          </span>
          <span className="badge" style={{ background: 'var(--bg-overlay)', border: '1px solid var(--border)' }}>
            v{status?.version ?? '2.0'}
          </span>
        </div>
      </div>

      {/* Stats Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 'var(--sp-4)' }}>
        <div className="card" style={{ padding: 'var(--sp-4)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-3)' }}>
            <div style={{ padding: 8, background: 'var(--accent-dim)', borderRadius: '50%' }}>
              <User size={18} style={{ color: 'var(--accent)' }} />
            </div>
            <div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>TOTAL PROFILES</div>
              <div style={{ fontSize: '1.4rem', fontWeight: 700 }}>{status?.profiles_total ?? 0}</div>
            </div>
          </div>
        </div>
        <div className="card" style={{ padding: 'var(--sp-4)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-3)' }}>
            <div style={{ padding: 8, background: 'var(--danger-dim)', borderRadius: '50%' }}>
              <ShieldAlert size={18} style={{ color: 'var(--danger)' }} />
            </div>
            <div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>HIGH RISK USERS</div>
              <div style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--danger)' }}>{status?.high_risk_users ?? 0}</div>
            </div>
          </div>
        </div>
        <div className="card" style={{ padding: 'var(--sp-4)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-3)' }}>
            <div style={{ padding: 8, background: 'var(--bg-overlay)', borderRadius: '50%' }}>
              <Database size={18} style={{ color: 'var(--text-muted)' }} />
            </div>
            <div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>TOTAL EVENTS</div>
              <div style={{ fontSize: '1.4rem', fontWeight: 700 }}>{status?.events_total?.toLocaleString() ?? 0}</div>
            </div>
          </div>
        </div>
        <div className="card" style={{ padding: 'var(--sp-4)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-3)' }}>
            <div style={{ padding: 8, background: 'var(--success-dim)', borderRadius: '50%' }}>
              <TrendingUp size={18} style={{ color: 'var(--success)' }} />
            </div>
            <div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>ENGINE MODE</div>
              <div style={{ fontSize: '1.2rem', fontWeight: 700, textTransform: 'uppercase' }}>{status?.mode ?? 'Monitor'}</div>
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div style={{ display: 'flex', gap: 'var(--sp-2)', borderBottom: '1px solid var(--border)', paddingBottom: 'var(--sp-2)' }}>
        {['dashboard', 'users', 'alerts', 'settings'].map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`btn ${tab === t ? 'btn-primary' : 'btn-ghost'}`}
            style={{ textTransform: 'capitalize' }}
          >
            {t}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
        {tab === 'dashboard' && (
          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 'var(--sp-4)' }}>
            {/* Top Risk Users */}
            <div className="card" style={{ overflow: 'hidden' }}>
              <div className="section-header">
                <h3>Top Risk Users</h3>
                <span className="badge badge-danger">Attention Required</span>
              </div>
              <table className="table">
                <thead>
                  <tr>
                    <th>User</th>
                    <th>Risk Level</th>
                    <th>Risk Score</th>
                    <th>Events</th>
                    <th>Baselines</th>
                  </tr>
                </thead>
                <tbody>
                  {usersData?.users?.slice(0, 5).map(u => (
                    <tr
                      key={u.username}
                      onClick={() => { setSelectedUser(u.username); setTab('users'); }}
                      style={{ cursor: 'pointer' }}
                    >
                      <td style={{ fontWeight: 600 }}>{u.username}</td>
                      <td>
                        <span className="badge" style={{
                          background: `${getRiskColor(u.risk_level)}20`,
                          color: getRiskColor(u.risk_level),
                          borderColor: getRiskColor(u.risk_level)
                        }}>
                          {u.risk_level}
                        </span>
                      </td>
                      <td>
                        <div style={{ width: 100, height: 8, background: 'var(--bg-overlay)', borderRadius: 4, overflow: 'hidden' }}>
                          <div style={{
                            width: `${u.risk_score * 100}%`,
                            height: '100%',
                            background: getRiskColor(u.risk_level)
                          }} />
                        </div>
                      </td>
                      <td>{u.event_count}</td>
                      <td>
                        {u.baseline_locked ?
                          <span className="badge badge-success"><UserCheck size={10} /> Locked</span> :
                          <span className="badge badge-info"><Clock size={10} /> Learning</span>
                        }
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Recent Alerts */}
            <div className="card">
              <div className="section-header">
                <h3>Recent Alerts</h3>
                <AlertCircle size={16} />
              </div>
              <div style={{ padding: 'var(--sp-2)', display: 'flex', flexDirection: 'column', gap: 'var(--sp-2)' }}>
                {alerts?.alerts?.slice(0, 8).map((a, i) => (
                  <div key={i} style={{ padding: 'var(--sp-3)', background: 'var(--bg-raised)', borderRadius: 'var(--radius)', borderLeft: `3px solid ${getRiskColor(a.risk_level)}` }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                      <span style={{ fontWeight: 700, fontSize: 'var(--text-xs)' }}>{a.username}</span>
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{new Date(a.event_time).toLocaleTimeString()}</span>
                    </div>
                    <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                      Anomaly: {(a.anomaly_score * 100).toFixed(0)}% in {a.detector_type ?? 'Traffic'}
                    </div>
                  </div>
                ))}
                {!alerts?.alerts?.length && (
                  <div style={{ padding: 'var(--sp-8)', textAlign: 'center', color: 'var(--text-muted)' }}>
                    No critical behavioral alerts.
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {tab === 'users' && (
          <div style={{ display: 'grid', gridTemplateColumns: selectedUser ? '300px 1fr' : '1fr', gap: 'var(--sp-4)' }}>
            {/* User List */}
            <div className="card">
              <div style={{ padding: 'var(--sp-4)', borderBottom: '1px solid var(--border)' }}>
                <div style={{ position: 'relative' }}>
                  <Search size={14} style={{ position: 'absolute', left: 10, top: 10, color: 'var(--text-muted)' }} />
                  <input
                    className="input"
                    style={{ paddingLeft: 32 }}
                    placeholder="Search users..."
                    value={userSearch}
                    onChange={e => setUserSearch(e.target.value)}
                  />
                </div>
              </div>
              <div style={{ maxHeight: '600px', overflowY: 'auto' }}>
                {usersData?.users?.map(u => (
                  <div
                    key={u.username}
                    onClick={() => setSelectedUser(u.username)}
                    style={{
                      padding: 'var(--sp-3) var(--sp-4)',
                      borderBottom: '1px solid var(--border)',
                      cursor: 'pointer',
                      background: selectedUser === u.username ? 'var(--accent-dim)' : 'transparent',
                      display: 'flex',
                      alignItems: 'center',
                      gap: 'var(--sp-3)'
                    }}
                  >
                    <div style={{
                      width: 8, height: 8, borderRadius: '50%',
                      background: getRiskColor(u.risk_level)
                    }} />
                    <div style={{ flex: 1 }}>
                      <div style={{ fontWeight: 600, fontSize: 'var(--text-sm)' }}>{u.username}</div>
                      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                        Risk: {fmtScore(u.risk_score)} • {u.event_count} eps
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Profile Detail */}
            {selectedUser && profile ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
                <div className="card" style={{ padding: 'var(--sp-5)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <div>
                      <h2 style={{ fontSize: '1.5rem', fontWeight: 800, marginBottom: 4 }}>{profile.username}</h2>
                      <p style={{ color: 'var(--text-muted)', fontSize: 'var(--text-sm)' }}>
                        Peer Group: <span className="tag">{profile.peer_group || 'Standard'}</span>
                      </p>
                    </div>
                    <div style={{ textAlign: 'right' }}>
                      <div style={{ fontSize: '2rem', fontWeight: 900, color: getRiskColor(profile.risk_level) }}>
                        {fmtScore(profile.risk_score)}
                      </div>
                      <div style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: getRiskColor(profile.risk_level), textTransform: 'uppercase' }}>
                        {profile.risk_level} Risk
                      </div>
                    </div>
                  </div>

                  <hr style={{ margin: 'var(--sp-5) 0', opacity: 0.1 }} />

                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 'var(--sp-4)' }}>
                    <div className="info-item">
                      <span className="info-item-label">Typical Window</span>
                      <span className="info-item-value">{profile.typical_hours}</span>
                    </div>
                    <div className="info-item">
                      <span className="info-item-label">Avg Daily Traffic</span>
                      <span className="info-item-value">{(profile.avg_daily_bytes / 1024 / 1024).toFixed(1)} MB</span>
                    </div>
                    <div className="info-item">
                      <span className="info-item-label">Baseline Status</span>
                      <span className="info-item-value">
                        {profile.baseline_locked ? 'Locked & Enforcing' : 'In Training'}
                      </span>
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: 'var(--sp-3)', marginTop: 'var(--sp-6)' }}>
                    <button className="btn btn-primary">
                      <FileText size={14} /> View Events
                    </button>
                    <button
                      className="btn btn-ghost"
                      style={{ color: 'var(--danger)', borderColor: 'var(--danger)' }}
                      onClick={() => {
                        if (confirm(`Reset baseline for ${profile.username}? User will need new training period.`)) {
                          resetMutation.mutate(profile.username);
                        }
                      }}
                    >
                      <UserX size={14} /> Reset Baseline
                    </button>
                  </div>
                </div>

                <div className="card">
                  <div className="section-header">
                    <h3>Known Infrastructure</h3>
                  </div>
                  <div style={{ padding: 'var(--sp-4)', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--sp-4)' }}>
                    <div>
                      <h4 style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--text-muted)', marginBottom: 8 }}>FREQUENT IPs</h4>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                        {profile.known_ips?.map(ip => <span key={ip} className="tag" style={{ fontFamily: 'var(--font-mono)' }}>{ip}</span>)}
                        {!profile.known_ips?.length && 'No IPs recorded'}
                      </div>
                    </div>
                    <div>
                      <h4 style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--text-muted)', marginBottom: 8 }}>ACCESSED SERVICES</h4>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                        {profile.known_services?.map(s => <span key={s} className="tag">{s}</span>)}
                        {!profile.known_services?.length && 'No services recorded'}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="card" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-muted)', minHeight: 400 }}>
                <div style={{ textAlign: 'center' }}>
                  <User size={40} style={{ opacity: 0.2, marginBottom: 12 }} />
                  <p>Select a user to view detailed profile and risk analysis.</p>
                </div>
              </div>
            )}
          </div>
        )}

        {tab === 'alerts' && (
          <div className="card">
            <div className="section-header">
              <h3>Security Anomalies</h3>
              <span className="tag">Last 50 Events</span>
            </div>
            <table className="table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>User</th>
                  <th>Score</th>
                  <th>Detector</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {alerts?.alerts?.map((a, i) => (
                  <tr key={i}>
                    <td style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{new Date(a.event_time).toLocaleString()}</td>
                    <td style={{ fontWeight: 600 }}>{a.username}</td>
                    <td>
                      <span style={{ fontWeight: 700, color: getRiskColor(a.risk_level) }}>{fmtScore(a.anomaly_score)}</span>
                    </td>
                    <td>
                      <span className="badge" style={{ background: 'var(--bg-overlay)' }}>{a.detector_type || 'Unknown'}</span>
                    </td>
                    <td>
                      <span className={`badge ${a.blocked ? 'badge-danger' : 'badge-info'}`}>
                        {a.blocked ? 'BLOCKED' : 'MONITORED'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {tab === 'settings' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
            <div className="card" style={{ padding: 'var(--sp-6)' }}>
              <h3 style={{ marginBottom: 'var(--sp-6)' }}>Engine Configuration</h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-5)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <div style={{ fontWeight: 700 }}>Enable UBA Analysis</div>
                    <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>Globally profile user behavior and detect anomalies</div>
                  </div>
                  <label className="toggle">
                    <input type="checkbox" checked={status?.status === 'active'} readOnly />
                    <span className="toggle-slider" />
                  </label>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--sp-4)' }}>
                  <div className="form-group">
                    <label className="form-label">Auto-Block Risk Level</label>
                    <select className="input">
                      <option value="CRITICAL">Critical Only</option>
                      <option value="HIGH">High & Critical</option>
                      <option value="MEDIUM">Medium and above</option>
                      <option value="NONE">Monitor Only (Never block)</option>
                    </select>
                  </div>
                  <div className="form-group">
                    <label className="form-label">Training Period (Min Events)</label>
                    <input className="input" type="number" defaultValue={500} />
                  </div>
                </div>

                <div className="info-box-success" style={{ display: 'flex', gap: 'var(--sp-3)', alignItems: 'center' }}>
                  <ShieldAlert size={18} />
                  <div style={{ fontSize: 'var(--text-sm)' }}>
                    The UBA engine is currently using <strong>Ensemble Discovery</strong> mode. Results from 5 detectors are being aggregated.
                  </div>
                </div>
              </div>
            </div>

            {/* Causal Deception Engine Card */}
            <div className="card" style={{ padding: 'var(--sp-6)', border: '1px solid rgba(255,180,0,0.3)', background: 'linear-gradient(135deg, var(--bg-card), rgba(255,180,0,0.04))' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-3)', marginBottom: 'var(--sp-5)' }}>
                <div style={{ padding: 8, background: 'rgba(255,180,0,0.15)', borderRadius: '50%' }}>
                  <Zap size={18} style={{ color: '#ffb400' }} />
                </div>
                <div>
                  <h3 style={{ color: '#ffb400', margin: 0 }}>Causal Deception Engine</h3>
                  <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: 0 }}>Patent-Pending Active Defense — Unified Deception Technology</p>
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: 'var(--sp-4)', background: 'var(--bg-raised)', borderRadius: 'var(--radius)', border: '1px solid rgba(255,180,0,0.15)' }}>
                <div>
                  <div style={{ fontWeight: 700 }}>Contextual Honeytoken Injection</div>
                  <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 4 }}>
                    When a user exceeds the high-risk threshold, the engine dynamically injects personalized fake files,
                    links, or credentials into the user's session. Any interaction proves malicious intent with 100% certainty.
                  </div>
                </div>
                <label className="toggle" style={{ marginLeft: 'var(--sp-5)', flexShrink: 0 }}>
                  <input
                    type="checkbox"
                    checked={ubaConfig?.deception_enabled ?? true}
                    onChange={() => updateConfigMutation.mutate({ ...ubaConfig, deception_enabled: !ubaConfig?.deception_enabled })}
                  />
                  <span className="toggle-slider" />
                </label>
              </div>

              <div style={{ marginTop: 'var(--sp-4)', padding: 'var(--sp-3) var(--sp-4)', background: 'rgba(255,180,0,0.08)', borderRadius: 'var(--radius)', fontSize: 'var(--text-xs)', color: '#ffb400', display: 'flex', gap: 8, alignItems: 'center' }}>
                <Zap size={12} />
                <span>Powered by the <strong>Unified Causal Deception Engine</strong> — Cross-module traps share a common intent verification pool.</span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
