import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ShieldOff, ShieldCheck, Plus, Trash2, RefreshCw,
  AlertTriangle, Wifi, Clock, User, X, Check
} from 'lucide-react';
import { firewallApi } from '../../services/api';

// ── Helpers ──────────────────────────────────────────────────────────────────

function fmtTime(ts) {
  if (!ts) return '—';
  return new Date(ts * 1000).toLocaleString();
}

function fmtExpiry(ts) {
  if (!ts) return 'Permanent';
  const d = new Date(ts * 1000);
  const now = new Date();
  const diff = d - now;
  if (diff <= 0) return 'Expired';
  const mins = Math.floor(diff / 60000);
  const hrs = Math.floor(mins / 60);
  if (hrs > 0) return `${hrs}h ${mins % 60}m`;
  return `${mins}m`;
}

// ── Block IP Modal ────────────────────────────────────────────────────────────

function BlockModal({ onClose, onConfirm, loading }) {
  const [ip, setIp] = useState('');
  const [reason, setReason] = useState('Manual block');
  const [duration, setDuration] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!ip.trim()) return;
    onConfirm(ip.trim(), reason, duration ? parseInt(duration) : null);
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-card" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h3 style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <ShieldOff size={18} style={{ color: 'var(--danger)' }} />
            Block IP Address
          </h3>
          <button className="icon-btn" onClick={onClose}><X size={16} /></button>
        </div>

        <form onSubmit={handleSubmit} className="modal-body">
          <div className="form-group">
            <label className="form-label">IP Address *</label>
            <input
              className="input"
              placeholder="e.g. 192.168.1.100"
              value={ip}
              onChange={e => setIp(e.target.value)}
              required
              autoFocus
            />
          </div>

          <div className="form-group">
            <label className="form-label">Reason</label>
            <input
              className="input"
              placeholder="Reason for blocking"
              value={reason}
              onChange={e => setReason(e.target.value)}
            />
          </div>

          <div className="form-group">
            <label className="form-label">Duration (seconds) — leave empty for permanent</label>
            <input
              className="input"
              type="number"
              placeholder="e.g. 3600 for 1 hour, blank = permanent"
              value={duration}
              onChange={e => setDuration(e.target.value)}
              min={60}
            />
          </div>

          <div className="modal-actions">
            <button type="button" className="btn btn-ghost" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn btn-danger" disabled={loading || !ip.trim()}>
              {loading ? <RefreshCw size={14} className="spin" /> : <ShieldOff size={14} />}
              Block IP
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function IPBlocklist() {
  const qc = useQueryClient();
  const [showModal, setShowModal] = useState(false);
  const [confirmClear, setConfirmClear] = useState(false);

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['blocked-ips'],
    queryFn: () => firewallApi.blockedIps().then(r => r.data),
    refetchInterval: 15000,
  });

  const blockedList = data?.blocked_ips ?? [];
  const stats = data?.stats ?? {};

  const blockMutation = useMutation({
    mutationFn: ({ ip, reason, duration }) => firewallApi.blockIp(ip, reason, duration),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['blocked-ips'] });
      setShowModal(false);
    },
  });

  const unblockMutation = useMutation({
    mutationFn: (ip) => firewallApi.unblockIp(ip),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['blocked-ips'] }),
  });

  const clearAllMutation = useMutation({
    mutationFn: () => firewallApi.unblockAll(),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['blocked-ips'] });
      setConfirmClear(false);
    },
  });

  return (
    <div className="module-page">
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <ShieldOff size={24} style={{ color: 'var(--danger)' }} />
            IP Blocklist
          </h1>
          <p className="page-subtitle">
            eBPF-enforced kernel-level IP blocks — instant hardware-speed drops
          </p>
        </div>
        <div style={{ display: 'flex', gap: 'var(--sp-3)' }}>
          <button className="btn btn-ghost" onClick={() => refetch()}>
            <RefreshCw size={15} /> Refresh
          </button>
          <button
            className="btn btn-ghost"
            style={{ borderColor: 'var(--danger)', color: 'var(--danger)' }}
            onClick={() => setConfirmClear(true)}
          >
            <Trash2 size={15} /> Clear All
          </button>
          <button className="btn btn-primary" onClick={() => setShowModal(true)}>
            <Plus size={15} /> Block IP
          </button>
        </div>
      </div>

      {/* Stats bar */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 'var(--sp-4)' }}>
        <div className="card" style={{ padding: 'var(--sp-4)', display: 'flex', alignItems: 'center', gap: 'var(--sp-3)' }}>
          <div style={{ width: 40, height: 40, borderRadius: '50%', background: 'var(--danger-dim)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <ShieldOff size={18} style={{ color: 'var(--danger)' }} />
          </div>
          <div>
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>BLOCKED IPs</div>
            <div style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--danger)' }}>{stats.total_blocked ?? blockedList.length}</div>
          </div>
        </div>

        <div className="card" style={{ padding: 'var(--sp-4)', display: 'flex', alignItems: 'center', gap: 'var(--sp-3)' }}>
          <div style={{ width: 40, height: 40, borderRadius: '50%', background: stats.ebpf_active ? 'var(--success-dim)' : 'var(--bg-overlay)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Wifi size={18} style={{ color: stats.ebpf_active ? 'var(--success)' : 'var(--text-muted)' }} />
          </div>
          <div>
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>eBPF ENGINE</div>
            <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: stats.ebpf_active ? 'var(--success)' : 'var(--text-muted)' }}>
              {stats.ebpf_active ? 'Active (Kernel)' : 'Software Mode'}
            </div>
          </div>
        </div>

        <div className="card" style={{ padding: 'var(--sp-4)', display: 'flex', alignItems: 'center', gap: 'var(--sp-3)' }}>
          <div style={{ width: 40, height: 40, borderRadius: '50%', background: 'var(--bg-overlay)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <ShieldCheck size={18} style={{ color: 'var(--accent)' }} />
          </div>
          <div>
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>PROTECTION</div>
            <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--accent)' }}>
              {stats.ebpf_active ? 'Zero-ms Drop' : 'Inspection Layer'}
            </div>
          </div>
        </div>
      </div>

      {/* Error / Loading */}
      {isLoading && (
        <div className="card" style={{ padding: 'var(--sp-6)', textAlign: 'center', color: 'var(--text-muted)' }}>
          <RefreshCw size={20} className="spin" style={{ marginBottom: 8 }} />
          <p>Loading blocklist…</p>
        </div>
      )}
      {isError && (
        <div className="card" style={{ padding: 'var(--sp-5)', borderColor: 'var(--danger)' }}>
          <p style={{ color: 'var(--danger)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <AlertTriangle size={16} /> Failed to load blocklist from backend
          </p>
        </div>
      )}

      {/* Blocklist Table */}
      {!isLoading && (
        <div className="card" style={{ overflow: 'hidden' }}>
          {blockedList.length === 0 ? (
            <div style={{ padding: 'var(--sp-8)', textAlign: 'center', color: 'var(--text-muted)' }}>
              <ShieldCheck size={40} style={{ marginBottom: 12, opacity: 0.4 }} />
              <p>No IP addresses are currently blocked.</p>
              <button className="btn btn-primary" style={{ marginTop: 'var(--sp-4)' }} onClick={() => setShowModal(true)}>
                <Plus size={14} /> Block First IP
              </button>
            </div>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th><Wifi size={12} style={{ marginRight: 4 }} />IP Address</th>
                  <th><AlertTriangle size={12} style={{ marginRight: 4 }} />Reason</th>
                  <th><User size={12} style={{ marginRight: 4 }} />Blocked By</th>
                  <th><Clock size={12} style={{ marginRight: 4 }} />Blocked At</th>
                  <th><Clock size={12} style={{ marginRight: 4 }} />Expires</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {blockedList.map(entry => (
                  <tr key={entry.ip} style={{ transition: 'opacity 0.2s' }}>
                    <td>
                      <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--danger)', fontSize: '0.9rem' }}>
                        {entry.ip}
                      </span>
                    </td>
                    <td style={{ color: 'var(--text-muted)', fontSize: 'var(--text-sm)' }}>
                      {entry.reason}
                    </td>
                    <td>
                      <span className="tag">{entry.blocked_by}</span>
                    </td>
                    <td style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)', fontFamily: 'var(--font-mono)' }}>
                      {fmtTime(entry.blocked_at)}
                    </td>
                    <td>
                      {entry.expires_at
                        ? <span className="badge badge-warning"><Clock size={10} /> {fmtExpiry(entry.expires_at)}</span>
                        : <span className="badge badge-danger">Permanent</span>
                      }
                    </td>
                    <td>
                      <button
                        className="btn btn-ghost"
                        style={{ fontSize: 'var(--text-xs)', gap: 4, padding: '4px 10px' }}
                        title={`Unblock ${entry.ip}`}
                        disabled={unblockMutation.isPending}
                        onClick={() => {
                          if (window.confirm(`Unblock ${entry.ip}?`)) {
                            unblockMutation.mutate(entry.ip);
                          }
                        }}
                      >
                        <Check size={13} style={{ color: 'var(--success)' }} /> Unblock
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Block IP Modal */}
      {showModal && (
        <BlockModal
          onClose={() => setShowModal(false)}
          onConfirm={(ip, reason, duration) => blockMutation.mutate({ ip, reason, duration })}
          loading={blockMutation.isPending}
        />
      )}

      {/* Confirm Clear All */}
      {confirmClear && (
        <div className="modal-overlay" onClick={() => setConfirmClear(false)}>
          <div className="modal-card" style={{ maxWidth: 420 }} onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3 style={{ color: 'var(--danger)', display: 'flex', alignItems: 'center', gap: 8 }}>
                <AlertTriangle size={18} /> Confirm Clear All
              </h3>
              <button className="icon-btn" onClick={() => setConfirmClear(false)}><X size={16} /></button>
            </div>
            <div className="modal-body">
              <p style={{ color: 'var(--text-muted)' }}>
                This will immediately unblock <strong style={{ color: 'var(--danger)' }}>{blockedList.length} IP{blockedList.length !== 1 ? 's' : ''}</strong> at the kernel level.
                Are you absolutely sure?
              </p>
              <div className="modal-actions">
                <button className="btn btn-ghost" onClick={() => setConfirmClear(false)}>Cancel</button>
                <button
                  className="btn btn-danger"
                  disabled={clearAllMutation.isPending}
                  onClick={() => clearAllMutation.mutate()}
                >
                  {clearAllMutation.isPending ? <RefreshCw size={14} className="spin" /> : <Trash2 size={14} />}
                  Clear All IPs
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
