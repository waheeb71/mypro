import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { responseApi } from '../../services/api';
import { Shield, Trash2, RefreshCw } from 'lucide-react';

export default function ActiveBlocks() {
  const qc = useQueryClient();

  const { data: blocks = [], isLoading } = useQuery({
    queryKey: ['active-blocks'],
    queryFn: () => responseApi.blocks().then(r => r.data?.active_blocks || []),
    refetchInterval: 5000
  });

  const unblockMut = useMutation({
    mutationFn: (ip) => responseApi.unblock(ip),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['active-blocks'] });
    }
  });

  if (isLoading) return <div className="settings-loading"><RefreshCw className="spin" /> Loading Hardware Blocks...</div>;

  return (
    <div style={{ padding: 'var(--sp-4)' }}>
      <div style={{ marginBottom: 'var(--sp-6)' }}>
        <h2 style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--error-color)' }}>
          <Shield size={20} /> Response Orchestrator (eBPF Blocks)
        </h2>
        <p style={{ color: 'var(--text-secondary)' }}>Hardware-level IP blocklists currently enforced by the kernel.</p>
      </div>

      <div className="card" style={{ padding: 'var(--sp-4)' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: 'var(--text-sm)' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)', color: 'var(--text-secondary)' }}>
              <th style={{ padding: '8px 0' }}>Banned IP Address</th>
              <th>Reason</th>
              <th>Status</th>
              <th style={{ textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {blocks.length === 0 ? (
              <tr><td colSpan="4" style={{ padding: '16px 0', textAlign: 'center', color: 'var(--success)' }}>No active blocks. The system is clean.</td></tr>
            ) : blocks.map((b) => (
              <tr key={b.ip} style={{ borderBottom: '1px solid var(--border)' }}>
                <td style={{ padding: '12px 0', fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--error-color)' }}>{b.ip}</td>
                <td style={{ color: 'var(--text-primary)' }}>{b.reason}</td>
                <td>
                   <span className="badge badge-error">ENFORCED</span>
                </td>
                <td style={{ textAlign: 'right' }}>
                  <button 
                     className="btn btn-ghost" 
                     title="Remove Block"
                     onClick={() => unblockMut.mutate(b.ip)}
                     disabled={unblockMut.isPending}
                     style={{ color: 'var(--text-secondary)', padding: '4px' }}>
                    <Trash2 size={16} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
