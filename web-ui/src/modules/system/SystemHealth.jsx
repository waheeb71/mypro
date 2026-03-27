import React, { useState, useEffect } from 'react';
import { enterpriseApi } from '../../services/api';
import './Enterprise.css';

export default function SystemHealth() {
  const [health, setHealth] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  const fetchHealth = async () => {
    try {
      const res = await enterpriseApi.healthDetailed();
      setHealth(res.data);
      setError('');
    } catch (err) {
      setError('Failed to fetch detailed system health.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, 5000); // Live update every 5s
    return () => clearInterval(interval);
  }, []);

  if (loading) return <div className="p-4 text-slate-300">Loading System Health...</div>;
  if (error) return <div className="p-4 text-red-400">{error}</div>;
  if (!health) return null;

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-indigo-500">
            System Health Center
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Enterprise Control Plane Monitoring & Circuit Breakers
          </p>
        </div>
        <div className="flex items-center space-x-2">
           <span className="relative flex h-3 w-3">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span>
          </span>
          <span className="text-slate-300 text-sm font-medium">Live Feed</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
        
        {/* High Availability (HA) Status */}
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-5 shadow-lg">
          <h2 className="text-lg font-bold text-white mb-4 flex items-center">
             <i className="fi fi-rr-cloud-share mr-2 text-indigo-400"></i> High Availability Cluster
          </h2>
          <div className="space-y-4">
            <div className={`p-4 rounded-lg flex justify-between items-center ${health.ha?.is_leader ? 'bg-indigo-900/40 border border-indigo-500/30' : 'bg-slate-900/50'}`}>
              <div className="text-slate-300">Node Role</div>
              <div className={`font-mono font-bold ${health.ha?.is_leader ? 'text-indigo-400' : 'text-slate-400'}`}>
                {health.ha?.is_leader ? 'MASTER' : (health.ha?.enabled ? 'BACKUP' : 'STANDALONE')}
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="bg-slate-900/50 p-3 rounded-lg border border-slate-700/50">
                <div className="text-xs text-slate-500 mb-1">State Sync</div>
                <div className={`font-bold ${health.state_sync?.etcd_connected ? 'text-emerald-400' : 'text-amber-400'}`}>
                   {health.state_sync?.etcd_connected ? 'Connected' : 'Local Only'}
                </div>
              </div>
              <div className="bg-slate-900/50 p-3 rounded-lg border border-slate-700/50">
                <div className="text-xs text-slate-500 mb-1">Local Keys</div>
                <div className="font-bold text-slate-200">{health.state_sync?.local_keys || 0}</div>
              </div>
            </div>
          </div>
        </div>

        {/* CPU Core Affinity */}
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-5 shadow-lg">
          <h2 className="text-lg font-bold text-white mb-4 flex items-center">
             <i className="fi fi-rr-cpu mr-2 text-amber-400"></i> CPU Core Affinity
          </h2>
          <div className="space-y-4">
             <div className="flex items-center justify-between px-2 text-sm text-slate-400 mb-2">
                <span>Core Distribution</span>
                <span>{health.affinity?.total_logical_cores} Logical Cores</span>
             </div>
             
             {health.affinity?.roles && Object.entries(health.affinity.roles).map(([role, cores]) => (
                <div key={role} className="flex flex-col mb-3 last:mb-0">
                  <div className="flex justify-between text-sm mb-1">
                    <span className="text-slate-300 capitalize">{role.replace('_', ' ')}</span>
                    <span className="text-slate-500 text-xs">{cores.length} Cores</span>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {cores.map(c => (
                      <span key={c} className={`text-xs px-2 py-1 rounded font-mono ${role === 'data_plane' ? 'bg-amber-900/50 text-amber-300 border border-amber-500/30' : 'bg-slate-700 text-slate-300'}`}>
                        CPU {c}
                      </span>
                    ))}
                  </div>
                </div>
             ))}
             {!health.affinity?.pinned && (
                 <div className="text-amber-400 text-sm p-3 bg-amber-900/20 rounded border border-amber-900 border-dashed text-center">
                     Core pinning is currently disabled.
                 </div>
             )}
          </div>
        </div>
        
        {/* System Overview */}
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-5 shadow-lg">
           <h2 className="text-lg font-bold text-white mb-4 flex items-center">
             <i className="fi fi-rr-chart-pie-alt mr-2 text-blue-400"></i> Platform Status
          </h2>
          <div className="space-y-3">
             <div className="flex justify-between p-3 bg-slate-900/50 rounded-lg">
                <span className="text-slate-400">eBPF Acceleration</span>
                <span className={`font-medium ${health.ebpf_active ? 'text-emerald-400' : 'text-slate-500'}`}>
                   {health.ebpf_active ? 'ACTIVE' : 'INACTIVE'}
                </span>
             </div>
             <div className="flex justify-between p-3 bg-slate-900/50 rounded-lg">
                <span className="text-slate-400">mTLS Inter-Service</span>
                <span className={`font-medium ${health.mtls_active ? 'text-emerald-400' : 'text-slate-500'}`}>
                   {health.mtls_active ? 'ENABLED' : 'DISABLED'}
                </span>
             </div>
             <div className="flex justify-between p-3 bg-slate-900/50 rounded-lg">
                <span className="text-slate-400">System Time</span>
                <span className="font-mono text-sm text-slate-300">
                   {new Date(health.timestamp * 1000).toLocaleTimeString()}
                </span>
             </div>
             <div className="flex justify-between p-3 bg-slate-900/50 rounded-lg">
                <span className="text-slate-400">Plugin Sandbox</span>
                <span className="font-medium text-emerald-400">WASM Ready</span>
             </div>
          </div>
        </div>

      </div>

      {/* Circuit Breakers Registry */}
      <div className="bg-slate-800 border border-slate-700 rounded-xl p-5 shadow-lg mt-6">
         <h2 className="text-lg font-bold text-white mb-6 flex items-center">
             <i className="fi fi-rr-shield-check mr-2 text-rose-400"></i> Circuit Breakers Registry
          </h2>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
             {Object.entries(health.circuit_breakers || {}).map(([module, cb]) => {
                
                let stateColor = 'bg-emerald-500';
                let stateBg = 'bg-emerald-900/20 border-emerald-500/30';
                if (cb.state === 'OPEN') {
                   stateColor = 'bg-rose-500 animate-pulse';
                   stateBg = 'bg-rose-900/20 border-rose-500/30';
                } else if (cb.state === 'HALF-OPEN') {
                   stateColor = 'bg-amber-500';
                   stateBg = 'bg-amber-900/20 border-amber-500/30';
                }

                return (
                 <div key={module} className={`p-4 rounded-xl border ${stateBg} flex flex-col`}>
                    <div className="flex justify-between items-start mb-4">
                       <span className="font-medium text-slate-200 truncate pr-2 capitalize">{module.replace('_', ' ')}</span>
                       <span className={`${stateColor} text-white text-[10px] font-bold px-2 py-0.5 rounded-full`}>
                          {cb.state}
                       </span>
                    </div>
                    
                    <div className="grid grid-cols-2 gap-2 mt-auto">
                        <div className="text-center p-2 bg-slate-900/50 rounded">
                           <div className="text-[10px] text-slate-500 uppercase tracking-wide">Fails</div>
                           <div className="text-sm font-bold text-slate-300">{cb.failures}</div>
                        </div>
                        <div className="text-center p-2 bg-slate-900/50 rounded">
                           <div className="text-[10px] text-slate-500 uppercase tracking-wide">Next Check</div>
                           <div className="text-sm font-mono text-slate-300">
                             {cb.reset_timeout_s > 0 ? `${cb.reset_timeout_s}s` : 'Ready'}
                           </div>
                        </div>
                    </div>
                 </div>
             )})}
             
             {Object.keys(health.circuit_breakers || {}).length === 0 && (
                <div className="col-span-full py-8 text-center text-slate-500">
                   No circuit breakers registered yet. They will appear here once modules execute.
                </div>
             )}
          </div>
      </div>
    </div>
  );
}
