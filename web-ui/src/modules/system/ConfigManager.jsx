import React, { useState, useEffect } from 'react';
import { enterpriseApi } from '../../services/api';
import './Enterprise.css';

export default function ConfigManager() {
  const [versions, setVersions] = useState([]);
  const [selectedVersion, setSelectedVersion] = useState(null);
  const [diff, setDiff] = useState(null);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const fetchVersions = async () => {
    try {
      setLoading(true);
      const res = await enterpriseApi.configVersions();
      setVersions(res.data.versions || []);
      setError('');
    } catch (err) {
      setError('Failed to load configuration history.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchVersions();
  }, []);

  const handleDiff = async (versionStr) => {
    try {
       setDiff(null);
       const current = versions[0]?.version_id; // normally the first is active/latest
       const res = await enterpriseApi.configDiff(current, versionStr);
       setDiff({ target: versionStr, changes: res.data.diff });
       setSelectedVersion(versionStr);
    } catch(err) {
       setError('Failed to generate diff.');
    }
  };

  const handleRollback = async (versionStr) => {
    if (!window.confirm(`⚠️ WARNING: Critical Action\n\nAre you sure you want to rollback the entire system configuration to version [${versionStr}]? This will hot-reload all modules immediately.`)) return;
    
    try {
      setActionLoading(true);
      await enterpriseApi.configRollback(versionStr);
      setSuccess(`Successfully rolled back to configuration version ${versionStr}`);
      setTimeout(() => setSuccess(''), 5000);
      await fetchVersions();
      setDiff(null);
      setSelectedVersion(null);
    } catch (err) {
      setError(err.response?.data?.detail || 'Rollback failed.');
    } finally {
      setActionLoading(false);
    }
  };

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <div className="mb-8">
        <h1 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-indigo-500">
          Configuration Manager
        </h1>
        <p className="text-slate-400 text-sm mt-1">
          Version Control, Snapshots, and Emergency Rollbacks
        </p>
      </div>

      {error && <div className="mb-6 p-4 bg-rose-900/30 border border-rose-500/50 text-rose-300 rounded-lg">{error}</div>}
      {success && <div className="mb-6 p-4 bg-emerald-900/30 border border-emerald-500/50 text-emerald-300 rounded-lg">{success}</div>}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        
        {/* Left Column: History */}
        <div className="bg-slate-800 border border-slate-700 rounded-xl max-h-[700px] flex flex-col shadow-lg">
          <div className="p-4 border-b border-slate-700 font-bold text-white flex justify-between items-center">
             <span>Snapshot History</span>
             <button onClick={fetchVersions} className="text-slate-400 hover:text-white transition">
                <i className="fi fi-rr-refresh"></i>
             </button>
          </div>
          
          <div className="flex-1 overflow-y-auto p-4 space-y-3">
             {loading ? (
                <div className="text-slate-500 text-center py-4">Loading history...</div>
             ) : versions.length === 0 ? (
                <div className="text-slate-500 text-center py-4">No snapshots found.</div>
             ) : (
                versions.map((ver, idx) => {
                   const isActive = idx === 0;
                   const isSelected = selectedVersion === ver.version_id;
                   
                   return (
                     <div 
                        key={ver.version_id} 
                        onClick={() => !isActive && handleDiff(ver.version_id)}
                        className={`p-4 rounded-lg border transition cursor-pointer ${
                           isActive 
                             ? 'bg-indigo-900/30 border-indigo-500 cursor-default' 
                             : isSelected 
                               ? 'bg-slate-700 border-slate-500 hover:bg-slate-600'
                               : 'bg-slate-900/50 border-slate-700/50 hover:border-slate-600'
                        }`}
                     >
                        <div className="flex justify-between items-start mb-2">
                           <span className="font-mono text-sm font-bold text-slate-200">
                             {ver.version_id.substring(0, 15)}
                           </span>
                           {isActive && <span className="bg-indigo-500 text-white text-[10px] px-2 py-0.5 rounded-full font-bold">ACTIVE</span>}
                        </div>
                        <div className="text-xs flex items-center text-slate-400">
                           <i className="fi fi-rr-calendar-clock mr-1"></i> {new Date(ver.created_at).toLocaleString()}
                        </div>
                        <div className="text-xs mt-2 text-slate-500 capitalize">
                           Trigger: {ver.source || 'Manual Update'}
                        </div>
                     </div>
                   );
                })
             )}
          </div>
        </div>

        {/* Right Column: Diff & Actions */}
        <div className="lg:col-span-2 space-y-6">
           {/* Diff Viewer */}
           <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden shadow-lg h-full flex flex-col">
              <div className="p-4 border-b border-slate-700 font-bold text-white flex items-center">
                 <i className="fi fi-rr-file-diff mr-2 text-indigo-400"></i> Configuration Diff Review
              </div>
              
              <div className="p-0 flex-1 bg-slate-900/80 font-mono text-xs overflow-x-auto">
                 {!diff ? (
                    <div className="h-full flex items-center justify-center text-slate-500 p-8">
                       Select an older snapshot from the left to view the difference compared to the current active configuration.
                    </div>
                 ) : (
                    <div className="p-4 space-y-1">
                       <div className="mb-4 text-slate-400 border-b border-slate-700 pb-2">
                          Comparing <span className="text-indigo-400">Active</span> vs <span className="text-amber-400">{diff.target}</span>
                       </div>
                       
                       {Object.keys(diff.changes || {}).length === 0 ? (
                          <div className="text-emerald-400 py-4">No meaningful changes detected. The configurations might be identical.</div>
                       ) : (
                          Object.entries(diff.changes).map(([key, change]) => (
                             <div key={key} className="py-2 border-b border-slate-800/50 last:border-0 grid grid-cols-1 md:grid-cols-2 gap-4">
                                <div className="text-slate-300 font-bold col-span-full">{key}</div>
                                <div className="bg-rose-900/20 text-rose-300 p-2 rounded whitespace-pre-wrap overflow-x-auto border border-rose-900/50">
                                   <div className="text-[10px] text-rose-500 mb-1 font-sans font-bold">ACTIVE VALUE:</div>
                                   {JSON.stringify(change.old, null, 2)}
                                </div>
                                <div className="bg-emerald-900/20 text-emerald-300 p-2 rounded whitespace-pre-wrap overflow-x-auto border border-emerald-900/50">
                                   <div className="text-[10px] text-emerald-500 mb-1 font-sans font-bold">SNAPSHOT VALUE:</div>
                                   {JSON.stringify(change.new, null, 2)}
                                </div>
                             </div>
                          ))
                       )}
                    </div>
                 )}
              </div>
              
              {/* Actions Footer */}
              {diff && (
                  <div className="p-4 bg-slate-900 border-t border-slate-700 flex justify-end">
                     <button
                        onClick={() => handleRollback(diff.target)}
                        disabled={actionLoading}
                        className="bg-amber-600 hover:bg-amber-500 text-white font-bold py-2 px-6 rounded-lg shadow-lg flex items-center transition disabled:opacity-50"
                     >
                        {actionLoading ? (
                           <><i className="fi fi-rr-spinner animate-spin mr-2"></i> Executing...</>
                        ) : (
                           <><i className="fi fi-rr-time-past mr-2"></i> Rollback to this Snapshot</>
                        )}
                     </button>
                  </div>
              )}
           </div>
        </div>

      </div>
    </div>
  );
}
