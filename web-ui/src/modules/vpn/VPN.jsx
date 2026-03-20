import React, { useState, useEffect } from 'react';
import { Shield, Play, Square, Settings, Users, Plus, Trash2, Key, Server, Hash, RefreshCw, X, AlertCircle } from 'lucide-react';
import './VPN.css';

export default function VPN() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [actionLoading, setActionLoading] = useState(false);
  
  // State
  const [status, setStatus] = useState("Interface down");
  const [interfaceName, setInterfaceName] = useState("wg0");
  const [config, setConfig] = useState({
    enabled: true, listen_port: 51820, server_ip: "10.10.0.1/24", dns: "", mtu: 1420
  });
  const [peers, setPeers] = useState([]);
  
  // Modals
  const [showAddPeer, setShowAddPeer] = useState(false);
  const [newPeer, setNewPeer] = useState({
    name: "", public_key: "", allowed_ips: "10.10.0.2/32", endpoint: "", persistent_keepalive: 25
  });

  // Derived state
  const isActive = status !== "Interface down" && status.includes("interface: ");

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    setLoading(true);
    try {
      await Promise.all([
        fetchStatus(),
        fetchConfig(),
        fetchPeers()
      ]);
    } catch (err) {
      setError("Failed to load VPN data. Is the backend running?");
    } finally {
      setLoading(false);
    }
  };

  const fetchStatus = async () => {
    const res = await fetch('/api/v1/vpn/status', {
      headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
    });
    if (res.ok) {
      const data = await res.json();
      setStatus(data.status);
      if (data.interface) setInterfaceName(data.interface);
    }
  };

  const fetchConfig = async () => {
    const res = await fetch('/api/v1/vpn/config', {
      headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
    });
    if (res.ok) {
      const data = await res.json();
      if (data.server_ip) setConfig(data);
    }
  };

  const fetchPeers = async () => {
    const res = await fetch('/api/v1/vpn/peers', {
      headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
    });
    if (res.ok) {
      const data = await res.json();
      setPeers(data.peers || []);
    }
  };

  // Actions
  const handleToggleVPN = async () => {
    setActionLoading(true);
    try {
      const endpoint = isActive ? '/api/v1/vpn/stop' : '/api/v1/vpn/start';
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
      });
      
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || `Failed to ${isActive ? 'stop' : 'start'} VPN`);
      }
      
      // Give system a second to apply before fetching status
      setTimeout(() => {
        fetchStatus();
        setActionLoading(false);
      }, 500);
    } catch (err) {
      alert(err.message);
      setActionLoading(false);
    }
  };

  const handleSaveConfig = async (e) => {
    e.preventDefault();
    setActionLoading(true);
    try {
      const res = await fetch('/api/v1/vpn/config', {
        method: 'PUT',
        headers: { 
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(config)
      });
      
      if (res.ok) {
        alert("Configuration saved successfully. If VPN is active, restart it to apply changes.");
      } else {
        throw new Error("Failed to save config");
      }
    } catch (err) {
      alert(err.message);
    } finally {
      setActionLoading(false);
    }
  };

  const handleAddPeer = async (e) => {
    e.preventDefault();
    setActionLoading(true);
    try {
      const formattedPeer = {
        ...newPeer,
        allowed_ips: newPeer.allowed_ips.split(',').map(ip => ip.trim())
      };

      const res = await fetch('/api/v1/vpn/peers', {
        method: 'POST',
        headers: { 
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(formattedPeer)
      });
      
      if (res.ok) {
        fetchPeers();
        setShowAddPeer(false);
        setNewPeer({ name: "", public_key: "", allowed_ips: "10.10.0.x/32", endpoint: "", persistent_keepalive: 25 });
        if (isActive) setTimeout(fetchStatus, 500);
      } else {
        const err = await res.json();
        throw new Error(err.detail || "Failed to add peer");
      }
    } catch (err) {
      alert(err.message);
    } finally {
      setActionLoading(false);
    }
  };

  const handleRemovePeer = async (pubkey) => {
    if (!confirm("Are you sure you want to remove this peer?")) return;
    
    setActionLoading(true);
    try {
      const res = await fetch(`/api/v1/vpn/peers/${encodeURIComponent(pubkey)}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
      });
      
      if (res.ok) {
        fetchPeers();
        if (isActive) setTimeout(fetchStatus, 500);
      } else {
        throw new Error("Failed to remove peer");
      }
    } catch (err) {
      alert(err.message);
    } finally {
      setActionLoading(false);
    }
  };

  const handleGenerateKeys = async () => {
    try {
      const res = await fetch('/api/v1/vpn/keys/generate', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
      });
      if (res.ok) {
        const data = await res.json();
        setNewPeer(prev => ({ ...prev, public_key: data.public_key }));
        alert(`New Keypair Generated!\n\nPrivate Key (Give to Client ONLY):\n${data.private_key}\n\nPublic Key (Saved): ${data.public_key}`);
      }
    } catch (err) {
      alert("Failed to generate keys");
    }
  };

  if (loading && !status) return <div className="module-page" style={{display: 'flex', alignItems: 'center', justifyContent: 'center', height: '50vh'}}><RefreshCw className="animate-spin" size={32} style={{color: 'var(--accent)'}}/></div>;

  return (
    <div className="module-page">
      <div className="page-header">
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Shield size={24} style={{ color: 'var(--accent)' }} /> 
            WireGuard VPN Dashboard
          </h1>
          <p className="page-subtitle">Manage Site-to-Site and Remote Access VPN tunnels securely.</p>
        </div>
        <button className="btn-secondary" onClick={fetchData} disabled={actionLoading}>
          <RefreshCw size={16} className={actionLoading ? 'animate-spin' : ''} /> Refresh
        </button>
      </div>

      {error ? (
        <div className="alert error" style={{marginBottom: 20}}>
          <AlertCircle size={18} /> {error}
        </div>
      ) : (
        <div className="vpn-container">
          {/* Status Card */}
          <div className="vpn-status-card">
            <div className="status-info">
              <div className={`status-icon-wrapper ${isActive ? 'active' : 'inactive'}`}>
                <Shield size={28} />
              </div>
              <div className="status-details">
                <h2>
                  Interface: {interfaceName}
                  <span className={`status-badge ${isActive ? 'active' : 'inactive'}`}>
                    {isActive ? 'Running' : 'Stopped'}
                  </span>
                </h2>
                <p>{isActive ? `VPN is actively routing traffic on ${config.server_ip}` : 'VPN engine is completely disabled'}</p>
              </div>
            </div>
            
            <button 
              className={`vpn-action-btn ${isActive ? 'stop' : 'start'}`}
              onClick={handleToggleVPN}
              disabled={actionLoading}
            >
              {actionLoading ? <RefreshCw size={18} className="animate-spin" /> : 
                isActive ? <><Square size={18} fill="currentColor" /> Stop Server</> : 
                          <><Play size={18} fill="currentColor"/> Start Server</>
              }
            </button>
          </div>

          <div className="vpn-content-grid">
            {/* Left Col: Peers List */}
            <div className="peers-panel">
              <div className="peers-header">
                <h3><Users size={20} /> VPN Peers (Clients)</h3>
                <button className="btn-primary" onClick={() => setShowAddPeer(true)}>
                  <Plus size={16} /> Add Peer
                </button>
              </div>
              <div className="table-container">
                <table className="peers-table">
                  <thead>
                    <tr>
                      <th>Name / Identifier</th>
                      <th>Public Key</th>
                      <th>Allowed IPs</th>
                      <th>Endpoint</th>
                      <th style={{textAlign: 'right'}}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {peers.length === 0 ? (
                      <tr>
                        <td colSpan="5" style={{textAlign: 'center', padding: '2rem', color: 'var(--text-muted)'}}>
                          No peers configured yet. Add your first client.
                        </td>
                      </tr>
                    ) : (
                      peers.map(peer => (
                        <tr key={peer.public_key}>
                          <td>
                            <div className="peer-name">{peer.name || 'Unnamed Peer'}</div>
                            <div style={{fontSize: 12, color: 'var(--text-muted)', marginTop: 2}}>
                              Keepalive: {peer.persistent_keepalive}s
                            </div>
                          </td>
                          <td><span className="peer-pubkey">{peer.public_key.substring(0, 16)}...</span></td>
                          <td>
                            <div style={{display: 'flex', flexWrap: 'wrap', gap: 4}}>
                              {peer.allowed_ips.map(ip => (
                                <span key={ip} className="badge" style={{background: 'rgba(255,255,255,0.05)', fontSize: 11}}>
                                  {ip}
                                </span>
                              ))}
                            </div>
                          </td>
                          <td>{peer.endpoint || '-'}</td>
                          <td style={{textAlign: 'right'}}>
                            <button className="btn-icon" onClick={() => handleRemovePeer(peer.public_key)} title="Remove Peer">
                              <Trash2 size={16} />
                            </button>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Right Col: Server Config */}
            <div className="config-panel">
              <div className="config-header">
                <h3><Settings size={18} /> Global Config</h3>
              </div>
              <form onSubmit={handleSaveConfig}>
                <div className="form-group">
                  <label><Server size={14} style={{display:'inline', marginRight: 4, verticalAlign: 'text-bottom'}}/> Server Subnet (CIDR)</label>
                  <input type="text" className="form-input" value={config.server_ip} onChange={e => setConfig({...config, server_ip: e.target.value})} required placeholder="10.10.0.1/24" />
                </div>
                <div className="form-group">
                  <label><Hash size={14} style={{display:'inline', marginRight: 4, verticalAlign: 'text-bottom'}}/> Listen Port</label>
                  <input type="number" className="form-input" value={config.listen_port} onChange={e => setConfig({...config, listen_port: parseInt(e.target.value)})} required />
                </div>
                <div className="form-group">
                  <label>DNS Server (Optional)</label>
                  <input type="text" className="form-input" value={config.dns || ''} onChange={e => setConfig({...config, dns: e.target.value})} placeholder="e.g. 1.1.1.1" />
                </div>
                <div className="form-group">
                  <label>MTU</label>
                  <input type="number" className="form-input" value={config.mtu} onChange={e => setConfig({...config, mtu: parseInt(e.target.value)})} />
                </div>
                <button type="submit" className="btn-secondary" style={{width: '100%', marginTop: 'var(--sp-2)'}} disabled={actionLoading}>
                  Save Configuration
                </button>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* Add Peer Modal */}
      {showAddPeer && (
        <div className="modal-overlay" onClick={() => setShowAddPeer(false)}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Add VPN Client (Peer)</h3>
              <button className="btn-icon" onClick={() => setShowAddPeer(false)}><X size={20}/></button>
            </div>
            <form onSubmit={handleAddPeer}>
              <div className="modal-body">
                <div className="form-group">
                  <label>Client Name (Identifier)</label>
                  <input type="text" className="form-input" required value={newPeer.name} onChange={e => setNewPeer({...newPeer, name: e.target.value})} placeholder="e.g. CEO Laptop" autoFocus/>
                </div>
                <div className="form-group">
                  <label style={{display: 'flex', justifyContent: 'space-between'}}>
                    Public Key
                    <button type="button" className="generate-key-btn" onClick={handleGenerateKeys}>
                      <Key size={12}/> Generate Keypair
                    </button>
                  </label>
                  <input type="text" className="form-input" required value={newPeer.public_key} onChange={e => setNewPeer({...newPeer, public_key: e.target.value})} placeholder="Base64 Public Key from Client" />
                </div>
                <div className="form-group">
                  <label>Allowed IPs (Comma separated)</label>
                  <input type="text" className="form-input" required value={newPeer.allowed_ips} onChange={e => setNewPeer({...newPeer, allowed_ips: e.target.value})} placeholder="10.10.0.2/32" />
                  <span style={{fontSize: 11, color: 'var(--text-muted)'}}>The VPN IPs this client will use.</span>
                </div>
                <div className="form-group">
                  <label>Endpoint URL / IP (Optional for dial-in clients)</label>
                  <input type="text" className="form-input" value={newPeer.endpoint} onChange={e => setNewPeer({...newPeer, endpoint: e.target.value})} placeholder="peer.example.com:51820" />
                </div>
              </div>
              <div className="modal-footer">
                <button type="button" className="btn-secondary" onClick={() => setShowAddPeer(false)}>Cancel</button>
                <button type="submit" className="btn-primary" disabled={actionLoading}>Add Peer</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
