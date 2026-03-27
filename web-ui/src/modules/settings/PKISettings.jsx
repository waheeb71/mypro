import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { certificatesApi } from '../../services/api';
import { Shield, Key, Download, RefreshCw, AlertTriangle } from 'lucide-react';

export default function PKISettings() {
  const qc = useQueryClient();

  const { data: certInfo, isLoading } = useQuery({
    queryKey: ['ca-cert-info'],
    queryFn: () => certificatesApi.info().then(r => r.data),
    retry: false,
  });

  const generateMut = useMutation({
    mutationFn: () => certificatesApi.generate(),
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ['ca-cert-info'] });
      alert(data.data.message || 'Key regeneration successful!');
    },
    onError: (err) => {
      alert(`Failed to regenerate keys: ${err.message}`);
    }
  });

  const handleDownload = async (format) => {
    try {
      const resp = await certificatesApi.download(format);
      const url = window.URL.createObjectURL(new Blob([resp.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `CyberNexus-Root-CA.${format}`);
      document.body.appendChild(link);
      link.click();
      link.parentNode.removeChild(link);
    } catch (err) {
      alert(`Download failed: ${err.message}`);
    }
  };

  if (isLoading) return <div className="settings-loading"><RefreshCw className="spin" /> Inspecting cryptographic materials...</div>;

  return (
    <div style={{ padding: 'var(--sp-4)' }}>
      <div style={{ marginBottom: 'var(--sp-6)' }}>
        <h2 style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--success)' }}>
          <Key size={20} /> Identity & PKI Management
        </h2>
        <p style={{ color: 'var(--text-secondary)' }}>Manage the Enterprise NGFW Transparent Interception Root Certificate Authority (CA).</p>
      </div>

      {certInfo?.status === 'active' ? (
        <div className="card" style={{ padding: 'var(--sp-5)', marginBottom: 'var(--sp-5)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 'var(--sp-4)' }}>
            <Shield size={24} style={{ color: 'var(--success)' }} />
            <div>
              <h3 style={{ margin: 0, fontSize: 'var(--text-md)', color: 'var(--text-primary)' }}>Active Root CA</h3>
              <p style={{ margin: 0, fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>Used for SSL/TLS Deep Packet Inspection</p>
            </div>
          </div>
          
          <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)', gap: 'var(--sp-4)', background: 'var(--bg-overlay)', padding: 'var(--sp-4)', borderRadius: 6, marginBottom: 'var(--sp-5)' }}>
             <div>
               <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', marginBottom: 4 }}>Subject Name</div>
               <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', wordBreak: 'break-all' }}>{certInfo.subject}</div>
             </div>
             <div>
               <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', marginBottom: 4 }}>Fingerprint (SHA-256)</div>
               <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', wordBreak: 'break-all' }}>{certInfo.fingerprint}</div>
             </div>
             <div>
               <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', marginBottom: 4 }}>Valid From</div>
               <div style={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}>{new Date(certInfo.valid_from).toLocaleString()}</div>
             </div>
             <div>
               <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', marginBottom: 4 }}>Valid To</div>
               <div style={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}>{new Date(certInfo.valid_to).toLocaleString()}</div>
             </div>
          </div>

          <div style={{ display: 'flex', gap: 'var(--sp-3)', flexWrap: 'wrap' }}>
            <button className="btn btn-primary" onClick={() => handleDownload('pem')}>
              <Download size={14} /> Download (.pem)
            </button>
            <button className="btn btn-ghost" onClick={() => handleDownload('der')} style={{ border: '1px solid var(--border)' }}>
              Download (.der)
            </button>
            <button className="btn btn-ghost" onClick={() => handleDownload('p12')} style={{ border: '1px solid var(--border)' }}>
              <Key size={14} /> Download PFX (.p12)
            </button>
          </div>
        </div>
      ) : (
        <div className="card" style={{ padding: 'var(--sp-5)', marginBottom: 'var(--sp-5)', border: '1px solid var(--error-color)' }}>
           <h3 style={{ color: 'var(--error-color)', display: 'flex', alignItems: 'center', gap: 6 }}>
             <AlertTriangle size={18} /> No Root CA Installed!
           </h3>
           <p style={{ color: 'var(--text-secondary)' }}>The system currently has no cryptographic identity material to perform SSL proxying.</p>
        </div>
      )}

      {/* Danger Zone */}
      <div className="card" style={{ padding: 'var(--sp-5)', border: '1px solid var(--error-color)' }}>
         <h3 style={{ color: 'var(--error-color)', display: 'flex', alignItems: 'center', gap: 6, marginBottom: 'var(--sp-3)' }}>
           <AlertTriangle size={18} /> Danger Zone
         </h3>
         <p style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-sm)', marginBottom: 'var(--sp-4)' }}>
           Generating a new Root CA will invalidate all previous certificates injected into client machines. Active SSL interception connections will drop immediately until clients install the new certificate.
         </p>
         <button 
           className="btn btn-ghost" 
           onClick={() => {
             if (window.confirm("Are you ABSOLUTELY SURE you want to overwrite the existing Root CA? This causes immediate TLS errors on all proxy clients until updated.")) {
               generateMut.mutate();
             }
           }} 
           style={{ color: 'var(--error-color)', border: '1px solid var(--error-color)' }}
           disabled={generateMut.isPending}
         >
           {generateMut.isPending ? 'Generating 4096-bit Keys...' : 'Generate New Root CA'}
         </button>
      </div>

    </div>
  );
}
