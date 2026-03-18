import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { systemApi } from '../../services/api';
import { Save, RefreshCw, FileText, Server, Shield, Layers, Plus } from 'lucide-react';
import './Settings.css';

export default function Settings() {
  const [activeFile, setActiveFile] = useState('base.yaml');
  const [expandedSections, setExpandedSections] = useState({});
  const qc = useQueryClient();

  // Fetch configuration
  const { data: config, isLoading, isError, refetch } = useQuery({
    queryKey: ['config', activeFile],
    queryFn: async () => {
      const res = await systemApi.config(activeFile);
      return res.data;
    }
  });

  const updateMutation = useMutation({
    mutationFn: ({ category, key, value }) => systemApi.updateConfig({ category, key, value }, activeFile),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['config'] });
    }
  });

  if (isLoading) return <div className="settings-loading"><RefreshCw className="spin" /> Loading configurations...</div>;
  if (isError) return <div className="settings-error">Failed to load {activeFile}</div>;

  const handleToggleExpand = (section) => {
    setExpandedSections(prev => ({ ...prev, [section]: !prev[section] }));
  };

  const handleValueChange = (category, objKey, val, originalType) => {
    let parsedVal = val;
    if (originalType === 'number') parsedVal = Number(val);
    if (originalType === 'boolean') parsedVal = val === 'true' || val === true;

    updateMutation.mutate({ category, key: objKey, value: parsedVal });
  };

  const renderValueInput = (category, objKey, val) => {
    const type = typeof val;

    if (type === 'boolean') {
      return (
        <label className="settings-toggle">
          <input 
            type="checkbox" 
            checked={val} 
            onChange={(e) => handleValueChange(category, objKey, e.target.checked, 'boolean')} 
            disabled={updateMutation.isPending}
          />
          <span className="slider"></span>
        </label>
      );
    }
    
    if (type === 'number') {
      return (
        <input 
          type="number" 
          defaultValue={val} 
          onBlur={(e) => handleValueChange(category, objKey, e.target.value, 'number')}
          className="settings-input settings-number"
          disabled={updateMutation.isPending}
        />
      );
    }

    if (Array.isArray(val)) {
      return <div className="settings-array">{val.length} items (Edit via text mode coming soon)</div>;
    }

    if (type === 'object' && val !== null) {
      return <div className="settings-nested-hint">Nested Object</div>;
    }

    return (
      <input 
        type="text" 
        defaultValue={val} 
        onBlur={(e) => handleValueChange(category, objKey, e.target.value, 'string')}
        className="settings-input"
        disabled={updateMutation.isPending}
      />
    );
  };

  const renderBlock = (category, sectionData) => {
    if (typeof sectionData !== 'object' || sectionData === null) return null;
    
    return (
      <div className="settings-section" key={category}>
        <div className="settings-section-header" onClick={() => handleToggleExpand(category)}>
          <h3>{category.toUpperCase()}</h3>
          <span className="expand-indicator">{expandedSections[category] ? '▼' : '▶'}</span>
        </div>
        
        {expandedSections[category] && (
          <div className="settings-section-body">
            {Object.entries(sectionData).map(([k, v]) => (
              <div className="settings-row" key={k}>
                <div className="settings-key">{k}</div>
                <div className="settings-val">
                  {renderValueInput(category, k, v)}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="settings-page">
      <div className="settings-header">
        <h1>Configuration Center</h1>
        <p>Manage raw configuration YAML files for the NGFW engine in real-time.</p>
      </div>

      <div className="settings-controls">
        <div className="file-tabs">
          <div 
            className={`file-tab ${activeFile === 'base.yaml' ? 'active' : ''}`}
            onClick={() => setActiveFile('base.yaml')}
          >
            <Server size={18} /> base.yaml
          </div>
          <div 
            className={`file-tab ${activeFile === 'phase2_3.yaml' ? 'active' : ''}`}
            onClick={() => setActiveFile('phase2_3.yaml')}
          >
            <Layers size={18} /> phase2_3.yaml
          </div>
        </div>
        
        <button className="btn-refresh" onClick={() => refetch()}>
          <RefreshCw size={16} /> Refresh
        </button>
      </div>

      <div className="settings-content">
        {config && Object.entries(config).map(([category, data]) => renderBlock(category, data))}
      </div>
      
      {updateMutation.isPending && (
        <div className="saving-overlay">
          <span>Saving & Hot-reloading...</span>
        </div>
      )}
    </div>
  );
}
