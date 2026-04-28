import React, { useState } from 'react';
import { Search, ShieldCheck, ShieldAlert, ShieldQuestion, Loader2 } from 'lucide-react';

const API_BASE = 'http://127.0.0.1:8001/api';

const LinkScanner = ({ token }) => {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleScan = async (e) => {
    e.preventDefault();
    if (!url) return;

    setLoading(true);
    setResult(null);
    setError(null);

    try {
      const res = await fetch(`${API_BASE}/scanner/scan`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url })
      });

      if (!res.ok) {
        throw new Error('Failed to scan URL');
      }

      const data = await res.json();
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const getStatusIcon = () => {
    if (result.status === 'safe') return <ShieldCheck size={48} color="#22c55e" />;
    if (result.status === 'malicious') return <ShieldAlert size={48} color="#ef4444" />;
    return <ShieldQuestion size={48} color="#f59e0b" />;
  };

  const getStatusColor = () => {
    if (result.status === 'safe') return '#22c55e';
    if (result.status === 'malicious') return '#ef4444';
    return '#f59e0b';
  };

  return (
    <div className="glass-panel">
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
        <Search size={24} color="var(--primary-color)" />
        <h3>Suspicious Link Scanner</h3>
      </div>
      <p style={{ marginBottom: '1.5rem', fontSize: '0.9rem' }}>
        Paste any link below to check for malicious redirects, phishing attempts, or suspicious domains.
      </p>
      
      <form onSubmit={handleScan} style={{ marginBottom: '1.5rem' }}>
        <div className="form-group" style={{ display: 'flex', gap: '0.5rem' }}>
          <input 
            type="text" 
            placeholder="https://example.com/login" 
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            style={{ flex: 1, marginBottom: 0 }}
          />
          <button 
            className="btn btn-primary" 
            type="submit" 
            disabled={loading || !url}
            style={{ minWidth: '100px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}
          >
            {loading ? <Loader2 className="spin" size={18} /> : 'Scan'}
          </button>
        </div>
      </form>

      {error && (
        <div style={{ color: 'var(--danger-color)', fontSize: '0.85rem', marginTop: '1rem' }}>
          Error: {error}
        </div>
      )}

      {result && (
        <div className="result-container" style={{ 
          marginTop: '1.5rem', 
          padding: '1.5rem', 
          borderRadius: '12px', 
          background: 'rgba(255, 255, 255, 0.05)',
          border: `1px solid ${getStatusColor()}44`,
          textAlign: 'center'
        }}>
          <div style={{ marginBottom: '1rem', display: 'flex', justifyContent: 'center' }}>
            {getStatusIcon()}
          </div>
          <h4 style={{ color: getStatusColor(), textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '0.5rem' }}>
            {result.status}
          </h4>
          <p style={{ fontSize: '0.9rem', opacity: 0.9 }}>{result.reason}</p>
          <div style={{ marginTop: '1rem', fontSize: '0.75rem', opacity: 0.6 }}>
            Risk Score: {result.risk_score}/100
          </div>
        </div>
      )}
    </div>
  );
};

export default LinkScanner;
