import React, { useEffect, useState } from 'react';
import { LogOut, AlertTriangle, ShieldAlert, KeyRound, RadioReceiver, CheckCircle } from 'lucide-react';

const API_BASE = 'http://127.0.0.1:8001/api';

const Dashboard = ({ setToken, token }) => {
  const [user, setUser] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [error, setError] = useState(null);
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [resetMsg, setResetMsg] = useState('');

  const fetchProfile = async () => {
    try {
      const res = await fetch(`${API_BASE}/tokens/me`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.status === 403 || res.status === 401) {
        handleLogout();
        return;
      }
      const data = await res.json();
      if (res.ok) setUser(data);
    } catch (err) {
      console.error(err);
    }
  };

  const fetchAlerts = async () => {
    try {
      const res = await fetch(`${API_BASE}/tokens/alerts`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setAlerts(data);
      }
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchProfile();
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 5000); // Poll for alerts
    return () => clearInterval(interval);
  }, []);

  const handleLogout = () => {
    localStorage.removeItem('token');
    setToken(null);
  };

  const simulateAttack = async () => {
    try {
      // Send request with fake Moscow IP to trigger the anomaly engine
      const res = await fetch(`${API_BASE}/tokens/me`, {
        headers: { 
          'Authorization': `Bearer ${token}`,
          'X-Forwarded-For': '185.20.12.5', // Moscow IP
          'User-Agent': 'Mozilla/5.0 (Hacker-Bot)'
        }
      });
      
      if (res.status === 403) {
        setError("Token Guardian intercepted the attack and revoked your token!");
        fetchAlerts();
        // Delay logout so user can read the message
        setTimeout(handleLogout, 4000);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const resetPassword = async (e) => {
    e.preventDefault();
    setResetMsg('');
    try {
      const res = await fetch(`${API_BASE}/auth/reset-password`, {
        method: 'POST',
        headers: { 
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ old_password: oldPassword, new_password: newPassword })
      });
      const data = await res.json();
      if (res.ok) {
        setResetMsg("Password reset! All old tokens instantly revoked.");
        setOldPassword('');
        setNewPassword('');
      } else {
        setResetMsg(`Error: ${data.detail}`);
      }
    } catch (err) {
      console.error(err);
    }
  };

  if (!user) return <div className="app-container"><p>Loading profile...</p></div>;

  return (
    <div className="dashboard-container">
      <div className="dashboard-header">
        <div>
          <h2>Welcome, {user.username}</h2>
          <p>Security Dashboard</p>
        </div>
        <button className="btn btn-outline" onClick={handleLogout}>
          <LogOut size={18} /> Logout
        </button>
      </div>

      {error && (
        <div className="glass-panel" style={{ background: 'rgba(239, 68, 68, 0.2)', borderColor: '#ef4444', marginBottom: '2rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', color: '#fca5a5' }}>
            <AlertTriangle size={32} />
            <div>
              <h3>Security Breach Detected!</h3>
              <p>{error}</p>
            </div>
          </div>
        </div>
      )}

      <div className="grid-2">
        {/* Left Column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
          
          {/* Attack Simulator */}
          <div className="glass-panel">
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
              <RadioReceiver size={24} color="var(--primary-color)" />
              <h3>Simulate Attack</h3>
            </div>
            <p style={{ marginBottom: '1.5rem', fontSize: '0.9rem' }}>
              Clicking this button will send an API request using your current active token, but spoofing the IP address to originate from Moscow (185.20.12.5). 
              The backend Anomaly Engine will detect the impossible travel and instantly revoke the token.
            </p>
            <button className="btn btn-danger" onClick={simulateAttack} style={{ width: '100%' }}>
              <ShieldAlert size={18} /> Execute Simulated Attack
            </button>
          </div>

          {/* Password Reset */}
          <div className="glass-panel">
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
              <KeyRound size={24} color="var(--primary-color)" />
              <h3>Password & Revocation</h3>
            </div>
            <p style={{ marginBottom: '1rem', fontSize: '0.9rem' }}>
              Changing your password will also iterate through all active tokens in the database and explicitly mark them as revoked.
            </p>
            <form onSubmit={resetPassword}>
              <div className="form-group">
                <input 
                  type="password" 
                  placeholder="Current Password" 
                  value={oldPassword}
                  onChange={(e) => setOldPassword(e.target.value)}
                  required 
                />
              </div>
              <div className="form-group">
                <input 
                  type="password" 
                  placeholder="New Password" 
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  required 
                />
              </div>
              {resetMsg && <p style={{ color: resetMsg.includes('Error') ? 'var(--danger-color)' : '#22c55e', marginBottom: '1rem', fontSize: '0.85rem' }}>{resetMsg}</p>}
              <button className="btn btn-outline" style={{ width: '100%' }} type="submit">
                Reset Password
              </button>
            </form>
          </div>

        </div>

        {/* Right Column (Alerts) */}
        <div className="glass-panel">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.5rem' }}>
            <AlertTriangle size={24} color="var(--danger-color)" />
            <h3>Security Alerts History</h3>
          </div>
          
          <div className="alert-list">
            {alerts.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-secondary)' }}>
                <CheckCircle size={48} style={{ opacity: 0.5, margin: '0 auto 1rem' }} />
                <p>No security alerts found.</p>
                <p style={{ fontSize: '0.8rem' }}>Your account is secure.</p>
              </div>
            ) : (
              alerts.map((alert) => (
                <div key={alert.id} className="alert-item">
                  <div style={{ fontWeight: 600, marginBottom: '0.25rem' }}>{alert.alert_type}</div>
                  <div style={{ fontSize: '0.875rem', opacity: 0.9 }}>{alert.description}</div>
                  <div style={{ fontSize: '0.75rem', opacity: 0.6, marginTop: '0.5rem' }}>
                    Risk Score: {alert.risk_score} | {new Date(alert.created_at).toLocaleString()}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

      </div>
    </div>
  );
};

export default Dashboard;
