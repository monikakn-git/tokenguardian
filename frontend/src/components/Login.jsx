import React, { useState } from 'react';
import { ShieldCheck, User, Lock, Loader2 } from 'lucide-react';

const API_BASE = '/api/auth';

const Login = ({ setToken }) => {
  const [isLogin, setIsLogin] = useState(true);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      if (isLogin) {
        const formData = new URLSearchParams();
        formData.append('username', username);
        formData.append('password', password);

        const res = await fetch(`${API_BASE}/login`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: formData,
        });

        const data = await res.json();
        
        if (!res.ok) throw new Error(data.detail || 'Login failed');

        localStorage.setItem('token', data.access_token);
        setToken(data.access_token);
      } else {
        const res = await fetch(`${API_BASE}/register`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ username, password }),
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Registration failed');

        // Auto login after register
        setIsLogin(true);
        setError('Registration successful! Please login.');
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app-container">
      <div className="glass-panel" style={{ width: '100%', maxWidth: '400px' }}>
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <ShieldCheck size={48} color="var(--primary-color)" style={{ marginBottom: '1rem' }} />
          <h2>TokenGuardian</h2>
          <p>{isLogin ? 'Sign in to access your dashboard' : 'Create a secure account'}</p>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Username</label>
            <div style={{ position: 'relative' }}>
              <User size={18} style={{ position: 'absolute', top: '12px', left: '12px', color: 'var(--text-secondary)' }} />
              <input 
                type="text" 
                placeholder="Enter username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                style={{ paddingLeft: '2.5rem' }}
                required 
              />
            </div>
          </div>

          <div className="form-group">
            <label>Password</label>
            <div style={{ position: 'relative' }}>
              <Lock size={18} style={{ position: 'absolute', top: '12px', left: '12px', color: 'var(--text-secondary)' }} />
              <input 
                type="password" 
                placeholder="Enter password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                style={{ paddingLeft: '2.5rem' }}
                required 
              />
            </div>
          </div>

          {error && <div className={`error-text ${error.includes('successful') ? '' : 'text-danger'}`} style={{color: error.includes('successful') ? '#22c55e' : 'var(--danger-color)', marginBottom: '1rem'}}>{error}</div>}

          <button type="submit" className="btn btn-primary" style={{ width: '100%' }} disabled={loading}>
            {loading ? <Loader2 size={18} className="spinner" /> : (isLogin ? 'Sign In' : 'Register')}
          </button>
        </form>

        <div style={{ textAlign: 'center', marginTop: '1.5rem' }}>
          <p style={{ fontSize: '0.875rem' }}>
            {isLogin ? "Don't have an account? " : "Already have an account? "}
            <span 
              style={{ color: 'var(--primary-color)', cursor: 'pointer', fontWeight: 500 }}
              onClick={() => { setIsLogin(!isLogin); setError(null); }}
            >
              {isLogin ? 'Register now' : 'Sign in'}
            </span>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Login;
