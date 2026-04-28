import { useEffect, useState, useMemo } from 'react';
import { api } from '../api';
import { BarChart3, AlertTriangle, ShieldCheck, Wifi } from 'lucide-react';

export default function AdminPage() {
  const [stats, setStats] = useState(null);
  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    api.get('/stats').then((response) => setStats(response.data)).catch(() => setStats(null));
  }, []);

  useEffect(() => {
    const ws = new WebSocket((import.meta.env.VITE_API_URL || 'http://localhost:8000/api').replace('http', 'ws').replace('/api', '') + '/alerts/ws');
    ws.addEventListener('message', (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.type === 'alert') {
          setAlerts((prev) => [payload.data, ...prev].slice(0, 5));
        }
      } catch (error) {
        console.error(error);
      }
    });

    return () => ws.close();
  }, []);

  const riskSummary = useMemo(() => {
    if (!stats) return null;
    return [
      { label: 'Total scans', value: stats.total || 0, icon: BarChart3 },
      { label: 'Phishing', value: stats.phishing || 0, icon: AlertTriangle },
      { label: 'Suspicious', value: stats.suspicious || 0, icon: ShieldCheck },
      { label: 'Safe', value: stats.safe || 0, icon: Wifi },
    ];
  }, [stats]);

  return (
    <div className="space-y-8">
      <div className="rounded-3xl border border-white/10 bg-slate-900/95 p-8 shadow-xl shadow-black/20">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <p className="text-sm uppercase tracking-[.3em] text-purple-300">Admin Dashboard</p>
            <h1 className="mt-2 text-3xl font-semibold text-white">Live platform health and alert monitoring</h1>
            <p className="mt-3 text-gray-400">Track platform usage, detect live phishing incidents, and see how TokenGuardian scores content.</p>
          </div>
        </div>
      </div>

      <div className="grid gap-6 xl:grid-cols-4">
        {riskSummary?.map((item) => {
          const Icon = item.icon;
          return (
            <div key={item.label} className="rounded-3xl border border-white/10 bg-slate-900/95 p-6 text-center shadow-xl shadow-black/10">
              <Icon className="mx-auto mb-4 h-8 w-8 text-purple-400" />
              <p className="text-3xl font-semibold text-white">{item.value}</p>
              <p className="mt-2 text-sm uppercase tracking-[.3em] text-gray-400">{item.label}</p>
            </div>
          );
        })}
      </div>

      <div className="rounded-3xl border border-white/10 bg-slate-900/95 p-8 shadow-xl shadow-black/20">
        <h2 className="text-xl font-semibold text-white">Live alerts</h2>
        <p className="mt-2 text-gray-400">High-risk scans immediately notify the dashboard using WebSockets.</p>
        <div className="mt-6 space-y-4">
          {alerts.length === 0 ? (
            <p className="text-gray-400">No live alerts yet. Trigger a high-risk scan to see alerts appear here.</p>
          ) : (
            alerts.map((alert) => (
              <div key={alert.id} className="rounded-3xl bg-slate-950/80 p-4 text-gray-200">
                <div className="flex items-center justify-between gap-4">
                  <div>
                    <p className="font-semibold text-white">{alert.attack_type || 'Phishing Alert'}</p>
                    <p className="text-sm text-gray-400">{new Date(alert.timestamp).toLocaleString()}</p>
                  </div>
                  <span className="rounded-full bg-red-500/20 px-3 py-1 text-sm text-red-300">{alert.risk_level}</span>
                </div>
                <p className="mt-3 text-sm text-gray-300">{alert.verdict}</p>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
