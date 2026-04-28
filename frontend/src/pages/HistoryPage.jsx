import { useEffect, useState } from 'react';
import { Clock3 } from 'lucide-react';
import { api } from '../api';

export default function HistoryPage() {
  const [history, setHistory] = useState([]);

  useEffect(() => {
    api.get('/history?limit=20').then((response) => setHistory(response.data)).catch(() => setHistory([]));
  }, []);

  return (
    <div className="space-y-8">
      <div className="rounded-3xl border border-white/10 bg-slate-900/95 p-8 shadow-xl shadow-black/20">
        <p className="text-sm uppercase tracking-[.3em] text-purple-300">History</p>
        <h1 className="mt-2 text-3xl font-semibold text-white">Recent scans and signal timelines</h1>
        <p className="mt-3 text-gray-400">Review your last content submissions and the analysis outputs.</p>
      </div>

      <div className="grid gap-4">
        {history.length === 0 ? (
          <div className="rounded-3xl border border-white/10 bg-slate-900/95 p-8 text-center text-gray-400">No analysis history available.</div>
        ) : (
          history.map((item) => (
            <div key={item.id} className="rounded-3xl border border-white/10 bg-slate-900/95 p-6 shadow-xl shadow-black/10">
              <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
                <div>
                  <p className="text-sm uppercase tracking-[.3em] text-gray-400">{item.attack_type || 'Unknown'}</p>
                  <h2 className="mt-2 text-xl font-semibold text-white">{item.content_preview}</h2>
                </div>
                <div className="rounded-3xl bg-slate-800 px-4 py-3 text-center">
                  <p className="text-xs uppercase tracking-[.3em] text-gray-400">Score</p>
                  <p className="mt-2 text-2xl font-semibold text-white">{item.score}</p>
                </div>
              </div>
              <div className="mt-4 flex flex-wrap gap-2 text-sm text-gray-300">
                <span className="rounded-full bg-slate-950/80 px-3 py-1">{item.risk_level}</span>
                <span className="rounded-full bg-slate-950/80 px-3 py-1">{new Date(item.timestamp).toLocaleString()}</span>
                <span className="rounded-full bg-slate-950/80 px-3 py-1">URLs: {item.url_count}</span>
              </div>
              <div className="mt-4 rounded-3xl bg-slate-950/70 p-4 text-sm text-gray-300">
                <p className="font-semibold text-white">Signals</p>
                <ul className="mt-2 list-disc space-y-1 pl-5">
                  {item.signals.map((signal, idx) => (
                    <li key={idx}>{signal}</li>
                  ))}
                </ul>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
