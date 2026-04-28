import { useEffect, useState } from 'react'
import api from '../api'

export default function History() {
  const [history, setHistory] = useState([])

  useEffect(() => {
    api.get('/history').then((res) => setHistory(res.data)).catch(() => setHistory([]))
  }, [])

  return (
    <section className="space-y-6 rounded-3xl border border-white/10 bg-slate-900/70 p-8 shadow-xl shadow-slate-950/20">
      <div>
        <p className="text-sm uppercase tracking-[0.25em] text-gray-400">History</p>
        <h1 className="mt-2 text-3xl font-semibold text-white">Recent token scans</h1>
      </div>

      <div className="grid gap-4">
        {history.length > 0 ? (
          history.map((entry) => (
            <div key={entry.id} className="rounded-3xl border border-white/10 bg-slate-950/80 p-6">
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div>
                  <p className="text-sm text-gray-400">{entry.timestamp}</p>
                  <p className="mt-2 text-lg font-semibold text-white">{entry.source || 'Token scan'}</p>
                </div>
                <span className="rounded-full bg-purple-600/15 px-3 py-1 text-xs uppercase tracking-[0.2em] text-purple-200">
                  {entry.verdict || 'unknown'}
                </span>
              </div>
              <p className="mt-4 text-sm leading-6 text-gray-300">{entry.summary || 'No details available.'}</p>
            </div>
          ))
        ) : (
          <div className="rounded-3xl border border-white/10 bg-slate-950/80 p-6 text-sm text-gray-400">No scan history available yet.</div>
        )}
      </div>
    </section>
  )
}
