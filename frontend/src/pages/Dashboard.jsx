import { useEffect, useState } from 'react'
import { ShieldCheck } from 'lucide-react'
import ScoreGauge from '../components/ScoreGauge'
import api from '../api'

export default function Dashboard() {
  const [stats, setStats] = useState({ total: 0, alerts: 0, threat_score: 0 })
  const [history, setHistory] = useState([])
  const [offline, setOffline] = useState(false)

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [statsRes, historyRes] = await Promise.all([
          api.get('/stats'),
          api.get('/history'),
        ])
        setStats(statsRes.data)
        setHistory(historyRes.data.slice(0, 3))
      } catch (error) {
        setOffline(true)
        setStats({ total: 0, alerts: 0, threat_score: 0 })
        setHistory([])
      }
    }

    fetchData()
  }, [])

  return (
    <div className="grid gap-6 lg:grid-cols-[1.5fr_1fr]">
      <section className="space-y-6 rounded-3xl border border-white/10 bg-slate-900/70 p-8 shadow-xl shadow-slate-950/20">
        {offline && (
          <div className="rounded-3xl border border-slate-700 bg-slate-950/80 p-4 text-sm text-slate-300">
            Running in offline mode — live data is not available right now.
          </div>
        )}
        <div className="flex items-center justify-between gap-4">
          <div>
            <p className="text-sm uppercase tracking-[0.25em] text-gray-400">Overview</p>
            <h1 className="mt-2 text-3xl font-semibold text-white">Security command center</h1>
          </div>
          <span className="rounded-full bg-purple-600/20 px-4 py-2 text-xs uppercase tracking-wide text-purple-200">Live</span>
        </div>

        <div className="grid gap-4 sm:grid-cols-3">
          <article className="rounded-3xl bg-slate-950/70 p-5">
            <p className="text-sm text-gray-400">Analyses</p>
            <p className="mt-3 text-3xl font-semibold text-white">{stats?.total ?? 0}</p>
          </article>
          <article className="rounded-3xl bg-slate-950/70 p-5">
            <p className="text-sm text-gray-400">Alerts</p>
            <p className="mt-3 text-3xl font-semibold text-white">{stats?.alerts ?? 0}</p>
          </article>
          <article className="rounded-3xl bg-slate-950/70 p-5">
            <p className="text-sm text-gray-400">Risk</p>
            <p className="mt-3 text-3xl font-semibold text-white">{stats?.threat_score ?? 0}%</p>
          </article>
        </div>

        <div className="grid gap-4 lg:grid-cols-2">
          <ScoreGauge score={stats?.threat_score ?? 72} trend={stats?.threat_score >= 70 ? 'high' : stats?.threat_score >= 40 ? 'moderate' : 'low'} detail={stats?.total ? 'Live token risk score' : 'token exposure detected'} />
          <div className="rounded-3xl bg-slate-950/70 p-6">
            <p className="text-sm uppercase tracking-[0.25em] text-gray-400">Recent scans</p>
            <div className="mt-4 space-y-4">
              {history.length > 0 ? (
                history.map((item) => (
                  <div key={item.id} className="rounded-3xl border border-white/10 bg-slate-900/90 p-4">
                    <p className="text-sm text-gray-300">{item.source || 'Token'} — {item.timestamp}</p>
                    <p className="mt-2 text-white">{item.summary || item.verdict || 'No summary available'}</p>
                  </div>
                ))
              ) : (
                <div className="rounded-3xl border border-white/10 bg-slate-900/90 p-6 text-center text-sm text-slate-400">
                  <div className="mx-auto mb-3 inline-flex h-10 w-10 items-center justify-center rounded-full bg-slate-800 text-slate-300">
                    <ShieldCheck className="h-5 w-5" />
                  </div>
                  No scans yet
                </div>
              )}
            </div>
          </div>
        </div>
      </section>

      <section className="space-y-6 rounded-3xl border border-white/10 bg-slate-900/70 p-8 shadow-xl shadow-slate-950/20">
        <div>
          <p className="text-sm uppercase tracking-[0.25em] text-gray-400">Briefing</p>
          <h2 className="mt-2 text-2xl font-semibold text-white">Threat posture snapshot</h2>
        </div>
        <div className="space-y-4 text-sm leading-6 text-gray-300">
          <p>The dashboard aggregates token scans, alert counts, and dynamic risk scoring so your security team can act quickly.</p>
          <p>Use the Analyze page to scan new payloads and the Threat Map page to see suspicious networks and token flow.</p>
        </div>
      </section>
    </div>
  )
}
