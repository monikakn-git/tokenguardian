import { useState } from 'react'
import ScoreGauge from '../components/ScoreGauge'
import api from '../api'

export default function Analyzer() {
  const [input, setInput] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const submitScan = async (event) => {
    event.preventDefault()
    setLoading(true)
    setError(null)
    try {
      const response = await api.post('/analyze', { content: input })
      setResult(response.data)
    } catch (err) {
      setError('Unable to analyze payload. Please try again.')
      setResult(null)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="grid gap-6 lg:grid-cols-[1.4fr_0.8fr]">
      <section className="rounded-3xl border border-white/10 bg-slate-900/70 p-8 shadow-xl shadow-slate-950/20">
        <div className="flex items-center justify-between gap-4">
          <div>
            <p className="text-sm uppercase tracking-[0.25em] text-gray-400">Analyzer</p>
            <h1 className="mt-2 text-3xl font-semibold text-white">Scan new token payloads</h1>
          </div>
        </div>

        <form onSubmit={submitScan} className="mt-8 space-y-6">
          <div>
            <label className="text-sm font-medium text-gray-300" htmlFor="payload">
              Enter suspicious token or request details
            </label>
            <textarea
              id="payload"
              rows="8"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              className="mt-3 w-full rounded-3xl border border-white/10 bg-slate-950/80 p-4 text-sm text-white outline-none transition focus:border-purple-500 focus:ring-2 focus:ring-purple-500/20"
              placeholder="Paste code, token details, or suspicious input here..."
            />
          </div>

          <button
            type="submit"
            disabled={!input.trim() || loading}
            className="inline-flex items-center justify-center rounded-3xl bg-purple-600 px-6 py-3 text-sm font-semibold text-white transition hover:bg-purple-500 disabled:cursor-not-allowed disabled:bg-purple-500/50"
          >
            {loading ? 'Scanning…' : 'Run analysis'}
          </button>
        </form>

        {error && <p className="mt-6 text-sm text-rose-300">{error}</p>}

        {result && (
          <div className="mt-8 rounded-3xl border border-white/10 bg-slate-950/80 p-6">
            <p className="text-sm uppercase tracking-[0.3em] text-gray-400">Result</p>
            <p className="mt-4 text-xl font-semibold text-white">{result.verdict || 'Unknown verdict'}</p>
            <div className="mt-5 grid gap-4 sm:grid-cols-2">
              <div className="rounded-3xl bg-slate-900/80 p-4 text-sm text-gray-300">
                <p className="font-medium text-white">Threat score</p>
                <p className="mt-2 text-3xl font-semibold text-white">{result.score ?? '—'}%</p>
                <p className="mt-2">Risk level: {result.risk_level || 'unknown'}</p>
              </div>
              <div className="rounded-3xl bg-slate-900/80 p-4 text-sm text-gray-300">
                <p className="font-medium text-white">Recommendations</p>
                <ul className="mt-2 list-disc space-y-2 pl-5">
                  {(result.recommendations || []).map((item, index) => (
                    <li key={index}>{item}</li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        )}
      </section>

      <aside className="space-y-6 rounded-3xl border border-white/10 bg-slate-900/70 p-8 shadow-xl shadow-slate-950/20">
        <ScoreGauge score={result?.score ?? 65} trend={result?.risk_level?.toLowerCase() || 'moderate'} detail={result?.verdict || 'Awaiting scan results'} />
        <div className="rounded-3xl bg-slate-950/80 p-6 text-sm leading-6 text-gray-300">
          <p className="font-semibold text-white">How it works</p>
          <p className="mt-3">The analyzer applies token heuristics, metadata checks, and AI-powered classification to score suspicious payloads and prioritize alerts.</p>
        </div>
      </aside>
    </div>
  )
}
