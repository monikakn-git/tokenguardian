import { useEffect, useState } from 'react'
import api from '../api'

export default function GraphView() {
  const [graphData, setGraphData] = useState(null)

  useEffect(() => {
    api.get('/graph').then((res) => setGraphData(res.data)).catch(() => setGraphData(null))
  }, [])

  return (
    <section className="space-y-6 rounded-3xl border border-white/10 bg-slate-900/70 p-8 shadow-xl shadow-slate-950/20">
      <div>
        <p className="text-sm uppercase tracking-[0.25em] text-gray-400">Graph view</p>
        <h1 className="mt-2 text-3xl font-semibold text-white">Token relationships</h1>
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <div className="rounded-3xl bg-slate-950/80 p-6">
          <p className="text-sm text-gray-400">Nodes</p>
          <p className="mt-3 text-3xl font-semibold text-white">{graphData?.nodes?.length ?? '—'}</p>
          <p className="mt-2 text-sm text-gray-300">Connected entities in the threat map.</p>
        </div>
        <div className="rounded-3xl bg-slate-950/80 p-6">
          <p className="text-sm text-gray-400">Links</p>
          <p className="mt-3 text-3xl font-semibold text-white">{graphData?.links?.length ?? '—'}</p>
          <p className="mt-2 text-sm text-gray-300">Token flow relationships detected by the backend.</p>
        </div>
      </div>

      <div className="grid gap-4 rounded-3xl bg-slate-950/80 p-6 text-sm text-gray-300">
        <p className="font-semibold text-white">Graph summary</p>
        <p>{graphData ? 'This view highlights token relationships and helps teams prioritize suspicious clusters.' : 'Loading graph metadata...'}</p>
      </div>
    </section>
  )
}
