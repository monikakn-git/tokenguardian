export default function ScoreGauge({ score = 82, trend = 'moderate', detail = 'suspicious' }) {
  const fill = Math.min(100, Math.max(0, score))
  const strokeDash = `${fill}, 100`
  const color = fill > 75 ? 'text-emerald-400' : fill > 50 ? 'text-amber-400' : 'text-rose-400'

  return (
    <div className="rounded-3xl border border-white/10 bg-slate-900/70 p-6 shadow-xl shadow-slate-950/30">
      <div className="flex items-center justify-between gap-4">
        <div>
          <p className="text-sm uppercase text-gray-400">Threat score</p>
          <h2 className="mt-2 text-3xl font-semibold text-white">{fill}%</h2>
          <p className="mt-1 text-sm text-gray-400">Real-time risk gauge for scanned tokens</p>
        </div>
        <div className="flex h-24 w-24 items-center justify-center rounded-full bg-slate-950 p-2">
          <svg viewBox="0 0 36 36" className="h-full w-full overflow-visible">
            <defs>
              <linearGradient id="scoreGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="#a855f7" />
                <stop offset="100%" stopColor="#22c55e" />
              </linearGradient>
            </defs>
            <circle
              cx="18"
              cy="18"
              r="15"
              stroke="rgba(255,255,255,0.1)"
              strokeWidth="4"
              fill="none"
            />
            <circle
              cx="18"
              cy="18"
              r="15"
              stroke="url(#scoreGradient)"
              strokeWidth="4"
              strokeDasharray={strokeDash}
              strokeDashoffset="25"
              strokeLinecap="round"
              fill="none"
              transform="rotate(-90 18 18)"
            />
          </svg>
        </div>
      </div>
      <div className="mt-4 rounded-3xl bg-slate-950/80 p-4 text-sm text-gray-300">
        <p>
          Threat level is <span className={`font-semibold ${color}`}>{trend}</span> based on token patterns and recent behavior.
        </p>
        <p className="mt-1 text-xs text-gray-500">Current verdict: {detail}</p>
      </div>
    </div>
  )
}
