import { Link } from 'react-router-dom';
import { ShieldCheck, Activity, ClipboardList, BarChart3 } from 'lucide-react';

export default function HomePage() {
  return (
    <div className="space-y-8">
      <div className="rounded-3xl border border-white/10 bg-slate-900/95 p-10 shadow-2xl shadow-black/20">
        <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <p className="text-sm uppercase tracking-[.3em] text-purple-300">TokenGuardian</p>
            <h1 className="mt-2 text-4xl font-semibold text-white">Google-native phishing defense for work and hackathons</h1>
            <p className="mt-4 max-w-2xl text-gray-400">
              Analyze URLs, email text, and suspicious messages with a modern security dashboard powered by rule-based scoring and intelligent threat detection.
            </p>
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <Link to="/analyze" className="rounded-2xl bg-purple-600 px-6 py-4 text-center text-sm font-semibold text-white transition hover:bg-purple-500">
              <ShieldCheck className="mx-auto mb-2 h-6 w-6" />
              Start Analysis
            </Link>
            <Link to="/admin" className="rounded-2xl border border-slate-800 bg-slate-800 px-6 py-4 text-center text-sm font-semibold text-white transition hover:border-purple-500">
              <BarChart3 className="mx-auto mb-2 h-6 w-6" />
              Live Admin Stats
            </Link>
          </div>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="rounded-3xl border border-white/10 bg-slate-900/95 p-6">
          <div className="flex items-center gap-3 text-purple-400">
            <Activity className="h-6 w-6" />
            <h2 className="text-lg font-semibold">Real-time Detection</h2>
          </div>
          <p className="mt-3 text-gray-400">Get instant phishing risk scores, attack type analysis, and clear remediation guidance.</p>
        </div>
        <div className="rounded-3xl border border-white/10 bg-slate-900/95 p-6">
          <div className="flex items-center gap-3 text-green-400">
            <ClipboardList className="h-6 w-6" />
            <h2 className="text-lg font-semibold">History & Insights</h2>
          </div>
          <p className="mt-3 text-gray-400">Review recent scans, track trends, and learn why each submission was flagged.</p>
        </div>
        <div className="rounded-3xl border border-white/10 bg-slate-900/95 p-6">
          <div className="flex items-center gap-3 text-yellow-400">
            <ShieldCheck className="h-6 w-6" />
            <h2 className="text-lg font-semibold">Clever Fallback</h2>
          </div>
          <p className="mt-3 text-gray-400">Adaptive scoring enhances detection, while rule-based fallback keeps the demo fully working.</p>
        </div>
      </div>
    </div>
  );
}
