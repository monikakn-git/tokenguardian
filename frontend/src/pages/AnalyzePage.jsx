import { useState } from 'react';
import { Shield, AlertTriangle, CheckCircle } from 'lucide-react';
import { api } from '../api';

const scoreColor = (score) => {
  if (score >= 70) return 'text-red-400';
  if (score >= 40) return 'text-yellow-400';
  return 'text-green-400';
};

const scoreBg = (score) => {
  if (score >= 70) return 'bg-red-500';
  if (score >= 40) return 'bg-yellow-500';
  return 'bg-green-500';
};

const riskIcon = (level) => {
  if (level === 'HIGH') return <AlertTriangle className="h-6 w-6 text-red-400" />;
  if (level === 'MEDIUM') return <AlertTriangle className="h-6 w-6 text-yellow-400" />;
  return <CheckCircle className="h-6 w-6 text-green-400" />;
};

export default function AnalyzePage() {
  const [content, setContent] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const submit = async () => {
    if (!content.trim()) return;
    setLoading(true);
    try {
      const response = await api.post('/analyze', { content });
      setResult(response.data);
    } catch (error) {
      setResult({
        score: 0,
        risk_level: 'LOW',
        verdict: 'Analysis failed. Please try again.',
        signals: ['Unable to connect to backend.'],
        recommendations: ['Retry later', 'Check backend status'],
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-8">
      <div className="rounded-3xl border border-white/10 bg-slate-900/95 p-8 shadow-xl shadow-black/20">
        <div className="mb-6 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <p className="text-sm uppercase tracking-[.3em] text-purple-300">Analyze</p>
            <h1 className="mt-2 text-3xl font-semibold text-white">Paste suspicious content and get a threat score</h1>
            <p className="mt-3 text-gray-400">TokenGuardian combines precise rule-based scoring with secure threat detection for every input.</p>
          </div>
          <div className="rounded-2xl bg-slate-800 px-6 py-4 text-white/80">
            <p className="text-sm uppercase tracking-[.3em] text-gray-300">Scoring</p>
            <p className="mt-2 text-3xl font-semibold text-white">0-100</p>
            <p className="mt-1 text-sm text-gray-400">Low / Medium / High risk levels</p>
          </div>
        </div>

        <textarea
          value={content}
          onChange={(e) => setContent(e.target.value)}
          rows={8}
          className="w-full rounded-3xl border border-slate-700 bg-slate-950/70 p-5 text-white placeholder:text-slate-500 focus:border-purple-500 focus:outline-none focus:ring-2 focus:ring-purple-500"
          placeholder="Paste a full email, suspicious URL, or message here..."
        />
        <button
          onClick={submit}
          disabled={loading || !content.trim()}
          className="mt-5 inline-flex items-center justify-center gap-2 rounded-3xl bg-purple-600 px-6 py-3 text-sm font-semibold text-white transition hover:bg-purple-500 disabled:cursor-not-allowed disabled:bg-slate-700"
        >
          {loading ? 'Analyzing...' : 'Run Analysis'}
          <Shield className="h-5 w-5" />
        </button>
      </div>

      {result && (
        <div className="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
          <div className="rounded-3xl border border-white/10 bg-slate-900/95 p-8 shadow-xl shadow-black/20">
            <div className="mb-6 flex items-center justify-between gap-4">
              <div>
                <p className="text-sm uppercase tracking-[.3em] text-gray-400">Verdict</p>
                <h2 className="mt-2 text-3xl font-semibold text-white">{result.verdict}</h2>
              </div>
              <div className="rounded-3xl bg-slate-800 px-5 py-4 text-center">
                <p className="text-sm uppercase tracking-[.25em] text-gray-400">Score</p>
                <p className={`mt-2 text-5xl font-semibold ${scoreColor(result.score)}`}>{result.score}</p>
              </div>
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="rounded-3xl bg-slate-800 p-5">
                <p className="text-xs uppercase tracking-[.3em] text-gray-400">Risk Level</p>
                <p className="mt-2 text-lg font-semibold text-white">{result.risk_level}</p>
              </div>
              <div className="rounded-3xl bg-slate-800 p-5">
                <p className="text-xs uppercase tracking-[.3em] text-gray-400">Attack Type</p>
                <p className="mt-2 text-lg font-semibold text-white">{result.attack_type || 'Unknown'}</p>
              </div>
            </div>

            <div className="mt-6 rounded-3xl bg-slate-800 p-6">
              <p className="text-sm uppercase tracking-[.3em] text-gray-400">Key Signals</p>
              <ul className="mt-4 space-y-3 text-gray-300">
                {result.signals.map((signal, index) => (
                  <li key={index} className="rounded-2xl bg-slate-950/50 px-4 py-3">{signal}</li>
                ))}
              </ul>
            </div>
          </div>

          <div className="space-y-6 rounded-3xl border border-white/10 bg-slate-900/95 p-8 shadow-xl shadow-black/20">
            <div className="rounded-3xl bg-slate-950/70 p-6">
              <p className="text-sm uppercase tracking-[.3em] text-gray-400">Confidence</p>
              <p className="mt-3 text-lg font-semibold text-white">{result.confidence || 'medium'}</p>
            </div>
            <div className="rounded-3xl bg-slate-950/70 p-6">
              <p className="text-sm uppercase tracking-[.3em] text-gray-400">Recommendations</p>
              <ul className="mt-3 space-y-2 text-gray-300">
                {(result.recommendations || []).map((rec, idx) => (
                  <li key={idx} className="rounded-2xl bg-slate-900/80 px-4 py-3">{rec}</li>
                ))}
              </ul>
            </div>
            <div className="rounded-3xl bg-slate-950/70 p-6">
              <p className="text-sm uppercase tracking-[.3em] text-gray-400">Indicators</p>
              <ul className="mt-3 space-y-2 text-gray-300">
                {(result.indicators || []).map((indicator, idx) => (
                  <li key={idx} className="rounded-2xl bg-slate-900/80 px-4 py-3">{indicator}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
