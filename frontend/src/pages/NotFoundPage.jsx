import { Link } from 'react-router-dom';

export default function NotFoundPage() {
  return (
    <div className="mx-auto flex min-h-[60vh] max-w-3xl flex-col items-center justify-center gap-6 rounded-3xl border border-white/10 bg-slate-900/95 p-10 text-center shadow-xl shadow-black/20">
      <p className="text-sm uppercase tracking-[.3em] text-purple-300">404</p>
      <h1 className="text-4xl font-semibold text-white">Page not found</h1>
      <p className="max-w-md text-gray-400">The page you are looking for does not exist. Use the navigation bar to return back to the TokenGuardian dashboard.</p>
      <Link to="/" className="rounded-3xl bg-purple-600 px-6 py-3 text-sm font-semibold text-white transition hover:bg-purple-500">
        Return Home
      </Link>
    </div>
  );
}
