export default function Settings() {
  return (
    <section className="space-y-6 rounded-3xl border border-white/10 bg-slate-900/70 p-8 shadow-xl shadow-slate-950/20">
      <div>
        <p className="text-sm uppercase tracking-[0.25em] text-gray-400">Settings</p>
        <h1 className="mt-2 text-3xl font-semibold text-white">Platform controls</h1>
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <div className="rounded-3xl bg-slate-950/80 p-6 text-sm text-gray-300">
          <p className="font-semibold text-white">Deployment</p>
          <p className="mt-3">Configure API endpoints, environment secrets, and deployment options from the backend service.</p>
        </div>
        <div className="rounded-3xl bg-slate-950/80 p-6 text-sm text-gray-300">
          <p className="font-semibold text-white">User access</p>
          <p className="mt-3">Manage secure access, alerts, and notification settings for the security operations team.</p>
        </div>
      </div>

      <div className="rounded-3xl bg-slate-950/80 p-6 text-sm text-gray-300">
        <p className="font-semibold text-white">Next steps</p>
        <ul className="mt-3 list-disc space-y-2 pl-5 text-gray-300">
          <li>Enable authentication and permissions.</li>
          <li>Integrate alert routing and reporting.</li>
          <li>Sync threat intelligence feeds for live updates.</li>
        </ul>
      </div>
    </section>
  )
}
