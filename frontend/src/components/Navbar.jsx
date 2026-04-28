import { NavLink } from 'react-router-dom'
import { Shield, Home, Radar, Activity, Clock3, Sparkles, Settings2 } from 'lucide-react'

const items = [
  { to: '/', label: 'Dashboard', icon: Home },
  { to: '/analyze', label: 'Analyze', icon: Radar },
  { to: '/threat-map', label: 'Threat Map', icon: Activity },
  { to: '/history', label: 'History', icon: Clock3 },
  { to: '/graph', label: 'Graph', icon: Sparkles },
  { to: '/settings', label: 'Settings', icon: Settings2 },
]

export default function Navbar() {
  return (
    <aside className="fixed left-0 top-0 z-50 h-full w-64 border-r border-white/10 bg-slate-950 px-6 py-8 text-white">
      <div className="mb-10 flex items-center gap-3">
        <div className="flex h-12 w-12 items-center justify-center rounded-3xl bg-purple-600 text-white shadow-xl shadow-purple-500/20">
          <Shield className="h-6 w-6" />
        </div>
        <div>
          <p className="text-lg font-semibold">TokenGuardian</p>
          <p className="text-xs uppercase tracking-[.3em] text-gray-400">Cyber security</p>
        </div>
      </div>

      <nav className="space-y-2">
        {items.map((item) => {
          const Icon = item.icon
          return (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-3xl px-4 py-3 text-sm font-medium transition ${
                  isActive ? 'bg-purple-700 text-white' : 'text-gray-300 hover:bg-white/5 hover:text-white'
                }`
              }
            >
              <Icon className="h-5 w-5" />
              {item.label}
            </NavLink>
          )
        })}
      </nav>
    </aside>
  )
}
