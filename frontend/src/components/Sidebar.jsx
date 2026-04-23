import { NavLink } from 'react-router-dom'
import { LayoutDashboard, ShieldOff, Settings, Shield } from 'lucide-react'

const NAV_LINKS = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/blacklist',  icon: ShieldOff,       label: 'IP Blacklist' },
  { to: '/admin',      icon: Settings,         label: 'Admin' },
]

export default function Sidebar() {
  return (
    <aside className="w-60 bg-slate-800 border-r border-slate-700 flex flex-col shrink-0">
      {/* Logo */}
      <div className="px-5 py-4 border-b border-slate-700 flex items-center gap-3">
        <div className="w-9 h-9 bg-cyan-500/15 border border-cyan-500/30 rounded-lg flex items-center justify-center">
          <Shield className="w-5 h-5 text-cyan-400" />
        </div>
        <div>
          <p className="font-bold text-white text-sm leading-tight">XDP Firewall</p>
          <p className="text-slate-400 text-xs">CN322 Security</p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-3 space-y-0.5">
        {NAV_LINKS.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                isActive
                  ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/25'
                  : 'text-slate-400 hover:text-white hover:bg-slate-700/60 border border-transparent'
              }`
            }
          >
            <Icon className="w-4 h-4 shrink-0" />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* Status footer */}
      <div className="p-3 border-t border-slate-700">
        <div className="bg-green-500/10 border border-green-500/20 rounded-lg px-3 py-2.5 flex items-center gap-2.5">
          <span className="w-2 h-2 bg-green-400 rounded-full animate-pulse shrink-0" />
          <div>
            <p className="text-green-400 text-xs font-semibold tracking-wide">FIREWALL ACTIVE</p>
            <p className="text-slate-400 text-xs mt-0.5">XDP kernel hook running</p>
          </div>
        </div>
      </div>
    </aside>
  )
}
