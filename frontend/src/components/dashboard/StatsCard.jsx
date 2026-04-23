const COLOR_MAP = {
  blue:   { bg: 'bg-blue-500/10',   border: 'border-blue-500/20',   icon: 'text-blue-400',   val: 'text-blue-400'   },
  red:    { bg: 'bg-red-500/10',    border: 'border-red-500/20',    icon: 'text-red-400',    val: 'text-red-400'    },
  yellow: { bg: 'bg-yellow-500/10', border: 'border-yellow-500/20', icon: 'text-yellow-400', val: 'text-yellow-400' },
  orange: { bg: 'bg-orange-500/10', border: 'border-orange-500/20', icon: 'text-orange-400', val: 'text-orange-400' },
}

export default function StatsCard({ title, value, subtitle, icon: Icon, color = 'blue' }) {
  const c = COLOR_MAP[color]
  return (
    <div className="bg-slate-800 border border-slate-700 rounded-xl p-5 flex items-start justify-between gap-3">
      <div className="min-w-0">
        <p className="text-slate-400 text-sm truncate">{title}</p>
        <p className={`text-3xl font-bold mt-1 tabular-nums ${c.val}`}>
          {value.toLocaleString()}
        </p>
        {subtitle && (
          <p className="text-slate-500 text-xs mt-1 truncate">{subtitle}</p>
        )}
      </div>
      <div className={`${c.bg} border ${c.border} rounded-lg p-2.5 shrink-0`}>
        <Icon className={`w-5 h-5 ${c.icon}`} />
      </div>
    </div>
  )
}
