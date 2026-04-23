function timeAgo(dateStr) {
  const diff = Date.now() - new Date(dateStr).getTime()
  const s = Math.floor(diff / 1000)
  if (s < 60)  return `${s}s ago`
  const m = Math.floor(s / 60)
  if (m < 60)  return `${m}m ago`
  const h = Math.floor(m / 60)
  return `${h}h ago`
}

const TYPE_CONFIG = {
  1: { label: 'BLACKLIST', cls: 'text-red-400    bg-red-500/10    border-red-500/30'    },
  2: { label: 'PING',      cls: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30' },
  3: { label: 'WEB',       cls: 'text-orange-400 bg-orange-500/10 border-orange-500/30' },
}

export default function RecentEvents({ events }) {
  return (
    <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
      <div className="flex items-center justify-between mb-4">
        <div>
          <p className="text-white font-semibold">Recent Events</p>
          <p className="text-slate-400 text-xs mt-0.5">Latest blocked packets</p>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 bg-green-400 rounded-full animate-pulse" />
          <span className="text-green-400 text-xs font-medium">Live</span>
        </div>
      </div>

      <div className="overflow-y-auto max-h-64 space-y-0 pr-1">
        {events.map(e => {
          const cfg = TYPE_CONFIG[e.event_type]
          return (
            <div
              key={e.id}
              className="flex items-center gap-2.5 py-2 border-b border-slate-700/40 last:border-0"
            >
              <span className={`text-xs font-semibold px-2 py-0.5 rounded border shrink-0 ${cfg.cls}`}>
                {cfg.label}
              </span>
              <span className="text-slate-200 text-xs font-mono flex-1 truncate">{e.source_ip}</span>
              {e.dest_port ? (
                <span className="text-slate-500 text-xs font-mono shrink-0">:{e.dest_port}</span>
              ) : (
                <span className="text-slate-600 text-xs font-mono shrink-0">—</span>
              )}
              <span className="text-slate-500 text-xs shrink-0 w-14 text-right tabular-nums">
                {timeAgo(e.created_at)}
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
