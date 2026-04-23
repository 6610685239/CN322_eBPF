export default function TopBlockedIPs({ data }) {
  const max = data[0]?.count || 1

  return (
    <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
      <p className="text-white font-semibold mb-1">Top Blocked IPs</p>
      <p className="text-slate-400 text-xs mb-4">Most active attackers (last 24h)</p>

      {data.length === 0 ? (
        <p className="text-slate-500 text-sm text-center py-6">No data yet</p>
      ) : (
        <div className="space-y-4">
          {data.map(({ ip, count }, i) => (
            <div key={ip}>
              <div className="flex items-center justify-between mb-1.5">
                <div className="flex items-center gap-2">
                  <span className="text-slate-600 text-xs font-mono w-4 shrink-0">#{i + 1}</span>
                  <span className="text-slate-100 text-sm font-mono">{ip}</span>
                </div>
                <span className="text-red-400 text-sm font-bold tabular-nums">{count.toLocaleString()}</span>
              </div>
              <div className="h-1.5 bg-slate-700 rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full bg-gradient-to-r from-red-600 to-red-400 transition-all duration-700"
                  style={{ width: `${(count / max) * 100}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
