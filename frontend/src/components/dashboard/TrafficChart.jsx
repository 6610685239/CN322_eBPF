import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, Legend, ResponsiveContainer,
} from 'recharts'

const TOOLTIP_STYLE = {
  contentStyle: {
    backgroundColor: '#1e293b',
    border: '1px solid #334155',
    borderRadius: '8px',
    fontSize: '12px',
  },
  labelStyle: { color: '#e2e8f0', marginBottom: '4px' },
  itemStyle: { color: '#94a3b8' },
}

export default function TrafficChart({ data }) {
  return (
    <div className="bg-slate-800 border border-slate-700 rounded-xl p-5 h-full">
      <p className="text-white font-semibold mb-1">Traffic — Last 24h</p>
      <p className="text-slate-400 text-xs mb-4">Blocked packets per hour by attack type</p>
      <ResponsiveContainer width="100%" height={210}>
        <AreaChart data={data} margin={{ top: 4, right: 8, left: -24, bottom: 0 }}>
          <defs>
            {[
              ['gradBlacklist', '#ef4444'],
              ['gradPing',      '#eab308'],
              ['gradWeb',       '#f97316'],
            ].map(([id, color]) => (
              <linearGradient key={id} id={id} x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%"  stopColor={color} stopOpacity={0.25} />
                <stop offset="95%" stopColor={color} stopOpacity={0}    />
              </linearGradient>
            ))}
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
          <XAxis
            dataKey="time"
            tick={{ fill: '#64748b', fontSize: 10 }}
            tickLine={false}
            interval={3}
          />
          <YAxis
            tick={{ fill: '#64748b', fontSize: 10 }}
            tickLine={false}
            axisLine={false}
          />
          <Tooltip {...TOOLTIP_STYLE} />
          <Legend
            wrapperStyle={{ fontSize: '11px', paddingTop: '8px' }}
            formatter={v => <span style={{ color: '#94a3b8' }}>{v}</span>}
          />
          <Area type="monotone" dataKey="blacklist" name="Blacklist" stroke="#ef4444" fill="url(#gradBlacklist)" strokeWidth={2} dot={false} />
          <Area type="monotone" dataKey="ping"      name="Ping"      stroke="#eab308" fill="url(#gradPing)"      strokeWidth={2} dot={false} />
          <Area type="monotone" dataKey="web"       name="Web"       stroke="#f97316" fill="url(#gradWeb)"       strokeWidth={2} dot={false} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}
