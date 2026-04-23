import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts'

const TOOLTIP_STYLE = {
  contentStyle: {
    backgroundColor: '#1e293b',
    border: '1px solid #334155',
    borderRadius: '8px',
    fontSize: '12px',
  },
}

function CustomLabel({ cx, cy, total }) {
  return (
    <>
      <text x={cx} y={cy - 6} textAnchor="middle" fill="#ffffff" fontSize={22} fontWeight={700}>
        {total.toLocaleString()}
      </text>
      <text x={cx} y={cy + 14} textAnchor="middle" fill="#64748b" fontSize={11}>
        total blocked
      </text>
    </>
  )
}

export default function AttackTypeChart({ data }) {
  const total = data.reduce((s, d) => s + d.value, 0)

  return (
    <div className="bg-slate-800 border border-slate-700 rounded-xl p-5 h-full flex flex-col">
      <p className="text-white font-semibold mb-1">Attack Distribution</p>
      <p className="text-slate-400 text-xs mb-2">Today's breakdown by type</p>

      <div className="flex-1 flex flex-col items-center justify-center">
        <ResponsiveContainer width="100%" height={180}>
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={55}
              outerRadius={80}
              paddingAngle={3}
              dataKey="value"
              labelLine={false}
            >
              {data.map((entry, i) => (
                <Cell key={i} fill={entry.color} stroke="transparent" />
              ))}
            </Pie>
            <Tooltip
              {...TOOLTIP_STYLE}
              formatter={(value, name) => [`${value} packets`, name]}
            />
            {/* centre label rendered via SVG text */}
            <text x="50%" y="46%" textAnchor="middle" dominantBaseline="middle" fill="#ffffff" fontSize={22} fontWeight={700}>
              {total.toLocaleString()}
            </text>
            <text x="50%" y="57%" textAnchor="middle" dominantBaseline="middle" fill="#64748b" fontSize={11}>
              total blocked
            </text>
          </PieChart>
        </ResponsiveContainer>

        {/* Legend */}
        <div className="flex flex-col gap-2 w-full mt-1">
          {data.map(d => (
            <div key={d.name} className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: d.color }} />
                <span className="text-slate-300 text-xs">{d.name}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-slate-200 text-xs font-semibold tabular-nums">{d.value}</span>
                <span className="text-slate-500 text-xs tabular-nums w-9 text-right">
                  {total ? `${Math.round((d.value / total) * 100)}%` : '0%'}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
