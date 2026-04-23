import { useState, useEffect, useMemo } from 'react'
import { Shield, ShieldX, WifiOff, Globe, Pause, Play } from 'lucide-react'
import {
  MOCK_EVENTS,
  generateEvent,
  getHourlyTraffic,
  getTopIPs,
  getTypeDistribution,
} from '../mock/data'
import StatsCard       from '../components/dashboard/StatsCard'
import TrafficChart    from '../components/dashboard/TrafficChart'
import AttackTypeChart from '../components/dashboard/AttackTypeChart'
import TopBlockedIPs   from '../components/dashboard/TopBlockedIPs'
import RecentEvents    from '../components/dashboard/RecentEvents'

function startOfToday() {
  const d = new Date()
  d.setHours(0, 0, 0, 0)
  return d
}

export default function Dashboard() {
  const [events, setEvents] = useState(MOCK_EVENTS)
  const [isLive, setIsLive]   = useState(true)
  const [clock,  setClock]    = useState(new Date())

  // Clock tick
  useEffect(() => {
    const t = setInterval(() => setClock(new Date()), 1000)
    return () => clearInterval(t)
  }, [])

  // Simulate live events arriving every 1.5–4 s
  useEffect(() => {
    if (!isLive) return
    let timeout
    const schedule = () => {
      timeout = setTimeout(() => {
        setEvents(prev => [generateEvent(), ...prev].slice(0, 600))
        schedule()
      }, 1500 + Math.random() * 2500)
    }
    schedule()
    return () => clearTimeout(timeout)
  }, [isLive])

  // Derived data (memoised so we don't recompute on every clock tick)
  const todayEvents   = useMemo(() => events.filter(e => new Date(e.created_at) >= startOfToday()), [events])
  const hourlyData    = useMemo(() => getHourlyTraffic(events),      [events])
  const topIPs        = useMemo(() => getTopIPs(events),             [events])
  const distribution  = useMemo(() => getTypeDistribution(todayEvents), [todayEvents])

  const stats = {
    total:     todayEvents.length,
    blacklist: todayEvents.filter(e => e.event_type === 1).length,
    ping:      todayEvents.filter(e => e.event_type === 2).length,
    web:       todayEvents.filter(e => e.event_type === 3).length,
  }

  const pct = (n) => stats.total ? `${Math.round((n / stats.total) * 100)}% of today` : '—'

  return (
    <div className="p-6 space-y-5 min-h-full">

      {/* ── Header ─────────────────────────────────────────────── */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Dashboard</h1>
          <p className="text-slate-400 text-sm mt-0.5">
            {clock.toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}
            {' · '}
            <span className="font-mono">{clock.toLocaleTimeString()}</span>
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Live / Pause toggle */}
          <button
            onClick={() => setIsLive(v => !v)}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-medium border transition-colors ${
              isLive
                ? 'bg-green-500/10 border-green-500/25 text-green-400 hover:bg-green-500/20'
                : 'bg-slate-700 border-slate-600 text-slate-300 hover:bg-slate-600'
            }`}
          >
            {isLive
              ? <><span className="w-1.5 h-1.5 bg-green-400 rounded-full animate-pulse" /><Pause className="w-3.5 h-3.5" /> Live</>
              : <><Play  className="w-3.5 h-3.5" /> Paused</>
            }
          </button>

          {/* Network interfaces badge */}
          <div className="bg-slate-800 border border-slate-700 rounded-lg px-3.5 py-2 text-xs text-slate-400">
            <span className="text-slate-500">Interfaces:</span>
            {' '}
            <span className="text-cyan-400 font-mono">enp0s3 · enp0s8 · enp0s9</span>
          </div>
        </div>
      </div>

      {/* ── Stats cards ────────────────────────────────────────── */}
      <div className="grid grid-cols-4 gap-4">
        <StatsCard
          title="Total Blocked Today"
          value={stats.total}
          subtitle="All attack types combined"
          icon={Shield}
          color="blue"
        />
        <StatsCard
          title="Blacklist Hits"
          value={stats.blacklist}
          subtitle={pct(stats.blacklist)}
          icon={ShieldX}
          color="red"
        />
        <StatsCard
          title="Ping Attacks"
          value={stats.ping}
          subtitle={pct(stats.ping)}
          icon={WifiOff}
          color="yellow"
        />
        <StatsCard
          title="Web Attacks"
          value={stats.web}
          subtitle="Ports 80 · 443 · 8000"
          icon={Globe}
          color="orange"
        />
      </div>

      {/* ── Charts row ─────────────────────────────────────────── */}
      <div className="grid grid-cols-5 gap-4">
        <div className="col-span-3">
          <TrafficChart data={hourlyData} />
        </div>
        <div className="col-span-2">
          <AttackTypeChart data={distribution} />
        </div>
      </div>

      {/* ── Bottom row ─────────────────────────────────────────── */}
      <div className="grid grid-cols-2 gap-4">
        <TopBlockedIPs data={topIPs} />
        <RecentEvents  events={events.slice(0, 25)} />
      </div>
    </div>
  )
}
