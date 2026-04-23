const ATTACKER_IPS = [
  '185.220.101.45',
  '91.108.4.0',
  '45.33.32.156',
  '198.20.69.74',
  '213.95.10.220',
  '5.188.210.100',
  '185.100.87.120',
  '89.248.167.131',
  '192.241.221.79',
  '64.62.197.182',
]

const INTERFACES = ['enp0s3', 'enp0s8', 'enp0s9']
const WEB_PORTS = [80, 443, 8000]

let _idCounter = 1000

function pickRandom(arr) {
  return arr[Math.floor(Math.random() * arr.length)]
}

function randomType() {
  const r = Math.random()
  return r < 0.35 ? 1 : r < 0.62 ? 2 : 3
}

export function generateEvent() {
  const type = randomType()
  return {
    id: ++_idCounter,
    created_at: new Date().toISOString(),
    source_ip: pickRandom(ATTACKER_IPS),
    dest_port: type === 3 ? pickRandom(WEB_PORTS) : null,
    event_type: type,
    interface: pickRandom(INTERFACES),
  }
}

function generateHistoricalEvents(count = 350) {
  const events = []
  for (let i = 0; i < count; i++) {
    const hoursAgo = Math.random() * 24
    const type = randomType()
    events.push({
      id: i + 1,
      created_at: new Date(Date.now() - hoursAgo * 3_600_000).toISOString(),
      source_ip: pickRandom(ATTACKER_IPS),
      dest_port: type === 3 ? pickRandom(WEB_PORTS) : null,
      event_type: type,
      interface: pickRandom(INTERFACES),
    })
  }
  return events.sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
}

export const MOCK_EVENTS = generateHistoricalEvents()

export const MOCK_BLACKLIST = [
  { id: 1, ip_address: '185.220.101.45', reason: 'Tor exit node',      is_active: true,  hit_count: 45, created_at: new Date(Date.now() - 86400000 * 3).toISOString() },
  { id: 2, ip_address: '45.33.32.156',   reason: 'Shodan scanner',     is_active: true,  hit_count: 23, created_at: new Date(Date.now() - 86400000 * 7).toISOString() },
  { id: 3, ip_address: '1.1.1.1',        reason: 'Manual block',       is_active: true,  hit_count: 12, created_at: new Date(Date.now() - 86400000 * 1).toISOString() },
  { id: 4, ip_address: '8.8.8.8',        reason: 'Manual block',       is_active: true,  hit_count: 8,  created_at: new Date(Date.now() - 86400000 * 2).toISOString() },
  { id: 5, ip_address: '192.168.1.108',  reason: 'Suspicious activity',is_active: false, hit_count: 3,  created_at: new Date(Date.now() - 86400000 * 5).toISOString() },
]

export function getHourlyTraffic(events) {
  return Array.from({ length: 24 }, (_, i) => {
    const target = new Date()
    target.setHours(target.getHours() - (23 - i), 0, 0, 0)
    const h = target.getHours()
    const slice = events.filter(e => new Date(e.created_at).getHours() === h)
    return {
      time: `${String(h).padStart(2, '0')}:00`,
      blacklist: slice.filter(e => e.event_type === 1).length,
      ping:      slice.filter(e => e.event_type === 2).length,
      web:       slice.filter(e => e.event_type === 3).length,
    }
  })
}

export function getTopIPs(events, limit = 5) {
  const counts = {}
  events.forEach(e => { counts[e.source_ip] = (counts[e.source_ip] || 0) + 1 })
  return Object.entries(counts)
    .sort(([, a], [, b]) => b - a)
    .slice(0, limit)
    .map(([ip, count]) => ({ ip, count }))
}

export function getTypeDistribution(events) {
  return [
    { name: 'Blacklist', value: events.filter(e => e.event_type === 1).length, color: '#ef4444' },
    { name: 'Ping',      value: events.filter(e => e.event_type === 2).length, color: '#eab308' },
    { name: 'Web',       value: events.filter(e => e.event_type === 3).length, color: '#f97316' },
  ]
}
