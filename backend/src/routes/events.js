import { Router } from 'express'
import { supabase } from '../lib/supabase.js'

const router = Router()

// GET /api/events?limit=50
router.get('/', async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 500)
  if (!supabase) return res.json([])

  const { data, error } = await supabase
    .from('blocked_events')
    .select('*')
    .order('created_at', { ascending: false })
    .limit(limit)

  if (error) return res.status(500).json({ error: error.message })
  res.json(data)
})

// POST /api/events  — called by loader.py wrapper
router.post('/', async (req, res) => {
  const { source_ip, dest_port, event_type, interface: iface } = req.body
  if (!supabase) return res.status(503).json({ error: 'Supabase not configured' })

  const { data, error } = await supabase
    .from('blocked_events')
    .insert({ source_ip, dest_port, event_type, interface: iface })
    .select()
    .single()

  if (error) return res.status(500).json({ error: error.message })
  res.status(201).json(data)
})

export default router
