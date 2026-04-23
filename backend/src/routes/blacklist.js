import { Router } from 'express'
import { supabase } from '../lib/supabase.js'

const router = Router()

router.get('/', async (req, res) => {
  if (!supabase) return res.json([])
  const { data, error } = await supabase
    .from('blacklist_rules')
    .select('*')
    .order('created_at', { ascending: false })
  if (error) return res.status(500).json({ error: error.message })
  res.json(data)
})

router.post('/', async (req, res) => {
  const { ip_address, reason } = req.body
  if (!supabase) return res.status(503).json({ error: 'Supabase not configured' })
  const { data, error } = await supabase
    .from('blacklist_rules')
    .insert({ ip_address, reason })
    .select()
    .single()
  if (error) return res.status(500).json({ error: error.message })
  res.status(201).json(data)
})

router.delete('/:id', async (req, res) => {
  if (!supabase) return res.status(503).json({ error: 'Supabase not configured' })
  const { error } = await supabase
    .from('blacklist_rules')
    .delete()
    .eq('id', req.params.id)
  if (error) return res.status(500).json({ error: error.message })
  res.status(204).end()
})

export default router
