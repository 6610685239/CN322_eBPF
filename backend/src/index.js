import 'dotenv/config'
import express from 'express'
import cors    from 'cors'
import eventsRouter   from './routes/events.js'
import blacklistRouter from './routes/blacklist.js'

const app  = express()
const PORT = process.env.PORT || 3001

app.use(cors())
app.use(express.json())

app.get('/api/health', (_, res) =>
  res.json({ status: 'ok', uptime: Math.floor(process.uptime()) })
)

app.use('/api/events',    eventsRouter)
app.use('/api/blacklist', blacklistRouter)

app.listen(PORT, () => console.log(`Backend listening on :${PORT}`))
