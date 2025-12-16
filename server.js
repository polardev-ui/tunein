const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const { randomUUID } = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Track which station each client is tuned to (in memory)
// clientId -> { station: string, updatedAt: number }
const clientStations = new Map();

app.use(express.json());
app.use(cookieParser());

// Simple client ID via cookie so we can count unique listeners
app.use((req, res, next) => {
  let id = req.cookies.clientId;
  if (!id) {
    id = randomUUID();
    // Not httpOnly so frontend can still read if needed, but fine for demo
    res.cookie('clientId', id, {
      maxAge: 1000 * 60 * 60 * 24 * 7,
      sameSite: 'lax'
    });
  }
  req.clientId = id;
  next();
});

// Client calls this when tuning to a station
app.post('/api/tune', (req, res) => {
  const { station } = req.body || {};
  if (!station || typeof station !== 'string') {
    return res.status(400).json({ error: 'station is required' });
  }

  clientStations.set(req.clientId, {
    station,
    updatedAt: Date.now()
  });

  res.json({ ok: true });
});

// Stats: total listeners + counts per station
app.get('/api/stats', (req, res) => {
  const now = Date.now();
  const cutoff = now - 5 * 60 * 1000; // drop listeners idle for > 5 minutes

  // Clean up stale entries
  for (const [id, info] of clientStations.entries()) {
    if (!info || info.updatedAt < cutoff) {
      clientStations.delete(id);
    }
  }

  const stations = {};
  for (const info of clientStations.values()) {
    if (!info || !info.station) continue;
    stations[info.station] = (stations[info.station] || 0) + 1;
  }

  let total = 0;
  for (const key of Object.keys(stations)) {
    total += stations[key];
  }

  res.json({ total, stations });
});

// Serve static files (index.html, audio, etc.) from this folder
app.use(express.static(path.join(__dirname)));

app.listen(PORT, () => {
  console.log(`tune in server listening on http://localhost:${PORT}`);
});
