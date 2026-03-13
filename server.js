// ─────────────────────────────────────────────
//  TrackLink — server.js
//  Node.js + Express link tracker
// ─────────────────────────────────────────────
const express  = require('express');
const Database = require('better-sqlite3');
const fetch    = require('node-fetch');
const UAParser = require('ua-parser-js');
const QRCode   = require('qrcode');
const path     = require('path');
const { nanoid } = require('nanoid');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─── DATABASE SETUP ───────────────────────────
const db = new Database('tracklink.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS links (
    id        TEXT PRIMARY KEY,
    slug      TEXT UNIQUE NOT NULL,
    label     TEXT,
    target    TEXT NOT NULL,
    created   TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS visits (
    id           TEXT PRIMARY KEY,
    link_id      TEXT NOT NULL,
    ip           TEXT,
    country      TEXT,
    country_code TEXT,
    region       TEXT,
    city         TEXT,
    lat          REAL,
    lon          REAL,
    isp          TEXT,
    browser      TEXT,
    browser_ver  TEXT,
    os           TEXT,
    os_ver       TEXT,
    device_type  TEXT,
    referrer     TEXT,
    ua           TEXT,
    visited_at   TEXT NOT NULL,
    FOREIGN KEY(link_id) REFERENCES links(id)
  );
`);

// ─── MIDDLEWARE ───────────────────────────────
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── HELPERS ──────────────────────────────────

// Get real client IP (works behind proxies / Nginx)
function getIP(req) {
  return (
    req.headers['x-forwarded-for']?.split(',')[0].trim() ||
    req.headers['x-real-ip'] ||
    req.socket.remoteAddress ||
    '0.0.0.0'
  );
}

// Free IP geolocation — ip-api.com (no key needed, 45 req/min on free tier)
async function geolocate(ip) {
  try {
    if (ip === '::1' || ip === '127.0.0.1' || ip.startsWith('192.168') || ip.startsWith('10.')) {
      return { country: 'Localhost', country_code: 'LH', region: '-', city: 'Local', lat: 0, lon: 0, isp: 'Local Network' };
    }
    const res  = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,regionName,city,lat,lon,isp`, { timeout: 4000 });
    const data = await res.json();
    if (data.status !== 'success') return {};
    return {
      country:      data.country,
      country_code: data.countryCode,
      region:       data.regionName,
      city:         data.city,
      lat:          data.lat,
      lon:          data.lon,
      isp:          data.isp,
    };
  } catch {
    return {};
  }
}

// Parse user-agent string
function parseUA(uaString) {
  const r = new UAParser(uaString).getResult();
  return {
    browser:     r.browser.name  || 'Unknown',
    browser_ver: r.browser.major || '',
    os:          r.os.name       || 'Unknown',
    os_ver:      r.os.version    || '',
    device_type: r.device.type   || 'desktop',
  };
}

// Country flag emoji from 2-letter country code
function countryFlag(code) {
  if (!code || code.length !== 2) return '🌐';
  return String.fromCodePoint(...[...code.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65));
}

// ─── API ROUTES ───────────────────────────────

// POST /api/links  — create tracking link
app.post('/api/links', (req, res) => {
  const { target, label, slug: customSlug } = req.body;

  if (!target) return res.status(400).json({ error: 'target URL is required' });
  try { new URL(target); } catch { return res.status(400).json({ error: 'Invalid target URL' }); }

  const id   = nanoid(10);
  const slug = customSlug?.trim().replace(/\s+/g, '-').toLowerCase() || nanoid(7);

  try {
    db.prepare(`INSERT INTO links (id, slug, label, target, created) VALUES (?,?,?,?,?)`)
      .run(id, slug, label || target, target, new Date().toISOString());

    const trackingUrl = `${req.protocol}://${req.get('host')}/t/${slug}`;
    res.json({ id, slug, label: label || target, target, trackingUrl, created: new Date().toISOString() });
  } catch (e) {
    if (e.message.includes('UNIQUE')) return res.status(409).json({ error: 'Slug already taken' });
    res.status(500).json({ error: e.message });
  }
});

// GET /api/links  — list all links with click count
app.get('/api/links', (req, res) => {
  const rows = db.prepare(`
    SELECT l.*, COUNT(v.id) as clicks
    FROM links l LEFT JOIN visits v ON v.link_id = l.id
    GROUP BY l.id ORDER BY l.created DESC
  `).all();
  const base = `${req.protocol}://${req.get('host')}`;
  res.json(rows.map(r => ({ ...r, trackingUrl: `${base}/t/${r.slug}` })));
});

// DELETE /api/links/:id
app.delete('/api/links/:id', (req, res) => {
  db.prepare('DELETE FROM visits WHERE link_id = ?').run(req.params.id);
  db.prepare('DELETE FROM links  WHERE id      = ?').run(req.params.id);
  res.json({ ok: true });
});

// GET /api/visits  — visits list, optional ?link_id=
app.get('/api/visits', (req, res) => {
  const { link_id } = req.query;
  const rows = link_id
    ? db.prepare('SELECT * FROM visits WHERE link_id=? ORDER BY visited_at DESC').all(link_id)
    : db.prepare('SELECT * FROM visits ORDER BY visited_at DESC LIMIT 500').all();
  res.json(rows.map(r => ({ ...r, flag: countryFlag(r.country_code) })));
});

// GET /api/stats  — global stats
app.get('/api/stats', (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  res.json({
    total_links:  db.prepare('SELECT COUNT(*) c FROM links').get().c,
    total_clicks: db.prepare('SELECT COUNT(*) c FROM visits').get().c,
    unique_ips:   db.prepare('SELECT COUNT(DISTINCT ip) c FROM visits').get().c,
    today:        db.prepare("SELECT COUNT(*) c FROM visits WHERE visited_at LIKE ?").get(`${today}%`).c,
  });
});

// GET /api/qr/:slug  — QR code PNG
app.get('/api/qr/:slug', async (req, res) => {
  const link = db.prepare('SELECT * FROM links WHERE slug=?').get(req.params.slug);
  if (!link) return res.status(404).json({ error: 'Not found' });
  const url = `${req.protocol}://${req.get('host')}/t/${link.slug}`;
  const png = await QRCode.toBuffer(url, { width: 300, margin: 2, color: { dark: '#00e5ff', light: '#0a0a0f' } });
  res.set('Content-Type', 'image/png');
  res.send(png);
});

// ─── TRACKING REDIRECT ────────────────────────
app.get('/t/:slug', async (req, res) => {
  const link = db.prepare('SELECT * FROM links WHERE slug=?').get(req.params.slug);
  if (!link) return res.status(404).send('<h1 style="font-family:monospace">404 — Link not found</h1>');

  // Redirect immediately, log in background
  res.redirect(302, link.target);

  // Async logging (doesn't delay the redirect)
  setImmediate(async () => {
    try {
      const ip  = getIP(req);
      const geo = await geolocate(ip);
      const ua  = parseUA(req.headers['user-agent'] || '');
      const ref = req.headers['referer'] || req.headers['referrer'] || 'Direct';

      db.prepare(`
        INSERT INTO visits
          (id,link_id,ip,country,country_code,region,city,lat,lon,isp,
           browser,browser_ver,os,os_ver,device_type,referrer,ua,visited_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
      `).run(
        nanoid(10), link.id, ip,
        geo.country||'', geo.country_code||'', geo.region||'', geo.city||'',
        geo.lat||0, geo.lon||0, geo.isp||'',
        ua.browser, ua.browser_ver, ua.os, ua.os_ver, ua.device_type,
        ref, req.headers['user-agent']||'',
        new Date().toISOString()
      );
    } catch (e) { console.error('Log error:', e.message); }
  });
});

// ─── SPA FALLBACK ─────────────────────────────
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ─── START ────────────────────────────────────
app.listen(PORT, () => console.log(`\n🔗  TrackLink → http://localhost:${PORT}\n`));
