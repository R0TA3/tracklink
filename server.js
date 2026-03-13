const express = require('express');
const Database = require('better-sqlite3');
const UAParser = require('ua-parser-js');
const QRCode = require('qrcode');
const crypto = require('crypto');
const path = require('path');

const app = express();
const db = new Database('tracklink.db');

// ─── CONFIG ──────────────────────────────────────────────────────────────────
const ADMIN_USERNAME = process.env.ADMIN_USER || 'a3achu';
const ADMIN_PASSWORD = process.env.ADMIN_PASS || 'tracklink2024';

// ─── DB SETUP ────────────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS links (
    id TEXT PRIMARY KEY, slug TEXT UNIQUE NOT NULL,
    label TEXT, target TEXT NOT NULL, created TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS visits (
    id TEXT PRIMARY KEY, link_id TEXT NOT NULL,
    ip TEXT, ip_type TEXT,
    country TEXT, country_code TEXT, city TEXT, region TEXT,
    region_code TEXT, zip TEXT, lat REAL, lon REAL,
    timezone TEXT, isp TEXT, org TEXT, as_number TEXT,
    is_proxy INTEGER DEFAULT 0, is_vpn INTEGER DEFAULT 0,
    is_tor INTEGER DEFAULT 0, is_mobile INTEGER DEFAULT 0,
    browser TEXT, browser_ver TEXT, browser_engine TEXT,
    os TEXT, os_ver TEXT, device TEXT, device_brand TEXT,
    device_model TEXT, cpu_arch TEXT,
    referrer TEXT, referrer_domain TEXT, ua TEXT,
    language TEXT, screen TEXT, color_depth TEXT,
    timezone_client TEXT, platform TEXT,
    time TEXT NOT NULL,
    FOREIGN KEY(link_id) REFERENCES links(id)
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY, created TEXT NOT NULL
  );
`);

// ─── MIDDLEWARE ───────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

function requireAuth(req, res, next) {
  const token = req.headers['x-auth-token'] || req.query.token;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
  if (!session) return res.status(401).json({ error: 'Invalid session' });
  next();
}

// ─── HELPERS ─────────────────────────────────────────────────────────────────
function getIP(req) {
  return (
    req.headers['cf-connecting-ip'] ||
    req.headers['x-real-ip'] ||
    (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
    req.socket.remoteAddress || '0.0.0.0'
  ).replace('::ffff:', '');
}

async function geoLocate(ip) {
  const isPrivate = ['127.0.0.1','::1','0.0.0.0'].includes(ip) ||
    ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.16.');
  if (isPrivate) return {
    country:'Local Network', country_code:'LO', city:'Localhost',
    region:'', region_code:'', zip:'', lat:0, lon:0,
    timezone:'Local', isp:'Local', org:'Local', as_number:'',
    is_proxy:0, is_mobile:0, ip_type:'private'
  };
  try {
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,mobile,hosting`);
    const d = await res.json();
    if (d.status === 'success') return {
      country:d.country, country_code:d.countryCode,
      city:d.city, region:d.regionName, region_code:d.region,
      zip:d.zip, lat:d.lat, lon:d.lon, timezone:d.timezone,
      isp:d.isp, org:d.org, as_number:d.as,
      is_proxy:d.proxy?1:0, is_vpn:d.proxy?1:0, is_mobile:d.mobile?1:0,
      ip_type:d.hosting?'hosting':'residential'
    };
  } catch(_) {}
  return { country:'Unknown', country_code:'??', city:'Unknown', region:'', region_code:'', zip:'', lat:0, lon:0, timezone:'', isp:'', org:'', as_number:'', is_proxy:0, is_mobile:0, ip_type:'unknown' };
}

function parseUA(ua) {
  const r = new UAParser(ua).getResult();
  return {
    browser:r.browser.name||'Unknown', browser_ver:r.browser.major||'',
    browser_engine:r.engine.name||'', os:r.os.name||'Unknown',
    os_ver:r.os.version||'', device:r.device.type||'desktop',
    device_brand:r.device.vendor||'', device_model:r.device.model||'',
    cpu_arch:r.cpu.architecture||''
  };
}

function refDomain(ref) {
  if (!ref || ref === 'Direct') return 'Direct';
  try { return new URL(ref).hostname; } catch { return ref; }
}

// ─── AUTH ────────────────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    const token = crypto.randomBytes(32).toString('hex');
    db.prepare('INSERT INTO sessions (token, created) VALUES (?, ?)').run(token, new Date().toISOString());
    res.json({ token, username });
  } else {
    res.status(401).json({ error: 'Invalid username or password' });
  }
});

app.post('/api/logout', (req, res) => {
  const token = req.headers['x-auth-token'];
  if (token) db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => res.json({ username: ADMIN_USERNAME }));

// ─── LINKS ───────────────────────────────────────────────────────────────────
app.post('/api/links', requireAuth, (req, res) => {
  const { target, label, slug: cs } = req.body;
  if (!target) return res.status(400).json({ error: 'target URL is required' });
  try { new URL(target); } catch { return res.status(400).json({ error: 'Invalid URL' }); }
  const slug = cs?.trim().replace(/\s+/g,'-').toLowerCase() || crypto.randomBytes(4).toString('hex');
  const id = crypto.randomBytes(4).toString('hex');
  try {
    db.prepare('INSERT INTO links (id,slug,label,target,created) VALUES (?,?,?,?,?)')
      .run(id, slug, label||target, target, new Date().toISOString());
    res.json({ id, slug, label: label||target, target });
  } catch(e) {
    if (e.message.includes('UNIQUE')) return res.status(409).json({ error: 'Slug taken.' });
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/links', requireAuth, (req, res) => {
  res.json(db.prepare('SELECT l.*, COUNT(v.id) as clicks FROM links l LEFT JOIN visits v ON v.link_id=l.id GROUP BY l.id ORDER BY l.created DESC').all());
});

app.delete('/api/links/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM visits WHERE link_id=?').run(req.params.id);
  db.prepare('DELETE FROM links WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

app.get('/api/visits', requireAuth, (req, res) => {
  const { link_id } = req.query;
  const q = link_id
    ? 'SELECT v.*,l.label as link_label,l.slug as link_slug FROM visits v JOIN links l ON l.id=v.link_id WHERE v.link_id=? ORDER BY v.time DESC LIMIT 500'
    : 'SELECT v.*,l.label as link_label,l.slug as link_slug FROM visits v JOIN links l ON l.id=v.link_id ORDER BY v.time DESC LIMIT 500';
  res.json(link_id ? db.prepare(q).all(link_id) : db.prepare(q).all());
});

app.get('/api/stats', requireAuth, (req, res) => {
  const today = new Date().toISOString().split('T')[0];
  res.json({
    total_clicks:  db.prepare('SELECT COUNT(*) as c FROM visits').get().c,
    unique_ips:    db.prepare('SELECT COUNT(DISTINCT ip) as c FROM visits').get().c,
    total_links:   db.prepare('SELECT COUNT(*) as c FROM links').get().c,
    today_clicks:  db.prepare("SELECT COUNT(*) as c FROM visits WHERE time LIKE ?").get(today+'%').c,
    top_countries: db.prepare('SELECT country,country_code,COUNT(*) as count FROM visits GROUP BY country ORDER BY count DESC LIMIT 8').all(),
    top_browsers:  db.prepare('SELECT browser,COUNT(*) as count FROM visits GROUP BY browser ORDER BY count DESC LIMIT 6').all(),
    devices:       db.prepare('SELECT device,COUNT(*) as count FROM visits GROUP BY device ORDER BY count DESC').all(),
    top_isps:      db.prepare("SELECT isp,COUNT(*) as count FROM visits WHERE isp!='' GROUP BY isp ORDER BY count DESC LIMIT 5").all(),
    proxy_count:   db.prepare('SELECT COUNT(*) as c FROM visits WHERE is_proxy=1').get().c,
    map_points:    db.prepare('SELECT lat,lon,city,country,country_code,ip,time,device,browser FROM visits WHERE lat!=0 AND lon!=0 ORDER BY time DESC LIMIT 300').all(),
  });
});

app.get('/api/qr', requireAuth, async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).send('url required');
  try {
    const dataUrl = await QRCode.toDataURL(url, { width:300, margin:2, color:{dark:'#00e5ff',light:'#0a0a0f'} });
    res.json({ qr: dataUrl });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Enrich visit with client-side browser data
app.post('/api/enrich/:visitId', (req, res) => {
  const { language, screen, colorDepth, timezone, platform } = req.body;
  db.prepare('UPDATE visits SET language=?,screen=?,color_depth=?,timezone_client=?,platform=? WHERE id=?')
    .run(language||'', screen||'', colorDepth||'', timezone||'', platform||'', req.params.visitId);
  res.json({ ok: true });
});

// ─── TRACKER REDIRECT ─────────────────────────────────────────────────────────
app.get('/t/:slug', async (req, res) => {
  const link = db.prepare('SELECT * FROM links WHERE slug=?').get(req.params.slug);
  if (!link) return res.status(404).send('Link not found.');

  const visitId = crypto.randomBytes(4).toString('hex');
  const ip = getIP(req);
  const ua = req.headers['user-agent'] || '';
  const referrer = req.headers['referer'] || 'Direct';
  const parsed = parseUA(ua);

  db.prepare(`INSERT INTO visits (id,link_id,ip,browser,browser_ver,browser_engine,os,os_ver,device,device_brand,device_model,cpu_arch,referrer,referrer_domain,ua,time) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(visitId, link.id, ip, parsed.browser, parsed.browser_ver, parsed.browser_engine, parsed.os, parsed.os_ver, parsed.device, parsed.device_brand, parsed.device_model, parsed.cpu_arch, referrer, refDomain(referrer), ua, new Date().toISOString());

  // Redirect immediately, enrich in background
  res.redirect(302, link.target);

  const geo = await geoLocate(ip);
  db.prepare(`UPDATE visits SET country=?,country_code=?,city=?,region=?,region_code=?,zip=?,lat=?,lon=?,timezone=?,isp=?,org=?,as_number=?,is_proxy=?,is_vpn=?,is_mobile=?,ip_type=? WHERE id=?`)
    .run(geo.country, geo.country_code, geo.city, geo.region, geo.region_code, geo.zip, geo.lat, geo.lon, geo.timezone, geo.isp, geo.org, geo.as_number, geo.is_proxy, geo.is_vpn||0, geo.is_mobile, geo.ip_type||'', visitId);
});

// ─── STATIC ───────────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n  🔗 TrackLink → http://localhost:${PORT}`);
  console.log(`  Login: ${ADMIN_USERNAME} / ${ADMIN_PASSWORD}\n`);
});
