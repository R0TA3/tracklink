# 🔗 TrackLink

A full-stack URL tracker built with **Node.js + Express + SQLite**.  
Track who clicks your links — real IP, geolocation, browser, device, and referrer.

---

## 🚀 Quick Start

### 1. Install dependencies
```bash
npm install
```

### 2. Start the server
```bash
npm start
# or for auto-reload during development:
npm run dev
```

### 3. Open in browser
```
http://localhost:3000
```

---

## 📦 Tech Stack

| Layer      | Technology                        |
|------------|-----------------------------------|
| Backend    | Node.js + Express                 |
| Database   | SQLite via `better-sqlite3`       |
| Geolocation| ip-api.com (free, no key needed)  |
| UA Parsing | `ua-parser-js`                    |
| QR Codes   | `qrcode` npm package              |
| Short IDs  | `nanoid`                          |
| Frontend   | Vanilla HTML/CSS/JS               |

---

## 🔧 How It Works

1. **Create a link** — paste any URL, get a tracking link like `http://localhost:3000/t/abc1234`
2. **Share it** — send it to anyone via chat, email, QR code, etc.
3. **They click** — the server instantly:
   - Logs their **real IP address**
   - Looks up **country, region, city, ISP** via ip-api.com
   - Parses their **browser, OS, device type** from user-agent
   - Records the **referrer** (where they came from)
   - **Redirects them** to your original URL (they may not even notice)
4. **You see the data** — dashboard and logs update in real time

---

## 📡 API Endpoints

| Method | Path                  | Description                        |
|--------|-----------------------|------------------------------------|
| POST   | `/api/links`          | Create a tracking link             |
| GET    | `/api/links`          | List all links with click counts   |
| DELETE | `/api/links/:id`      | Delete a link + its visit logs     |
| GET    | `/api/visits`         | Get all visits (optional ?link_id) |
| GET    | `/api/stats`          | Global stats (totals, today)       |
| GET    | `/api/qr/:slug`       | Get QR code PNG for a link         |
| GET    | `/t/:slug`            | **Tracking redirect** (main route) |

### Example: Create a link
```bash
curl -X POST http://localhost:3000/api/links \
  -H "Content-Type: application/json" \
  -d '{"target":"https://google.com","label":"Test Link","slug":"google-test"}'
```

Response:
```json
{
  "id": "abc123xyz",
  "slug": "google-test",
  "label": "Test Link",
  "target": "https://google.com",
  "trackingUrl": "http://localhost:3000/t/google-test",
  "created": "2026-03-13T10:00:00.000Z"
}
```

---

## 🌐 Deploy to the Internet (so links work from anywhere)

### Option A — Railway (easiest, free tier)
1. Push this folder to a GitHub repo
2. Go to https://railway.app → New Project → Deploy from GitHub
3. Select your repo, Railway auto-detects Node.js
4. Your app gets a public URL like `https://tracklink-xyz.up.railway.app`

### Option B — Render
1. Push to GitHub
2. https://render.com → New Web Service → connect repo
3. Build command: `npm install`
4. Start command: `npm start`

### Option C — VPS (DigitalOcean, Linode, etc.)
```bash
# On your server:
git clone <your-repo>
cd tracklink
npm install
npm install -g pm2
pm2 start server.js --name tracklink
pm2 save
```
Then set up Nginx as a reverse proxy to port 3000.

---

## 📝 Geolocation Note

This project uses **ip-api.com** (free tier):
- No API key required
- Limit: 45 requests/minute on free tier
- For production with high traffic, consider upgrading or using ipinfo.io / MaxMind

---

## 🔒 Legal / Ethics Note

- Always **disclose** that links are tracked if used in a professional context
- GDPR requires informing EU users about data collection
- This project is for **learning and legitimate analytics** only

---

## 📁 Project Structure

```
tracklink/
├── server.js          ← Express server + all API routes
├── package.json
├── tracklink.db       ← SQLite database (auto-created on first run)
└── public/
    └── index.html     ← Single-page frontend (HTML + CSS + JS)
```
