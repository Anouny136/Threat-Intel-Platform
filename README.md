# 🛡️ Threat Intel Hub

> A professional desktop threat intelligence platform for Windows. Queries 13 APIs in parallel, aggregates results with visual analytics, and generates PDF reports — all from a single app.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Platform](https://img.shields.io/badge/platform-Windows-informational)
![Electron](https://img.shields.io/badge/Electron-28-47848F?logo=electron)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Features

- **13 integrated threat intelligence APIs** queried in parallel
- **Visual threat scoring** — donut chart, breakdown bars, verdict badge
- **5 IOC types** — IP, Domain, Hash, URL, Email (auto-detected)
- **File analysis** — SHA-256 hashed locally, file never uploaded
- **Professional PDF reports** — dark-themed, multi-page, color-coded
- **OSINT Tools directory** — 37 curated tools across 8 categories with live search
- **Encrypted API key storage** via `electron-store`
- **Direct links** from each result card to the source website
- **Zero CORS issues** — all API calls run in Node.js main process

---

## Integrated APIs

### No key required (always active)
| Source | Provides |
|--------|----------|
| **IPInfo** | Geolocation, ASN, org, hosting/VPS detection |
| **BGPView** | ASN routing, CIDR prefix, country |

### Free tier available
| Source | IOC Types | Free Limit |
|--------|-----------|------------|
| **VirusTotal** | IP, Domain, Hash, URL | 500 req/day |
| **AbuseIPDB** | IP | 1,000 req/day |
| **AlienVault OTX** | IP, Domain, Hash | Free forever |
| **GreyNoise** | IP | 1,000 req/day |
| **URLScan.io** | URL, Domain | Free tier |
| **Hybrid Analysis** | Hash | Free tier |
| **Maltiverse** | Hash | Free tier |
| **SecurityTrails** | Domain, IP | 50 req/month |
| **Censys** | IP, Domain | Free tier |
| **HaveIBeenPwned** | Email | $3.50/month |

### Paid subscription required
| Source | IOC Types | Cost |
|--------|-----------|------|
| **Shodan** | IP | $49/year |

---

## Quick Start

### Step 1 — Install Node.js

Download from **[nodejs.org](https://nodejs.org)** → choose **LTS** → run installer → restart terminal.

Verify:
```
node --version    # must be v18 or higher
npm --version
```

### Step 2 — Clone & Install

```bash
git clone https://github.com/YOUR_USERNAME/threat-intel-hub.git
cd threat-intel-hub
npm install
```

`npm install` downloads Electron and dependencies. Takes 2–3 minutes, ~300MB. Only needed once.

### Step 3 — Run

```bash
npm start
```

### Step 4 — Add API Keys

1. Click **⚙ API Settings** in the top-right of the tab bar
2. Paste your keys (get them from the table below)
3. Click **Save All Configuration**

Keys are stored encrypted on your local machine using `electron-store`.

---

## Getting API Keys

| Service | Sign-up URL | Steps |
|---------|-------------|-------|
| VirusTotal | https://www.virustotal.com | Sign up → Profile → API Key |
| AbuseIPDB | https://www.abuseipdb.com | Sign up → Account → API |
| AlienVault OTX | https://otx.alienvault.com | Sign up → Settings → API Key |
| GreyNoise | https://viz.greynoise.io | Sign up → Account → API |
| URLScan.io | https://urlscan.io | Sign up → Settings → API Key |
| Hybrid Analysis | https://hybrid-analysis.com | Sign up → Profile → API Key |
| Maltiverse | https://maltiverse.com | Sign up → API Keys |
| SecurityTrails | https://securitytrails.com | Sign up → API → Generate |
| Censys | https://search.censys.io | Sign up → Account → API Access (get both ID and Secret) |
| HaveIBeenPwned | https://haveibeenpwned.com/API/Key | Purchase API key ($3.50/month) |
| Shodan | https://account.shodan.io | Purchase membership ($49/year) |

---

## Build Windows Installer

```bash
npm run build
```

Output in `dist/` folder after 3–5 minutes:
```
dist/
  Threat Intel Hub Setup 1.0.0.exe    ← standard installer
  Threat Intel Hub 1.0.0.exe          ← portable, no install needed
```

To add a custom app icon: replace `assets/icon.ico` with your own 256×256 `.ico` file before building.

---

## IOC Type Routing

| Type | Sources Queried |
|------|----------------|
| **IP** | VirusTotal · AbuseIPDB · GreyNoise · IPInfo · BGPView · Shodan · OTX · Censys |
| **Domain** | VirusTotal · OTX · URLScan · SecurityTrails · Censys |
| **Hash** | VirusTotal · Hybrid Analysis · Maltiverse |
| **URL** | VirusTotal · URLScan |
| **Email** | HaveIBeenPwned |

Type is auto-detected from the input. You can also force it from the dropdown.

---

## OSINT Tools Directory

The **OSINT Tools** tab has 37 tools across 8 categories, searchable by name or description:

| Category | Example Tools |
|----------|---------------|
| Infrastructure & Network | Shodan, Censys, GreyNoise, ZoomEye, BGPView, Netlas |
| Threat Intelligence | VirusTotal, MalwareBazaar, ThreatFox, URLhaus, OTX |
| Domain & DNS | SecurityTrails, DNSDumpster, ViewDNS, URLScan |
| Search & Frameworks | Maltego, SpiderFoot, OSINT Framework, IntelligenceX |
| Breach & Credentials | HIBP, DeHashed, LeakCheck, Snusbase |
| Social & Identity | Sherlock, Maigret, Social-Searcher, Namechk |
| Automated Recon | theHarvester, Amass, Subfinder, Nuclei |
| Dark Web | Ahmia, DarkSearch, IntelligenceX |

---

## Project Structure

```
threat-intel-hub/
├── main.js              ← Electron main process: API calls, PDF generation, IPC handlers
├── preload.js           ← Secure bridge between UI and Node.js (contextBridge)
├── package.json         ← Dependencies and electron-builder config
├── renderer/
│   ├── index.html       ← UI layout and all CSS
│   └── renderer.js      ← UI logic, card rendering, OSINT directory data
└── assets/
    └── icon.ico         ← App icon (replace with your own)
```

---

## Architecture

All API calls go through the Electron main process (Node.js) — no CORS, no proxy needed.

```
renderer (UI)  →  preload.js (IPC bridge)  →  main.js (Node.js)
                                                    ↓
                                            13 APIs, no CORS
                                            PDFKit report engine
                                            Encrypted key storage
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `npm install` fails | Run `npm install --legacy-peer-deps` |
| App window is blank | Check terminal for errors. Node.js must be v18+ |
| API returns HTTP 400/401 | Key is wrong, expired, or missing required subscription |
| Build fails (icon error) | Add `assets/icon.ico` or remove the `"icon"` line from `package.json` |
| Build is slow | Normal — first build downloads ~150MB Electron binaries |

---

## Contributing

PRs are welcome. Fork → clone → `npm install` → `npm start` to test changes live.

Ideas for contributions:
- Additional API sources (Recorded Future, Mandiant, Pulsedive)
- MITRE ATT&CK TTP mapping in PDF reports
- macOS / Linux packaging
- Dark web source integration

---

## License

MIT

---

## Disclaimer

For authorized security research and incident response only. Ensure your use complies with each API provider's terms of service. Do not investigate targets without proper authorization.
