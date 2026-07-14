# 🛡️ Threat Intel Hub

> Professional desktop threat intelligence platform for Windows. Queries multiple APIs in parallel, visualizes results with live threat scoring, and exports professional PDF reports — 100% local, no server required.

![Version](https://img.shields.io/badge/version-7.0-blue)
![Platform](https://img.shields.io/badge/platform-Windows-informational)
![Electron](https://img.shields.io/badge/Electron-28-47848F?logo=electron)
![License](https://img.shields.io/badge/license-MIT-green)

---

## 🆕 What's new in this release

- **4 new keyless OSINT sources** — crt.sh (certificate transparency → subdomain discovery), RDAP (registration data with a newly-registered-domain risk flag), Wayback Machine (historical snapshot footprint), and ransomware.live (leak-site victim check). All passive, none require an API key.
- **Select All in History** — one click selects every saved investigation so you can export a single combined PDF report.
- **MITRE ATT&CK download fix** — resolved a gzip decompression bug that broke STIX data downloads.
- **Security hardening** — locked down the local install IPC handler, added strict per-type IOC input validation, enabled the Electron sandbox, and added crash/renderer diagnostics.
- **`repair.bat`** — new one-click repair script for Electron install problems (missing `electron.exe`, npm cache issues, blocked binary downloads).

---

## ✨ Features

- **Multi-source API querying** — IP, domain, hash, URL, email IOCs
- **Free / keyless sources** — BGPView, IPInfo, Robtex, LeakCheck, Talos, crt.sh, RDAP, Wayback, ransomware.live all run with no API key
- **Passive OSINT recon** — certificate transparency, registration data, historical snapshots, and ransomware leak-site checks
- **Visual threat score** — donut chart, verdict badge, breakdown bars
- **File analysis** — SHA-256 hashed locally, only the hash is sent to APIs
- **PDF reports** — dark-themed, multi-page, color-coded export; combined report across multiple investigations
- **8 intelligence modules** — Threat Intel, Infrastructure, DNS, Breach, Search/Dark Web, Social, Recon, Dark Web
- **CLI tool auto-installer** — one-click install for Sherlock, Maigret, theHarvester
- **Light & Dark theme** — persists across sessions
- **Local API key storage** — keys are stored on your machine via `electron-store` and are never sent anywhere except the API they belong to

---

## 🚀 Installation

### Option A — Easiest: Double-click Setup File

1. Extract the zip
2. Open the `threat-intel-hub` folder
3. Double-click **`setup.bat`** (or `setup.ps1` for PowerShell)
4. It checks for Node.js, installs dependencies, verifies the app files, and launches the app

If Node.js is missing, `setup.ps1` downloads and installs it silently.
If dependencies fail to install (missing `electron.exe`, npm errors), run **`repair.bat`** — it cleans and reinstalls, and prints the exact error on screen.

---

### Option B — Manual (3 commands)

**Step 1 — Install Node.js** (if you don't have it)

Download from **[nodejs.org](https://nodejs.org)** → choose **LTS** → install → restart terminal.

Verify:
```
node --version   # must show v18 or higher
```

**Step 2 — Install dependencies** (first time only)

Open Command Prompt in the `threat-intel-hub` folder:
```
npm install
```
Takes 2–3 minutes. Downloads ~300MB. Only needed once.

**Step 3 — Launch**
```
npm start
```

---

## 🔧 How to Open CMD in the App Folder

1. Open **File Explorer** and navigate to the `threat-intel-hub` folder
2. Click the **address bar** at the top
3. Type `cmd` and press **Enter**
4. Command Prompt opens in the correct folder

---

## 🔑 Adding API Keys

1. Launch the app
2. Click **⚙ Settings** (top-right)
3. Select the module tab (Threat Intel, Infrastructure, etc.)
4. Paste your API keys
5. Click **💾 Save All API Keys**

Keys are stored **locally** on your machine using `electron-store`, in your user profile directory. They are only ever sent to the specific API each key belongs to. Note: the local store uses a fixed application key, so treat it as obfuscation rather than strong encryption — protect your OS user account accordingly.

### Where to get API keys

| Service | URL | Free Tier |
|---------|-----|-----------|
| VirusTotal | virustotal.com → Profile → API Key | 500 req/day |
| AbuseIPDB | abuseipdb.com → Account → API | 1,000 req/day |
| AlienVault OTX | otx.alienvault.com → Settings | Free forever |
| Hybrid Analysis | hybrid-analysis.com → Profile | Free |
| Maltiverse | maltiverse.com → API Keys | Free |
| URLScan.io | urlscan.io → Settings → API | Free |
| GreyNoise | viz.greynoise.io → Account | 1,000 req/day |
| Censys | search.censys.io → Account → API | Free (ID + Secret) |
| ZoomEye | zoomeye.hk → Account | Free |
| Netlas | app.netlas.io → Profile | Freemium |
| SecurityTrails | securitytrails.com → API | 50 req/month |
| ViewDNS | viewdns.info → API | Freemium |
| HaveIBeenPwned | haveibeenpwned.com/API/Key | $3.50/month |
| DeHashed | dehashed.com → Account → API | Paid |
| Snusbase | snusbase.com → Account | Paid |
| IntelligenceX | intelx.io → Account → API | Freemium |
| Social-Searcher | social-searcher.com → API | Freemium |
| Shodan | account.shodan.io | $49/year |

---

## 📦 Build a Windows Installer (.exe)

This creates a proper Windows installer and portable executable.

**Step 1 — Make sure you have dependencies installed:**
```
npm install
```

**Step 2 — Add an app icon (optional but recommended)**

Place a 256×256 `.ico` file at:
```
assets/icon.ico
```
If you skip this, the build still works with the default Electron icon.

**Step 3 — Build:**
```
npm run build
```

First build takes **3–5 minutes** (downloads Electron binaries ~150MB).

**Output in the `dist/` folder:**
```
dist/
  Threat Intel Hub Setup 7.0.0.exe    ← Windows installer
  Threat Intel Hub 7.0.0.exe          ← Portable (no install needed)
```

**To build only the portable version (faster):**
```
npm run build:portable
```

---

## 📁 Project Structure

```
threat-intel-hub/
├── main.js              ← Electron main process: all API calls, PDF generation, IPC
├── preload.js           ← Secure IPC bridge (contextBridge)
├── package.json         ← Dependencies + electron-builder config
├── setup.bat            ← Windows setup script (node check + npm install + file check + launch)
├── setup.ps1            ← PowerShell setup (auto-downloads Node.js if missing)
├── repair.bat           ← Repairs broken Electron installs; prints errors on screen
├── renderer/
│   ├── index.html       ← UI layout, CSS, all styles
│   └── renderer.js      ← UI logic, navigation, API routing
├── assets/
│   └── icon.ico         ← App icon (replace with your own 256×256)
�