const { app, BrowserWindow, ipcMain, dialog, shell, Menu } = require('electron');
const path = require('path');
let Store, store;
const fallbackPath = require('path').join(require('os').homedir(), '.tih-data.json');

function readFallback() {
  try { return JSON.parse(require('fs').readFileSync(fallbackPath, 'utf8')); } catch(e) { return {}; }
}
function writeFallback(data) {
  try { require('fs').writeFileSync(fallbackPath, JSON.stringify(data, null, 2), 'utf8'); } catch(e) {}
}

try {
  Store = require('electron-store');
  store = new Store({ encryptionKey: 'tih-secure-key-2024' });
} catch(e) {
  // electron-store not installed — use JSON file fallback so keys persist across restarts
  store = {
    get: (k, def) => { const d = readFallback(); return d[k] !== undefined ? d[k] : def; },
    set: (k, v)   => { const d = readFallback(); d[k] = v; writeFallback(d); },
  };
}

let PDFDocument;
try { PDFDocument = require('pdfkit'); } catch(e) { PDFDocument = null; }
const fs = require('fs');
let mainWindow;

// ══ DIAGNOSTICS — logs startup/crash detail to ~/tih-debug.log for bug reports ══
const DEBUG_LOG = path.join(require('os').homedir(), 'tih-debug.log');
function dlog(msg) {
  const line = new Date().toISOString() + '  ' + msg;
  console.log(line);
  try { fs.appendFileSync(DEBUG_LOG, line + '\n'); } catch (e) {}
}
process.on('uncaughtException', err => {
  dlog('MAIN PROCESS CRASH: ' + (err && err.stack || err));
  try { dialog.showErrorBox('Threat Intel Hub — Main Process Error', String(err && err.stack || err)); } catch (e) {}
});
process.on('unhandledRejection', err => {
  dlog('UNHANDLED REJECTION: ' + (err && err.stack || err));
});
dlog('=== main.js loaded, electron ' + process.versions.electron + ', node ' + process.versions.node + ' ===');
// ══ END DEBUG BLOCK (part 1) ══

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1600, height: 960, minWidth: 1200, minHeight: 750,
    webPreferences: { preload: path.join(__dirname, 'preload.js'), nodeIntegration: false, contextIsolation: true, sandbox: true },
    title: 'Threat Intel Hub', backgroundColor: '#060914', show: false, autoHideMenuBar: true,
  });
  // ══ DEBUG BLOCK (part 2) ══
  const indexPath = path.join(__dirname, 'renderer', 'index.html');
  if (!fs.existsSync(indexPath)) {
    dlog('FATAL: renderer/index.html NOT FOUND at ' + indexPath);
    dialog.showErrorBox('Missing file', 'Not found: ' + indexPath + '\nThis is why the window is blank.');
  }
  const rendererJs = path.join(__dirname, 'renderer', 'renderer.js');
  dlog('renderer.js exists: ' + fs.existsSync(rendererJs));
  mainWindow.webContents.on('did-fail-load', (_, code, desc, failedUrl) =>
    dlog(`did-fail-load code=${code} desc=${desc} url=${failedUrl}`));
  mainWindow.webContents.on('render-process-gone', (_, details) =>
    dlog('RENDER PROCESS GONE: ' + JSON.stringify(details)));
  mainWindow.webContents.on('preload-error', (_, preloadPath, err) =>
    dlog('PRELOAD ERROR in ' + preloadPath + ': ' + (err && err.message)));
  mainWindow.webContents.on('console-message', (_, level, message, line, sourceId) =>
    dlog(`renderer console [${level}] ${sourceId}:${line}  ${message}`));
  mainWindow.webContents.once('dom-ready', () => dlog('dom-ready fired — HTML parsed OK'));
  setTimeout(() => {
    if (mainWindow && !mainWindow.isDestroyed() && !mainWindow.isVisible()) {
      dlog('ready-to-show never fired after 6s — forcing window.show()');
      mainWindow.show();
    }
  }, 6000);
  // ══ END DEBUG BLOCK ══
  mainWindow.loadFile(indexPath);
  mainWindow.once('ready-to-show', () => { dlog('ready-to-show fired'); mainWindow.show(); });
  Menu.setApplicationMenu(null);
}

app.whenReady().then(() => { dlog('app ready — creating window'); createWindow(); app.on('activate', () => { if (!BrowserWindow.getAllWindows().length) createWindow(); }); });
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });

ipcMain.handle('open-external', (_, url) => { if (url?.startsWith('https://')) shell.openExternal(url); });

// ── Zoom ────────────────────────────────────────────────────────────────────
ipcMain.handle('zoom-in',    () => { if(mainWindow) { const z=Math.min(mainWindow.webContents.getZoomFactor()+0.1,2.5); mainWindow.webContents.setZoomFactor(z); return Math.round(z*100); } });
ipcMain.handle('zoom-out',   () => { if(mainWindow) { const z=Math.max(mainWindow.webContents.getZoomFactor()-0.1,0.5); mainWindow.webContents.setZoomFactor(z); return Math.round(z*100); } });
ipcMain.handle('zoom-reset', () => { if(mainWindow) { mainWindow.webContents.setZoomFactor(1); return 100; } });
ipcMain.handle('get-zoom',   () => { if(mainWindow) return Math.round(mainWindow.webContents.getZoomFactor()*100); return 100; });


// ─── IPC: Setup Check ─────────────────────────────────────────────────────
// SECURITY: this handler used to exec() whatever string the renderer sent.
// A compromised renderer (XSS via hostile threat-intel data) = full RCE.
// Now only "npm install/i" of known packages is permitted.
const ALLOWED_INSTALL_PKGS = new Set(['electron-store', 'pdfkit', '--save', '--save-dev']);
ipcMain.handle('run-install', async (_, { command }) => {
  const cmd = String(command || '').trim().replace(/\s+/g, ' ');
  const m = cmd.match(/^npm (?:install|i)((?: [A-Za-z0-9@^~._-]+)*)$/);
  const args = m ? m[1].trim().split(' ').filter(Boolean) : null;
  const allowed = !!m && args.every(a => ALLOWED_INSTALL_PKGS.has(a.replace(/@[\d^~.x*-]+$/, '')));
  if (!allowed) {
    return { success: false, output: 'Blocked: only "npm install electron-store pdfkit" may be run from the app.' };
  }
  const { exec } = require('child_process');
  return new Promise(resolve => {
    exec(cmd, { timeout: 120000, cwd: app.getAppPath() }, (error, stdout, stderr) => {
      resolve({ success: !error, output: stdout || stderr || error?.message || 'Done' });
    });
  });
});

ipcMain.handle('check-setup', () => {
  const checks = { nodeVersion: process.version, electronVersion: process.versions.electron };
  const pkgs = ['electron-store', 'pdfkit'];
  pkgs.forEach(pkg => {
    try { require(pkg); checks[pkg] = true; }
    catch(e) { checks[pkg] = false; }
  });
  checks.allGood = pkgs.every(p => checks[p]);
  return checks;
});
ipcMain.handle('get-api-keys', () => store.get('apiKeys', {}));
ipcMain.handle('save-api-keys', (_, keys) => { store.set('apiKeys', keys); return true; });

// ─── IOC INPUT VALIDATION ───────────────────────────────────────────────
// Many query functions interpolate the IOC straight into API URLs. Without
// validation, a crafted "IOC" can inject path segments or query params (SSRF-
// style) into requests carrying your API keys. Strict for typed IOCs; unknown
// types (usernames, free text) only get control-character screening because
// their call sites already encodeURIComponent.
const IOC_PATTERNS = {
  ip:     /^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$|^[0-9a-fA-F:]{2,45}$/,
  hash:   /^([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$/,
  domain: /^(?=.{1,253}$)([a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/,
  email:  /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
};
function validateIoc(ioc, type) {
  ioc = String(ioc == null ? '' : ioc).trim();
  if (!ioc || ioc.length > 2048) return null;
  if (/[\x00-\x1f\x7f]/.test(ioc)) return null;
  if (type === 'url') {
    try { const u = new URL(ioc); if (u.protocol !== 'http:' && u.protocol !== 'https:') return null; } catch (e) { return null; }
    return ioc;
  }
  const re = IOC_PATTERNS[type];
  if (re) return re.test(ioc) ? ioc : null;
  return ioc;
}

// ─── UNIFIED QUERY HANDLER ──────────────────────────────────────────────
ipcMain.handle('query-api', async (_, { source, ioc, type }) => {
  const cleaned = validateIoc(ioc, type);
  if (cleaned === null) {
    return { verdict: 'error', source, data: [['Error', `Invalid ${type || 'input'} format — query blocked`, 'danger']] };
  }
  ioc = cleaned;
  const k = store.get('apiKeys', {});
  try {
    switch (source) {
      // ── Threat Intelligence ──────────────────────────────────────────────
      case 'virustotal':      return await queryVirusTotal(ioc, type, k.virustotal);
      case 'abuseipdb':      return await queryAbuseIPDB(ioc, k.abuseipdb);
      case 'talos':          return await queryTalos(ioc);
      case 'shodan':         return await queryShodan(ioc, k.shodan);
      case 'otx':            return await queryOTX(ioc, type, k.otx);
      case 'urlscan':        return await queryURLScan(ioc, type, k.urlscan);
      case 'hybrid':         return await queryHybridAnalysis(ioc, k.hybrid);
      case 'maltiverse':     return await queryMaltiverse(ioc, k.maltiverse);
      // ── Infrastructure & Network ─────────────────────────────────────────
      case 'greynoise':      return await queryGreyNoise(ioc, k.greynoise);
      case 'censys':         return await queryCensys(ioc, type, k.censys_id, k.censys_secret);
      case 'zoomeye':        return await queryZoomEye(ioc, k.zoomeye);
      case 'netlas':         return await queryNetlas(ioc, k.netlas);
      case 'bgpview':        return await queryBGPView(ioc);
      case 'ipinfo':         return await queryIPInfo(ioc);
      // ── Domain & DNS ─────────────────────────────────────────────────────
      case 'securitytrails': return await querySecurityTrails(ioc, type, k.securitytrails);
      case 'robtex':         return await queryRobtex(ioc, type);
      case 'viewdns':        return await queryViewDNS(ioc, type, k.viewdns);
      // ── OSINT / Passive Recon (keyless) ───────────────────────────
      case 'crtsh':          return await queryCrtSh(ioc, type);
      case 'rdap':           return await queryRDAP(ioc, type);
      case 'wayback':        return await queryWayback(ioc, type);
      case 'ransomware':     return await queryRansomware(ioc);
      // ── Breach & Credentials ─────────────────────────────────────────────
      case 'hibp':           return await queryHIBP(ioc, k.hibp);
      case 'leakcheck':      return await queryLeakCheck(ioc);
      case 'dehashed':       return await queryDeHashed(ioc, k.dehashed_key, k.dehashed_user);
      case 'snusbase':       return await querySnusbase(ioc, k.snusbase);
      // ── Search / Dark Web ────────────────────────────────────────────────
      case 'intelligencex':  return await queryIntelligenceX(ioc, k.intelligencex);
      case 'darksearch':     return await queryDarkSearch(ioc);
      // ── Social & Identity ────────────────────────────────────────────────
      case 'socialsearcher': return await querySocialSearcher(ioc, k.socialsearcher);
      default: throw new Error('Unknown source: ' + source);
    }
  } catch (err) {
    return { verdict: 'error', source, data: [['Error', err.message, 'danger']] };
  }
});

// ─── COMBINED REPORT ────────────────────────────────────────────────────────
ipcMain.handle('generate-combined-report', async (_, { entries }) => {
  if (!PDFDocument) return { success:false, error:'pdfkit not installed' };
  const { filePath, canceled } = await dialog.showSaveDialog(mainWindow, {
    title: 'Save Combined Intelligence Report',
    defaultPath: path.join(app.getPath('documents'), `ThreatIntel_Combined_${Date.now()}.pdf`),
    filters: [{ name: 'PDF Files', extensions: ['pdf'] }],
  });
  if (canceled || !filePath) return { success: false };

  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({ size: 'A4', margin: 0, bufferPages: true });
      const stream = fs.createWriteStream(filePath);
      doc.pipe(stream);
      const W = doc.page.width, M = 50;

      // ── COVER ────────────────────────────────────────────────────────────
      doc.rect(0,0,W,120).fill('#060914');
      doc.rect(0,118,W,2).fill('#00f5ff');
      doc.fillColor('#00f5ff').font('Helvetica-Bold').fontSize(22).text('COMBINED THREAT INTELLIGENCE REPORT', M, 30);
      doc.fillColor('#94a3b8').font('Helvetica').fontSize(10).text(`${entries.length} indicators analyzed`, M, 60);
      doc.fillColor('#475569').fontSize(8.5)
        .text(`Generated: ${new Date().toUTCString()}`, M, 78)
        .text(`Report ID: COMB-${Date.now()}`, M, 91);

      // ── SUMMARY TABLE ─────────────────────────────────────────────────────
      let y = 140;
      doc.rect(M,y,W-M*2,24).fill('#0f172a');
      doc.fillColor('#00f5ff').font('Helvetica-Bold').fontSize(10).text('INDICATORS SUMMARY', M+12, y+8);
      y += 30;

      const colW = [(W-M*2)*0.45, (W-M*2)*0.12, (W-M*2)*0.15, (W-M*2)*0.14, (W-M*2)*0.14];
      const headers = ['Indicator', 'Type', 'Verdict', 'Score', 'Sources'];
      doc.rect(M,y,W-M*2,18).fill('#111827');
      let cx = M;
      headers.forEach((h,i) => {
        doc.fillColor('#64748b').font('Helvetica-Bold').fontSize(8).text(h, cx+6, y+5, {width:colW[i]});
        cx += colW[i];
      });
      y += 18;

      entries.forEach((e, idx) => {
        const rowH = 20;
        if (y + rowH > 780) {
          doc.addPage();
          doc.rect(0,0,W,30).fill('#060914');
          doc.fillColor('#00f5ff').font('Helvetica-Bold').fontSize(9).text('COMBINED REPORT — CONTINUED', M, 10);
          y = 42;
        }
        const vColor = e.verdict==='malicious'?'#ef4444':e.verdict==='suspicious'?'#f97316':'#10b981';
        doc.rect(M,y,W-M*2,rowH).fill(idx%2===0?'#111827':'#0d1424');
        let rx = M;
        const vals = [e.ioc.slice(0,50)+(e.ioc.length>50?'…':''), e.type.toUpperCase(), e.verdict.toUpperCase(), String(e.score)+'/100', String(e.sources)];
        vals.forEach((v,i) => {
          const col = i===2 ? vColor : '#e2e8f0';
          doc.fillColor(col).font(i===2?'Helvetica-Bold':'Helvetica').fontSize(8).text(v, rx+6, y+6, {width:colW[i]-8});
          rx += colW[i];
        });
        y += rowH;
      });

      y += 16;

      // ── BAR CHART (SVG-style in PDF) ─────────────────────────────────────
      if (y + 140 > 780) { doc.addPage(); y = 40; }
      doc.rect(M,y,W-M*2,24).fill('#0f172a');
      doc.fillColor('#00f5ff').font('Helvetica-Bold').fontSize(10).text('THREAT SCORE COMPARISON', M+12, y+8);
      y += 30;

      const chartW = W-M*2, chartH = 100, barW2 = Math.min(chartW/entries.length - 6, 45);
      const spacing2 = (chartW - barW2*entries.length)/(entries.length+1);

      // Chart background
      doc.rect(M,y,chartW,chartH).fill('#0d1424');

      entries.forEach((e, i) => {
        const vColor2 = e.verdict==='malicious'?'#ef4444':e.verdict==='suspicious'?'#f97316':'#10b981';
        const bx = M + spacing2*(i+1) + barW2*i;
        const bh = (e.score/100)*chartH*0.9;
        const by = y + chartH - bh - 5;
        doc.rect(bx, by, barW2, bh).fill(vColor2).fillOpacity(0.85);
        doc.fillColor(vColor2).font('Helvetica-Bold').fontSize(7).text(String(e.score), bx, by-10, {width:barW2, align:'center'});
        const label = (e.ioc.slice(0,10)+(e.ioc.length>10?'…':'')).toUpperCase();
        doc.fillColor('#64748b').font('Helvetica').fontSize(6).text(label, bx-4, y+chartH+3, {width:barW2+8, align:'center'});
      });
      y += chartH + 22;

      // ── PER-INDICATOR DETAILS ─────────────────────────────────────────────
      doc.rect(M,y,W-M*2,24).fill('#0f172a');
      doc.fillColor('#00f5ff').font('Helvetica-Bold').fontSize(10).text('DETAILED FINDINGS', M+12, y+8);
      y += 30;

      for (const e of entries) {
        if (y + 60 > 770) { doc.addPage(); y = 40; }
        const vColor3 = e.verdict==='malicious'?'#ef4444':e.verdict==='suspicious'?'#f97316':'#10b981';
        doc.rect(M,y,W-M*2,22).fill('#111827');
        doc.rect(M,y,3,22).fill(vColor3);
        doc.fillColor('#e2e8f0').font('Helvetica-Bold').fontSize(9).text(e.ioc, M+10, y+7, {width:W-M*2-120});
        doc.fillColor(vColor3).font('Helvetica-Bold').fontSize(8).text(e.verdict.toUpperCase()+' · '+e.score+'/100 · '+e.sources+' sources', W-M-120, y+7, {width:115, align:'right'});
        y += 24;

        // Sources row
        const dt = new Date(e.timestamp).toLocaleDateString();
        doc.fillColor('#475569').font('Helvetica').fontSize(7.5)
          .text(`Type: ${e.type.toUpperCase()}  ·  Analyzed: ${dt}`, M+10, y+4);
        y += 16;
      }

      // ── FOOTER ────────────────────────────────────────────────────────────
      const pageCount = doc.bufferedPageRange().count;
      for (let i=0; i<pageCount; i++) {
        doc.switchToPage(i);
        const pH = doc.page.height;
        doc.rect(0,pH-28,W,28).fill('#060914');
        doc.rect(0,pH-28,W,1).fill('#1e2340');
        doc.fillColor('#334155').font('Helvetica').fontSize(7.5)
          .text('Threat Intel Hub  —  Combined Report  —  CONFIDENTIAL', M, pH-18)
          .text(`Page ${i+1} of ${pageCount}`, 0, pH-18, {align:'right',width:W-M});
      }

      doc.end();
      stream.on('finish', () => { shell.openPath(filePath); resolve({success:true,filePath}); });
      stream.on('error',  err  => resolve({success:false,error:err.message}));
    } catch(err) { resolve({success:false,error:err.message}); }
  });
});


// ─── MITRE ATT&CK DATA ──────────────────────────────────────────────────────
const ATTACK_STIX_URL = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json';
const ATTACK_VERSION_URL = 'https://api.github.com/repos/mitre/cti/releases/latest';
const ATTACK_CACHE_PATH = path.join(app.getPath('userData'), 'attack-cache.json');

// Robust HTTPS GET for the ATT&CK endpoints.
// GZIP FIX: we no longer send 'Accept-Encoding: gzip'. Node's https module does
// NOT auto-decompress, so the old code buffered gzip bytes and JSON.parse blew up.
// Defensively, if a server compresses anyway, we decompress via zlib.
// Also: follows redirects, rejects on non-200 (a GitHub error page is no longer
// parsed as JSON), and enforces an idle timeout.
function httpsGetText(url, opts) {
  opts = opts || {};
  const timeout = opts.timeout || 30000;
  const onProgress = opts.onProgress || null;
  const redirects = opts.redirects === undefined ? 5 : opts.redirects;
  const https = require('https');
  const zlib = require('zlib');
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { 'User-Agent': 'ThreatIntelHub/7', 'Accept': 'application/json' } }, res => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location && redirects > 0) {
        res.resume();
        return resolve(httpsGetText(new URL(res.headers.location, url).toString(), { timeout, onProgress, redirects: redirects - 1 }));
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode} from ${new URL(url).hostname}`));
      }
      const total = parseInt(res.headers['content-length'] || '0', 10);
      let downloaded = 0;
      const chunks = [];
      res.on('data', chunk => {
        chunks.push(chunk);
        downloaded += chunk.length;
        if (onProgress) onProgress(downloaded, total);
      });
      res.on('end', () => {
        let buf = Buffer.concat(chunks);
        const enc = (res.headers['content-encoding'] || '').toLowerCase();
        try {
          if (enc === 'gzip') buf = zlib.gunzipSync(buf);
          else if (enc === 'deflate') buf = zlib.inflateSync(buf);
          else if (enc === 'br') buf = zlib.brotliDecompressSync(buf);
        } catch (e) { return reject(new Error('Decompression failed: ' + e.message)); }
        resolve(buf.toString('utf8'));
      });
      res.on('error', reject);
    });
    req.on('error', reject);
    req.setTimeout(timeout, () => req.destroy(new Error('Request timed out (' + Math.round(timeout / 1000) + 's idle)')));
  });
}

function parseStix(objects) {
  const tactics = [], techniques = [], mitigations = {}, relationships = [];
  const tacticMap = {}; // shortname -> id+name

  for (const obj of objects) {
    if (obj.type === 'x-mitre-tactic') {
      const ext = obj.external_references?.find(r => r.source_name === 'mitre-attack');
      const t = {
        id:    ext?.external_id || '',
        name:  obj.name,
        desc:  obj.description || '',
        short: obj.x_mitre_shortname || '',
      };
      tactics.push(t);
      tacticMap[t.short] = t.id;
    }
    if (obj.type === 'attack-pattern' && !obj.revoked && !obj.x_mitre_deprecated) {
      const ext  = obj.external_references?.find(r => r.source_name === 'mitre-attack');
      const url  = ext?.url || '';
      const tid  = ext?.external_id || '';
      const tacticIds = (obj.kill_chain_phases || [])
        .filter(p => p.kill_chain_name === 'mitre-attack')
        .map(p => tacticMap[p.phase_name] || p.phase_name);
      techniques.push({
        stixId:       obj.id,
        id:           tid,
        name:         obj.name,
        desc:         obj.description || '',
        url,
        platforms:    obj.x_mitre_platforms || [],
        permissions:  obj.x_mitre_permissions_required || [],
        detection:    obj.x_mitre_detection || '',
        isSub:        obj.x_mitre_is_subtechnique || false,
        tactics:      tacticIds,
        version:      obj.x_mitre_version || '1.0',
        created:      obj.created || '',
        modified:     obj.modified || '',
        datasources:  obj.x_mitre_data_sources || [],
        defbypass:    obj.x_mitre_defense_bypassed || [],
      });
    }
    if (obj.type === 'course-of-action') {
      const ext = obj.external_references?.find(r => r.source_name === 'mitre-attack');
      if (ext?.external_id) {
        mitigations[obj.id] = { id: ext.external_id, name: obj.name, desc: obj.description || '' };
      }
    }
    if (obj.type === 'relationship' &&
        (obj.relationship_type === 'mitigates' || obj.relationship_type === 'subtechnique-of')) {
      relationships.push({ type: obj.relationship_type, src: obj.source_ref, tgt: obj.target_ref });
    }
  }

  // Map mitigations to techniques
  const mitigationsByTech = {};
  for (const rel of relationships) {
    if (rel.type === 'mitigates' && mitigations[rel.src]) {
      if (!mitigationsByTech[rel.tgt]) mitigationsByTech[rel.tgt] = [];
      mitigationsByTech[rel.tgt].push(mitigations[rel.src]);
    }
  }
  // Map subtechniques to parent
  const subMap = {};
  for (const rel of relationships) {
    if (rel.type === 'subtechnique-of') {
      if (!subMap[rel.tgt]) subMap[rel.tgt] = [];
      subMap[rel.tgt].push(rel.src);
    }
  }

  tactics.sort((a, b) => a.id.localeCompare(b.id));
  return { tactics, techniques, mitigationsByTech, subMap, parsedAt: new Date().toISOString() };
}

ipcMain.handle('attack-get-cache', () => {
  try {
    if (fs.existsSync(ATTACK_CACHE_PATH)) {
      const cache = JSON.parse(fs.readFileSync(ATTACK_CACHE_PATH, 'utf8'));
      return { ok: true, data: cache };
    }
    return { ok: false };
  } catch(e) { return { ok: false, error: e.message }; }
});

ipcMain.handle('attack-check-version', async () => {
  try {
    const body = await httpsGetText(ATTACK_VERSION_URL, { timeout: 8000 });
    const release = JSON.parse(body);
    // Also get current cached version
    let cachedVersion = null;
    if (fs.existsSync(ATTACK_CACHE_PATH)) {
      const cache = JSON.parse(fs.readFileSync(ATTACK_CACHE_PATH, 'utf8'));
      cachedVersion = cache.releaseTag;
    }
    return { ok: true, latestTag: release.tag_name, latestDate: release.published_at, cachedVersion, hasUpdate: release.tag_name !== cachedVersion };
  } catch(e) { return { ok: false, error: e.message }; }
});

ipcMain.handle('attack-download', async (event) => {
  const send = (msg) => {
    try { if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('attack-progress', msg); } catch(e) {}
  };
  try {
    // First get latest release tag
    send({ step: 'check', msg: 'Checking latest ATT&CK version…' });
    let releaseTag = 'unknown';
    try {
      const tagBody = await httpsGetText(ATTACK_VERSION_URL, { timeout: 8000 });
      releaseTag = JSON.parse(tagBody).tag_name || 'unknown';
      send({ step: 'check', msg: `Latest version: ${releaseTag}` });
    } catch(e) { send({ step: 'check', msg: 'Could not check version, downloading latest…' }); }

    // Download the STIX JSON
    send({ step: 'download', msg: 'Downloading MITRE ATT&CK STIX data (~50MB)…', pct: 0 });
    let lastPct = -1;
    const rawBody = await httpsGetText(ATTACK_STIX_URL, {
      timeout: 60000,
      onProgress: (downloaded, total) => {
        if (total > 0) {
          const pct = Math.round(downloaded / total * 100);
          if (pct !== lastPct) { lastPct = pct; send({ step: 'download', msg: `Downloading… ${(downloaded/1024/1024).toFixed(1)} MB / ${(total/1024/1024).toFixed(1)} MB`, pct }); }
        } else {
          send({ step: 'download', msg: `Downloading… ${(downloaded/1024/1024).toFixed(1)} MB`, pct: 0 });
        }
      },
    });

    send({ step: 'parse', msg: 'Parsing ATT&CK objects…', pct: 0 });
    const stix = JSON.parse(rawBody);
    const objects = stix.objects || [];
    send({ step: 'parse', msg: `Processing ${objects.length.toLocaleString()} STIX objects…`, pct: 30 });

    const parsed = parseStix(objects);
    parsed.releaseTag = releaseTag;
    parsed.downloadedAt = new Date().toISOString();

    send({ step: 'save', msg: `Saving cache — ${parsed.techniques.length} techniques, ${parsed.tactics.length} tactics…` });
    fs.writeFileSync(ATTACK_CACHE_PATH, JSON.stringify(parsed), 'utf8');

    send({ step: 'done', msg: `Done! ${parsed.techniques.length} techniques across ${parsed.tactics.length} tactics.` });
    return { ok: true, tactics: parsed.tactics.length, techniques: parsed.techniques.length, releaseTag };
  } catch(e) {
    send({ step: 'error', msg: 'Error: ' + e.message });
    return { ok: false, error: e.message };
  }
});

// ─── PDF REPORT ─────────────────────────────────────────────────────────────
ipcMain.handle('generate-report', async (_, { ioc, results, iocType }) => {
  if (!PDFDocument) return { success:false, error:'pdfkit not installed — run npm install' };
  const { filePath, canceled } = await dialog.showSaveDialog(mainWindow, {
    title: 'Save Threat Intelligence Report',
    defaultPath: path.join(app.getPath('documents'), `ThreatIntel_${ioc.substring(0,20).replace(/[^a-zA-Z0-9]/g,'_')}_${Date.now()}.pdf`),
    filters: [{ name: 'PDF Files', extensions: ['pdf'] }],
  });
  if (canceled || !filePath) return { success: false };
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({ size: 'A4', margin: 0, bufferPages: true });
      const stream = fs.createWriteStream(filePath);
      doc.pipe(stream);
      const W = doc.page.width, M = 50;
      // ── HEADER BAR ──────────────────────────────────────────────────────
      doc.rect(0,0,W,100).fill('#060914');
      doc.rect(0,98,W,3).fill('#00f5ff');
      doc.fillColor('#00f5ff').font('Helvetica-Bold').fontSize(20)
        .text('THREAT INTELLIGENCE REPORT', M, 26);
      doc.fillColor('#94a3b8').font('Helvetica').fontSize(9)
        .text('Threat Intel Hub v7  —  Multi-Source Intelligence Platform', M, 52);
      doc.fillColor('#475569').fontSize(8)
        .text(`Generated: ${new Date().toUTCString()}`, M, 66)
        .text(`Report ID: TI-${Date.now()}`, W-M-160, 66);

      // ── IOC BOX ─────────────────────────────────────────────────────────
      const badgeColors = { ip:'#0ea5e9', domain:'#8b5cf6', hash:'#f97316', url:'#10b981', email:'#ec4899', unknown:'#64748b' };
      const iocBadgeColor = badgeColors[iocType]||'#64748b';
      doc.rect(M, 112, W-M*2, 48).fill('#0f172a');
      doc.rect(M, 112, 4, 48).fill(iocBadgeColor);
      doc.fillColor('#64748b').font('Helvetica-Bold').fontSize(7.5)
        .text('INDICATOR OF COMPROMISE', M+14, 120);
      // IOC value — handle long hashes by wrapping
      const iocDisplay = ioc.length > 60 ? ioc.slice(0,60)+'…' : ioc;
      doc.fillColor('#e2e8f0').font('Helvetica-Bold').fontSize(11)
        .text(iocDisplay, M+14, 132, {width: W-M*2-100, lineBreak: false});
      // Type badge
      doc.roundedRect(W-M-58, 122, 52, 18, 4).fill(iocBadgeColor);
      doc.fillColor('white').font('Helvetica-Bold').fontSize(8)
        .text((iocType||'IOC').toUpperCase(), W-M-54, 128);

      // ── VERDICT + STATS ROW ──────────────────────────────────────────────
      const entries = Object.values(results);
      const total      = entries.length;
      const malicious  = entries.filter(r=>r.verdict==='malicious').length;
      const suspicious = entries.filter(r=>r.verdict==='suspicious').length;
      const clean      = entries.filter(r=>r.verdict==='clean').length;
      const errored    = entries.filter(r=>r.verdict==='error').length;
      const scored     = total - errored;
      const threatScore = scored > 0 ? Math.round((malicious + suspicious*0.5)/scored*100) : 0;

      let ov='CLEAN', vc='#10b981', vbg='#052e16';
      if (malicious>0)  { ov='MALICIOUS';  vc='#ef4444'; vbg='#1c0707'; }
      else if(suspicious>0) { ov='SUSPICIOUS'; vc='#f97316'; vbg='#1c0e04'; }

      // Verdict card
      doc.rect(M, 172, 140, 72).fill(vbg);
      doc.rect(M, 172, 140, 4).fill(vc);
      doc.fillColor('#94a3b8').font('Helvetica-Bold').fontSize(7).text('VERDICT', M+10, 183);
      doc.fillColor(vc).font('Helvetica-Bold').fontSize(20).text(ov, M+10, 196);
      doc.fillColor('#64748b').font('Helvetica').fontSize(8).text(`Score: ${threatScore}/100`, M+10, 228);

      // Stat cards
      const stats = [
        {l:'SOURCES',   v:String(total),     c:'#94a3b8'},
        {l:'MALICIOUS', v:String(malicious),  c:'#ef4444'},
        {l:'SUSPICIOUS',v:String(suspicious), c:'#f97316'},
        {l:'CLEAN',     v:String(clean),      c:'#10b981'},
      ];
      const sBoxW = (W-M*2-140-8)/4 - 4;
      stats.forEach((s,i) => {
        const bx = M+140+8+i*(sBoxW+4);
        doc.rect(bx,172,sBoxW,72).fill('#0f172a');
        doc.rect(bx,172,sBoxW,4).fill(s.c);
        doc.fillColor(s.c).font('Helvetica-Bold').fontSize(28).text(s.v, bx+8, 194);
        doc.fillColor('#64748b').font('Helvetica-Bold').fontSize(7).text(s.l, bx+8, 230);
      });

      // ── EXECUTIVE SUMMARY ────────────────────────────────────────────────
      let y = 260;
      doc.rect(M,y,W-M*2,20).fill('#111827');
      doc.rect(M,y,4,20).fill('#00f5ff');
      doc.fillColor('#00f5ff').font('Helvetica-Bold').fontSize(9).text('EXECUTIVE SUMMARY', M+12, y+6);
      y += 22;

      const iocQ = '"' + iocDisplay + '"';
      const summaryText = ov === 'MALICIOUS'
        ? 'The indicator ' + iocQ + ' identified as MALICIOUS by ' + malicious + ' of ' + total + ' sources. Threat score: ' + threatScore + '/100. Immediate containment recommended.'
        : ov === 'SUSPICIOUS'
        ? 'The indicator ' + iocQ + ' raised flags in ' + suspicious + ' of ' + total + ' sources. Threat score: ' + threatScore + '/100. Further investigation advised.'
        : 'The indicator ' + iocQ + ' assessed as CLEAN across ' + total + ' sources. No immediate threats detected.';
      doc.rect(M,y,W-M*2,42).fill('#0d1424');
      doc.fillColor('#cbd5e1').font('Helvetica').fontSize(9)
        .text(summaryText, M+14, y+8, {width:W-M*2-28, align:'left'});
      y += 50;

      // ── RESULTS TABLE ────────────────────────────────────────────────────
      doc.rect(M,y,W-M*2,20).fill('#111827');
      doc.rect(M,y,4,20).fill('#00f5ff');
      doc.fillColor('#00f5ff').font('Helvetica-Bold').fontSize(9).text('SOURCE ANALYSIS RESULTS', M+12, y+6);
      y += 24;

      // Table header
      const colSource  = 110;
      const colVerdict = 78;
      const colKey     = 120;
      const colVal     = W-M*2 - colSource - colVerdict - colKey - 6;
      doc.rect(M,y,W-M*2,16).fill('#1e2340');
      doc.fillColor('#94a3b8').font('Helvetica-Bold').fontSize(7.5)
        .text('SOURCE', M+8, y+5)
        .text('VERDICT', M+colSource+8, y+5)
        .text('FIELD', M+colSource+colVerdict+8, y+5)
        .text('VALUE', M+colSource+colVerdict+colKey+8, y+5);
      y += 16;

      const vCM = {malicious:'#ef4444',suspicious:'#f97316',clean:'#10b981',error:'#64748b'};

      Object.entries(results).forEach(([source, result]) => {
        const rows = result.data || [];
        const blockH = rows.length * 16 + 4;
        if (y + blockH > 775) {
          doc.addPage();
          // Repeat mini-header on continuation pages
          doc.rect(0,0,W,26).fill('#060914');
          doc.rect(0,24,W,2).fill('#00f5ff');
          doc.fillColor('#00f5ff').font('Helvetica-Bold').fontSize(8)
            .text('THREAT INTELLIGENCE REPORT  —  CONTINUED', M, 8);
          doc.fillColor('#64748b').font('Helvetica').fontSize(7)
            .text(iocDisplay, W-M-200, 8, {width:195, align:'right'});
          y = 38;
          // Re-draw table header
          doc.rect(M,y,W-M*2,16).fill('#1e2340');
          doc.fillColor('#94a3b8').font('Helvetica-Bold').fontSize(7.5)
            .text('SOURCE', M+8, y+5)
            .text('VERDICT', M+colSource+8, y+5)
            .text('FIELD', M+colSource+colVerdict+8, y+5)
            .text('VALUE', M+colSource+colVerdict+colKey+8, y+5);
          y += 16;
        }

        const vColor = vCM[result.verdict]||'#64748b';
        // First row: show source + verdict spanning all data rows
        rows.forEach(([key, value], ri) => {
          const rowBg = ri%2===0 ? '#0d1424' : '#111827';
          doc.rect(M, y, W-M*2, 16).fill(rowBg);
          // Source name only on first row
          if (ri === 0) {
            doc.rect(M, y, 3, rows.length*16).fill(vColor);
            doc.fillColor('#00f5ff').font('Helvetica-Bold').fontSize(8)
              .text(source.toUpperCase().slice(0,12), M+7, y+4, {width:colSource-10, ellipsis:true});
          }
          // Verdict badge only on first row
          if (ri === 0) {
            doc.fillColor(vColor).font('Helvetica-Bold').fontSize(8)
              .text(result.verdict.toUpperCase(), M+colSource+8, y+4, {width:colVerdict-10});
          }
          // Key
          doc.fillColor('#64748b').font('Helvetica-Bold').fontSize(8)
            .text(String(key).slice(0,18), M+colSource+colVerdict+8, y+4, {width:colKey-10, ellipsis:true});
          // Value — full remaining width
          const valStr = String(value).slice(0,80) + (String(value).length>80?'…':'');
          doc.fillColor('#e2e8f0').font('Helvetica').fontSize(8)
            .text(valStr, M+colSource+colVerdict+colKey+8, y+4, {width:colVal-10, ellipsis:true});
          y += 16;
        });
        y += 4;
      });
      const pageCount = doc.bufferedPageRange().count;
      for (let i=0; i<pageCount; i++) {
        doc.switchToPage(i);
        const pH = doc.page.height;
        doc.rect(0,pH-28,W,28).fill('#060914');
        doc.rect(0,pH-28,W,1).fill('#1e2340');
        doc.fillColor('#334155').font('Helvetica').fontSize(7.5)
          .text('Threat Intel Hub  —  CONFIDENTIAL', M, pH-18)
          .text(`Page ${i+1} of ${pageCount}`, 0, pH-18, {align:'right',width:W-M});
      }
      doc.end();
      stream.on('finish', () => { shell.openPath(filePath); resolve({success:true,filePath}); });
      stream.on('error', err => resolve({success:false,error:err.message}));
    } catch(err) { resolve({success:false,error:err.message}); }
  });
});

// ════════════════════════════════════════════════════════════════════════════
// API FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════

// ─── THREAT INTELLIGENCE ────────────────────────────────────────────────────
async function queryVirusTotal(ioc, type, apiKey) {
  if (!apiKey) throw new Error('No API key configured');
  let url;
  ioc = ioc.trim();
  if (type !== 'url') ioc = ioc.toLowerCase(); // URL paths are case-sensitive
  if (type==='ip')          url=`https://www.virustotal.com/api/v3/ip_addresses/${ioc}`;
  else if (type==='domain') url=`https://www.virustotal.com/api/v3/domains/${ioc}`;
  else if (type==='hash')   url=`https://www.virustotal.com/api/v3/files/${ioc}`;
  else if (type==='url') {
    const encoded = Buffer.from(ioc.trim()).toString('base64').replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
    url=`https://www.virustotal.com/api/v3/urls/${encoded}`;
  }
  const res = await fetch(url, {headers:{'x-apikey':apiKey,'Accept':'application/json'}});
  if (res.status === 404) return { verdict:'clean', source:'virustotal', data:[
    ['Status','Not found in VirusTotal','success'],
    ['Note','File/hash has never been submitted',''],
  ]};
  if (!res.ok) {
    const body = await res.text().catch(()=>'');
    throw new Error(`HTTP ${res.status}${body?': '+body.slice(0,100):''}`);
  }
  const data = await res.json();
  const stats = data.data?.attributes?.last_analysis_stats||{};
  const malicious = stats.malicious||0, total = Object.values(stats).reduce((a,b)=>a+b,0);
  const verdict = malicious>5?'malicious':malicious>0?'suspicious':'clean';
  return { verdict, source:'virustotal', data:[
    ['Detection Ratio',`${malicious} / ${total}`,malicious>5?'danger':malicious>0?'warning':'success'],
    ['Malicious',malicious,malicious>0?'danger':'success'],
    ['Suspicious',stats.suspicious||0,stats.suspicious>0?'warning':''],
    ['Undetected',stats.undetected||0,'success'],
  ]};
}

async function queryAbuseIPDB(ip, apiKey) {
  if (!apiKey) throw new Error('No API key configured');
  const res = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90&verbose`, {headers:{'Key':apiKey,'Accept':'application/json'}});
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  const score = data.data.abuseConfidenceScore;
  const verdict = score>75?'malicious':score>25?'suspicious':'clean';
  return { verdict, source:'abuseipdb', data:[
    ['Confidence Score',`${score}%`,score>75?'danger':score>25?'warning':'success'],
    ['Total Reports',data.data.totalReports,''],
    ['Country',data.data.countryCode||'N/A',''],
    ['ISP',data.data.isp||'N/A',''],
  ]};
}

async function queryShodan(ip, apiKey) {
  if (!apiKey) throw new Error('No API key configured');
  const res = await fetch(`https://api.shodan.io/shodan/host/${ip}?key=${apiKey}`);
  if (res.status===401) throw new Error('Invalid key or premium subscription required');
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  const ports = data.ports?data.ports.join(', '):'None';
  const vulns = data.vulns?Object.keys(data.vulns).length:0;
  return { verdict:vulns>0?'suspicious':'clean', source:'shodan', data:[
    ['Open Ports',ports,vulns>0?'warning':''],
    ['Vulnerabilities',vulns,vulns>0?'danger':'success'],
    ['Organization',data.org||'Unknown',''],
    ['OS',data.os||'Unknown',''],
    ['Last Update',data.last_update?new Date(data.last_update).toLocaleDateString():'N/A',''],
  ]};
}

async function queryOTX(ioc, type, apiKey) {
  if (!apiKey) throw new Error('No API key configured');
  const ep = type==='ip'?`IPv4/${ioc}`:type==='domain'?`domain/${ioc}`:type==='hash'?`file/${ioc}`:`url/${encodeURIComponent(ioc)}`;
  const res = await fetch(`https://otx.alienvault.com/api/v1/indicators/${ep}/general`, {headers:{'X-OTX-API-KEY':apiKey}});
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  const pulseCount = data.pulse_info?.count??0;
  return { verdict:pulseCount>3?'malicious':pulseCount>0?'suspicious':'clean', source:'otx', data:[
    ['Pulse Count',pulseCount,pulseCount>3?'danger':pulseCount>0?'warning':'success'],
    ['Reputation',pulseCount===0?'Good':pulseCount>3?'Bad':'Suspicious',''],
    ['First Seen',data.base_indicator?.created?new Date(data.base_indicator.created).toLocaleDateString():'N/A',''],
  ]};
}

async function queryURLScan(ioc, type, apiKey) {
  if (!apiKey) throw new Error('No API key configured');
  let q;
  if (type==='url') { try { q=`domain:${new URL(ioc).hostname}`; } catch { q=`page.url:"${ioc}"`; } }
  else q=`domain:${ioc}`;
  const res = await fetch(`https://urlscan.io/api/v1/search/?q=${encodeURIComponent(q)}&size=10`, {headers:{'API-Key':apiKey}});
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text().catch(()=>'')}`);
  const data = await res.json();
  const first = data.results?.[0];
  const isMalicious = first?.verdicts?.overall?.malicious??false;
  const score = first?.verdicts?.overall?.score??null;
  return { verdict:first&&isMalicious?'malicious':'clean', source:'urlscan', data:[
    ['Scan Results',data.total||0,''],
    ['Verdict',first?(isMalicious?'Malicious':'Clean'):'No data found',isMalicious?'danger':'success'],
    ['Risk Score',score!==null?score:'N/A',score>50?'danger':score>20?'warning':'success'],
    ['Last Scan',first?.task?.time?new Date(first.task.time).toLocaleDateString():'N/A',''],
  ]};
}

async function queryHybridAnalysis(hash, apiKey) {
  if (!apiKey) throw new Error('No API key configured');
  hash = hash.trim().toLowerCase();
  // Try urlencoded first, fall back to JSON if 400
  let res = await fetch('https://www.hybrid-analysis.com/api/v2/search/hash', {
    method:'POST',
    headers:{'api-key':apiKey,'Content-Type':'application/x-www-form-urlencoded','User-Agent':'Falcon Sandbox'},
    body:`hash=${encodeURIComponent(hash)}`,
  });
  if (res.status === 400) {
    // Some versions need JSON
    res = await fetch('https://www.hybrid-analysis.com/api/v2/search/hash', {
      method:'POST',
      headers:{'api-key':apiKey,'Content-Type':'application/json','User-Agent':'Falcon Sandbox'},
      body: JSON.stringify({hash}),
    });
  }
  if (res.status === 404) return { verdict:'clean', source:'hybrid', data:[['Status','Hash not found in database','success'],['Note','File may not have been submitted yet','']] };
  if (!res.ok) {
    const body = await res.text().catch(()=>'');
    throw new Error(`HTTP ${res.status}${body?': '+body.slice(0,120):''}`);
  }
  const data = await res.json();
  if (!data||!data.length) return { verdict:'clean', source:'hybrid', data:[['Status','Not found in database','success'],['Verdict','Unknown','']] };
  const result = data[0], threatScore = result.threat_score||0;
  return { verdict:threatScore>70?'malicious':threatScore>30?'suspicious':'clean', source:'hybrid', data:[
    ['Threat Score',`${threatScore}/100`,threatScore>70?'danger':threatScore>30?'warning':'success'],
    ['Verdict',result.verdict||'Unknown',''],
    ['AV Detections',result.av_detect||'0',''],
    ['Environment',result.environment_description||'N/A',''],
  ]};
}

async function queryMaltiverse(ioc, apiKey) {
  if (!apiKey) throw new Error('No API key configured');
  const res = await fetch(`https://api.maltiverse.com/v1/hash/${ioc}`, {headers:{'Authorization':`Bearer ${apiKey}`}});
  if (res.status===404) return { verdict:'clean', source:'maltiverse', data:[['Status','Not found','success'],['Classification','Unknown','']] };
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  const cls = data.classification||'unknown';
  return { verdict:cls==='malicious'?'malicious':cls==='suspicious'?'suspicious':'clean', source:'maltiverse', data:[
    ['Classification',cls.toUpperCase(),cls==='malicious'?'danger':cls==='suspicious'?'warning':'success'],
    ['Score',data.score?`${data.score}/100`:'N/A',''],
    ['First Seen',data.creation_time?new Date(data.creation_time*1000).toLocaleDateString():'N/A',''],
  ]};
}

// ─── INFRASTRUCTURE & NETWORK ────────────────────────────────────────────────
async function queryGreyNoise(ip, apiKey) {
  if (!apiKey) throw new Error('No API key configured');
  const res = await fetch(`https://api.greynoise.io/v3/community/${ip}`, {headers:{'key':apiKey}});
  if (res.status===404) return { verdict:'clean', source:'greynoise', data:[['Classification','Not seen','success'],['Noise','No','success'],['RIOT','Unknown','']] };
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  const cls = data.classification||'unknown', isNoise=data.noise??false, isRiot=data.riot??false;
  const verdict = cls==='malicious'?'malicious':cls==='benign'?'clean':isNoise?'suspicious':'clean';
  return { verdict, source:'greynoise', data:[
    ['Classification',cls.charAt(0).toUpperCase()+cls.slice(1),cls==='malicious'?'danger':cls==='benign'?'success':'warning'],
    ['Internet Noise',isNoise?'Yes (mass scanner)':'No',isNoise?'warning':'success'],
    ['RIOT (trusted)',isRiot?'Yes':'No',isRiot?'success':''],
    ['Name',data.name||'Unknown',''],
    ['Last Seen',data.last_seen||'N/A',''],
  ]};
}

async function queryCensys(ioc, type, apiId, apiSecret) {
  if (!apiId||!apiSecret) throw new Error('Censys API ID and Secret required');
  const auth = Buffer.from(`${apiId}:${apiSecret}`).toString('base64');
  let url, options = {headers:{'Authorization':`Basic ${auth}`,'Content-Type':'application/json'}};
  if (type==='ip') {
    url = `https://search.censys.io/api/v2/hosts/${ioc}`;
  } else {
    url = 'https://search.censys.io/api/v2/certificates/search';
    options.method='POST'; options.body=JSON.stringify({q:`parsed.names: ${ioc}`,per_page:5});
  }
  const res = await fetch(url, options);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  if (type==='ip') {
    const result = data.result||{}, services = result.services||[];
    const ports = services.map(s=>`${s.port}/${s.transport_protocol}`).slice(0,5).join(', ')||'None';
    const labels = result.labels?.join(', ')||'None';
    return { verdict:services.length>10?'suspicious':'clean', source:'censys', data:[
      ['Open Ports',ports,services.length>10?'warning':''],
      ['Port Count',services.length,services.length>10?'warning':'success'],
      ['Labels',labels,''],
      ['Last Updated',result.last_updated_at?new Date(result.last_updated_at).toLocaleDateString():'N/A',''],
    ]};
  } else {
    const hits = data.result?.hits||[], count = data.result?.total||0;
    return { verdict:'clean', source:'censys', data:[
      ['Certificates Found',count,''],
      ['Subject DNs',hits.slice(0,3).map(h=>h.parsed?.subject_dn||'').filter(Boolean).join(' | ')||'None',''],
    ]};
  }
}

async function queryZoomEye(ioc, apiKey) {
  if (!apiKey) throw new Error('No ZoomEye API key configured');
  const res = await fetch(`https://api.zoomeye.hk/host/search?query=${encodeURIComponent(ioc)}&page=1`, {headers:{'API-KEY':apiKey}});
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  const total = data.total||0, first = data.matches?.[0];
  return { verdict:'clean', source:'zoomeye', data:[
    ['Total Results',total,''],
    ['Port/Service',first?.portinfo?.port?`${first.portinfo.port}/${first.portinfo.service||'?'}`:'N/A',''],
    ['Organization',first?.portinfo?.organization||'N/A',''],
    ['Country',first?.geoinfo?.country?.names?.en||'N/A',''],
    ['OS',first?.portinfo?.os||'N/A',''],
  ]};
}

async function queryNetlas(ioc, apiKey) {
  if (!apiKey) throw new Error('No Netlas API key configured');
  const res = await fetch(`https://app.netlas.io/api/responses/?q=${encodeURIComponent(ioc)}&source_type=include&start=0&fields=*`, {headers:{'X-API-Key':apiKey}});
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  const count = data.count||0, first = data.items?.[0]?.data;
  return { verdict:'clean', source:'netlas', data:[
    ['Results Found',count,''],
    ['Protocol',first?.protocol||'N/A',''],
    ['Port',first?.port||'N/A',''],
    ['Country',first?.geo?.country||'N/A',''],
    ['Certificate CN',first?.tls?.subject_cn||'N/A',''],
  ]};
}

async function queryTalos(ip) {
  // Talos public IP blacklist — no API key needed
  let isBlacklisted = false;
  let category = 'Unknown';
  let emailScore = 'N/A';

  try {
    const listRes = await fetch('https://www.talosintelligence.com/documents/ip-blacklist', {
      headers: { 'User-Agent': 'Mozilla/5.0 ThreatIntelHub/7.0', 'Accept': 'text/plain' },
    });
    if (listRes.ok) {
      const text = await listRes.text();
      isBlacklisted = text.split('\n').some(line => line.trim() === ip.trim());
    }
  } catch(e) {}

  const verdict = isBlacklisted ? 'malicious' : 'clean';
  return {
    verdict, source: 'talos',
    data: [
      ['IP Blacklisted',    isBlacklisted ? '⚠ YES — On Talos Blacklist' : '✓ Not on blacklist', isBlacklisted ? 'danger' : 'success'],
      ['Reputation Source', 'Cisco Talos Intelligence', ''],
      ['Blacklist Type',    'Talos Community IP Reputation', ''],
      ['Full Report',       `talosintelligence.com/reputation_center/lookup?search=${ip}`, ''],
    ],
  };
}

async function queryBGPView(ip) {
  const res = await fetch(`https://api.bgpview.io/ip/${ip}`, {headers:{'Accept':'application/json'}});
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  const prefix = data.data?.prefixes?.[0];
  return { verdict:'clean', source:'bgpview', data:[
    ['ASN',prefix?.asn?.asn?`AS${prefix.asn.asn}`:'Unknown',''],
    ['ASN Name',prefix?.asn?.name||'Unknown',''],
    ['Description',prefix?.asn?.description_short||'N/A',''],
    ['Prefix (CIDR)',prefix?.prefix||'Unknown',''],
    ['Country',prefix?.asn?.country_code||'Unknown',''],
  ]};
}

async function queryIPInfo(ip) {
  const res = await fetch(`https://ipinfo.io/${ip}/json`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  const isHosting = ['amazon','google','microsoft','cloudflare','digitalocean','linode','vultr','ovh','hetzner'].some(h=>(data.org||'').toLowerCase().includes(h));
  return { verdict:'clean', source:'ipinfo', data:[
    ['Organization',data.org||'Unknown',''],
    ['Location',[data.city,data.region,data.country].filter(Boolean).join(', ')||'Unknown',''],
    ['Hostname',data.hostname||'None',''],
    ['Hosting/VPS',isHosting?'Yes':'No',isHosting?'warning':''],
    ['Timezone',data.timezone||'Unknown',''],
  ]};
}

// ─── DOMAIN & DNS ────────────────────────────────────────────────────────────
async function querySecurityTrails(ioc, type, apiKey) {
  if (!apiKey) throw new Error('No API key configured');
  const url = type==='domain'?`https://api.securitytrails.com/v1/domain/${ioc}`:`https://api.securitytrails.com/v1/ips/nearby/${ioc}`;
  const res = await fetch(url, {headers:{'apikey':apiKey}});
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  if (type==='domain') {
    return { verdict:'clean', source:'securitytrails', data:[
      ['A Records',data.current_dns?.a?.values?.map(v=>v.ip).join(', ')||'None',''],
      ['Nameservers',data.current_dns?.ns?.values?.map(v=>v.value).join(', ')||'None',''],
      ['MX Records',data.current_dns?.mx?.values?.map(v=>v.value).join(', ')||'None',''],
      ['Subdomains',data.subdomain_count??'Unknown',data.subdomain_count>50?'warning':''],
      ['Alexa Rank',data.alexa_rank||'Not ranked',''],
    ]};
  } else {
    const nearby = data.records?.slice(0,3).map(r=>r.hostname).join(', ')||'None';
    return { verdict:'clean', source:'securitytrails', data:[['Nearby Domains',nearby,''],['Count',data.records?.length||0,'']] };
  }
}

async function queryRobtex(ioc, type) {
  let url = type==='ip' ? `https://freeapi.robtex.com/ipquery/${ioc}` : `https://freeapi.robtex.com/pdns/forward/${ioc}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  if (type==='ip') {
    return { verdict:'clean', source:'robtex', data:[
      ['AS Name',data.asname||'N/A',''],
      ['AS Number',data.as?`AS${data.as}`:'N/A',''],
      ['Country',data.country||'N/A',''],
      ['Active Routes',data.act?.slice(0,3).map(r=>r.o).join(', ')||'None',''],
    ]};
  } else {
    return { verdict:'clean', source:'robtex', data:[
      ['Resolved IPs',data.rrdata?.slice(0,4).map(r=>r.ip).join(', ')||'None',''],
      ['Record Count',data.rrdata?.length||0,''],
    ]};
  }
}

async function queryViewDNS(ioc, type, apiKey) {
  if (!apiKey) throw new Error('No ViewDNS API key configured');
  const endpoint = type==='domain' ? `iphistory/?domain=${ioc}` : `reverseip/?host=${ioc}`;
  const res = await fetch(`https://api.viewdns.info/${endpoint}&apikey=${apiKey}&output=json`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  const records = data.response?.records||[];
  return { verdict:'clean', source:'viewdns', data:[
    ['Records Found',records.length,''],
    ...(records.slice(0,4).map((r,i)=>[
      type==='domain'?`IP ${i+1}`:`Domain ${i+1}`,
      type==='domain'?(r.ip||JSON.stringify(r)):(r.name||JSON.stringify(r)),
      ''
    ]))
  ]};
}

// ─── BREACH & CREDENTIALS ────────────────────────────────────────────────────
async function queryHIBP(email, apiKey) {
  if (!apiKey) throw new Error('No HIBP API key configured');
  const res = await fetch(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`, {
    headers:{'hibp-api-key':apiKey,'User-Agent':'ThreatIntelHub-Desktop'},
  });
  if (res.status===404) return { verdict:'clean', source:'hibp', data:[['Status','Not found in any breach','success'],['Breaches','0','success']] };
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const breaches = await res.json();
  const count = breaches.length, names = breaches.slice(0,4).map(b=>b.Name).join(', ');
  const latest = breaches.sort((a,b)=>new Date(b.BreachDate)-new Date(a.BreachDate))[0];
  return { verdict:count>0?'malicious':'clean', source:'hibp', data:[
    ['Breach Count',count,count>5?'danger':count>0?'warning':'success'],
    ['Known Breaches',names||'None',count>0?'warning':''],
    ['Latest Breach',latest?.BreachDate||'N/A',''],
    ['Data Types',latest?.DataClasses?.slice(0,3).join(', ')||'N/A',''],
  ]};
}

async function queryLeakCheck(email) {
  // Free public endpoint — no key needed
  const res = await fetch(`https://leakcheck.io/api/public?check=${encodeURIComponent(email)}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  const found = data.found??false, count = data.sources?.length||0;
  return { verdict:found?'malicious':'clean', source:'leakcheck', data:[
    ['Exposed',found?'Yes':'No',found?'danger':'success'],
    ['Source Count',count,count>0?'warning':'success'],
    ['Sources',data.sources?.slice(0,4).join(', ')||'None',count>0?'warning':''],
  ]};
}

async function queryDeHashed(email, apiKey, apiUser) {
  if (!apiKey||!apiUser) throw new Error('DeHashed requires email login + API key');
  const auth = Buffer.from(`${apiUser}:${apiKey}`).toString('base64');
  const res = await fetch(`https://api.dehashed.com/search?query=email:${encodeURIComponent(email)}&size=5`, {
    headers:{'Authorization':`Basic ${auth}`,'Accept':'application/json'},
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  const count = data.total||0, first = data.entries?.[0];
  return { verdict:count>0?'malicious':'clean', source:'dehashed', data:[
    ['Records Found',count,count>0?'danger':'success'],
    ['First Breach',first?.database_name||'N/A',''],
    ['Password Found',first?.password?'Yes':'No',first?.password?'danger':''],
    ['Username',first?.username||'N/A',''],
  ]};
}

async function querySnusbase(query, apiKey) {
  if (!apiKey) throw new Error('No Snusbase API key configured');
  const res = await fetch('https://api.snusbase.com/data/search', {
    method:'POST',
    headers:{'Auth':apiKey,'Content-Type':'application/json'},
    body:JSON.stringify({terms:[query],types:['email','username','password','hash','name'],wildcard:false}),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  const size = data.size||0, firstDb = Object.keys(data.results||{})[0];
  const first = firstDb?data.results[firstDb][0]:null;
  return { verdict:size>0?'malicious':'clean', source:'snusbase', data:[
    ['Records Found',size,size>0?'danger':'success'],
    ['Database',firstDb||'N/A',''],
    ['Email',first?.email||'N/A',''],
    ['Password',first?.password?'Found (hidden)':'N/A',first?.password?'danger':''],
  ]};
}

// ─── SEARCH / DARK WEB ───────────────────────────────────────────────────────
async function queryIntelligenceX(ioc, apiKey) {
  if (!apiKey) throw new Error('No IntelligenceX API key configured');
  const searchRes = await fetch('https://2.intelx.io/intelligent/search', {
    method:'POST',
    headers:{'x-key':apiKey,'Content-Type':'application/json'},
    body:JSON.stringify({term:ioc,maxresults:10,media:0,target:0,terminate:[],timeout:5}),
  });
  if (!searchRes.ok) throw new Error(`HTTP ${searchRes.status}`);
  const { id } = await searchRes.json();
  if (!id) throw new Error('No search ID returned');
  await new Promise(r=>setTimeout(r,2500));
  const resultsRes = await fetch(`https://2.intelx.io/intelligent/search/result?id=${id}&limit=10&statistics=1`, {headers:{'x-key':apiKey}});
  if (!resultsRes.ok) throw new Error(`HTTP ${resultsRes.status}`);
  const results = await resultsRes.json();
  const count = results.records?.length||0;
  return { verdict:count>0?'suspicious':'clean', source:'intelligencex', data:[
    ['Results Found',count,count>0?'warning':'success'],
    ['Status',results.status===2?'Complete':'In Progress',''],
    ['First Source',results.records?.[0]?.storageid||'N/A',''],
    ['Search ID',id.slice(0,20)+'…',''],
  ]};
}

async function queryDarkSearch(query) {
  const res = await fetch(`https://darksearch.io/api/search?query=${encodeURIComponent(query)}&page=1`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  const total = data.total||0, first = data.data?.[0];
  return { verdict:total>0?'suspicious':'clean', source:'darksearch', data:[
    ['Dark Web Results',total,total>0?'warning':'success'],
    ['First Title',first?.title||'None',''],
    ['First URL',first?.link?first.link.substring(0,50)+'…':'N/A',''],
    ['Page',data.current_page||1,''],
  ]};
}

// ─── OSINT / PASSIVE RECON (keyless) ─────────────────────────────
// Certificate Transparency (crt.sh) - subdomain discovery, no key.
async function queryCrtSh(domain, type) {
  domain = String(domain).trim().toLowerCase();
  const res = await fetch(`https://crt.sh/?q=${encodeURIComponent('%.' + domain)}&output=json`,
    { headers: { 'User-Agent': 'ThreatIntelHub/7', 'Accept': 'application/json' } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch (e) {
    return { verdict: 'clean', source: 'crtsh', data: [['Certificates', 'No data returned', '']] };
  }
  if (!Array.isArray(data) || !data.length)
    return { verdict: 'clean', source: 'crtsh', data: [['Certificates Found', '0', ''], ['Subdomains', 'None', '']] };
  const subs = new Set();
  data.forEach(c => String(c.name_value || '').split('\n').forEach(n => {
    n = n.trim().toLowerCase();
    if (n && !n.startsWith('*.')) subs.add(n);
  }));
  const subList = [...subs];
  const issuers = [...new Set(data.slice(0, 60).map(c => c.issuer_name || '').filter(Boolean))];
  return { verdict: 'clean', source: 'crtsh', data: [
    ['Certificates Found', data.length, ''],
    ['Unique Subdomains', subList.length, subList.length > 50 ? 'warning' : ''],
    ['Sample Subdomains', subList.slice(0, 6).join(', ') || 'None', ''],
    ['Issuers', issuers.slice(0, 2).join(' | ') || 'N/A', ''],
  ]};
}

// RDAP registration data (rdap.org) - no key. Flags newly-registered domains.
async function queryRDAP(ioc, type) {
  ioc = String(ioc).trim().toLowerCase();
  const url = type === 'ip' ? `https://rdap.org/ip/${ioc}` : `https://rdap.org/domain/${ioc}`;
  const res = await fetch(url, { headers: { 'Accept': 'application/rdap+json', 'User-Agent': 'ThreatIntelHub/7' } });
  if (res.status === 404) return { verdict: 'clean', source: 'rdap', data: [['Status', 'Not found in RDAP', '']] };
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const d = await res.json();
  const events = {};
  (d.events || []).forEach(e => { if (e.eventAction) events[e.eventAction] = e.eventDate; });
  const registrar = (d.entities || []).find(e => (e.roles || []).includes('registrar'));
  let regName = registrar && registrar.handle || 'N/A';
  try {
    const fn = registrar.vcardArray[1].find(f => f[0] === 'fn');
    if (fn && fn[3]) regName = fn[3];
  } catch (e) {}
  if (type === 'ip') {
    return { verdict: 'clean', source: 'rdap', data: [
      ['Network Name', d.name || d.handle || 'N/A', ''],
      ['Range', (d.startAddress && d.endAddress) ? `${d.startAddress} - ${d.endAddress}` : 'N/A', ''],
      ['Country', d.country || 'N/A', ''],
      ['Registered', events.registration ? new Date(events.registration).toLocaleDateString() : 'N/A', ''],
      ['Last Changed', events.lastChanged ? new Date(events.lastChanged).toLocaleDateString() : 'N/A', ''],
    ]};
  }
  let ageDays = null, verdict = 'clean';
  if (events.registration) {
    ageDays = Math.floor((Date.now() - new Date(events.registration)) / 86400000);
    if (ageDays >= 0 && ageDays < 30) verdict = 'suspicious';
  }
  const young = ageDays !== null && ageDays < 30;
  return { verdict, source: 'rdap', data: [
    ['Registrar', regName, ''],
    ['Registered', events.registration ? new Date(events.registration).toLocaleDateString() : 'N/A', young ? 'warning' : ''],
    ['Domain Age', ageDays !== null ? `${ageDays} days` : 'N/A', young ? 'danger' : ''],
    ['Expires', events.expiration ? new Date(events.expiration).toLocaleDateString() : 'N/A', ''],
    ['Status', (d.status || []).slice(0, 3).join(', ') || 'N/A', ''],
  ]};
}

// Wayback Machine (archive.org CDX) - historical footprint, no key.
async function queryWayback(ioc, type) {
  let host = String(ioc).trim();
  try { if (type === 'url') host = new URL(host).hostname; } catch (e) {}
  host = host.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  const cdx = `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(host)}*&output=json&fl=timestamp,original&collapse=urlkey&limit=200`;
  const res = await fetch(cdx, { headers: { 'User-Agent': 'ThreatIntelHub/7' } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const rows = await res.json();
  const body = Array.isArray(rows) ? rows.slice(1) : [];
  if (!body.length) return { verdict: 'clean', source: 'wayback', data: [['Snapshots', 'None archived', '']] };
  const times = body.map(r => r[0]).filter(Boolean).sort();
  const fmt = t => t ? `${t.slice(0,4)}-${t.slice(4,6)}-${t.slice(6,8)}` : 'N/A';
  return { verdict: 'clean', source: 'wayback', data: [
    ['Unique URLs Archived', body.length + (body.length >= 200 ? '+' : ''), ''],
    ['Earliest Snapshot', fmt(times[0]), ''],
    ['Latest Snapshot', fmt(times[times.length - 1]), ''],
    ['Sample Path', body[0] && body[0][1] ? String(body[0][1]).slice(0, 60) : 'N/A', ''],
  ]};
}

// ransomware.live - is this org listed on a ransomware leak site? no key.
async function queryRansomware(ioc) {
  let keyword = String(ioc).trim().toLowerCase();
  try { if (/^https?:\/\//.test(keyword)) keyword = new URL(keyword).hostname; } catch (e) {}
  keyword = keyword.replace(/^www\./, '').split('.')[0];
  if (!keyword) throw new Error('Could not derive an organization name');
  const res = await fetch(`https://api.ransomware.live/v2/searchvictims/${encodeURIComponent(keyword)}`,
    { headers: { 'Accept': 'application/json', 'User-Agent': 'ThreatIntelHub/7' } });
  if (res.status === 404) return { verdict: 'clean', source: 'ransomware', data: [['Leak-Site Listings', 'None found', 'success']] };
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  const arr = Array.isArray(data) ? data : (data.victims || []);
  if (!arr.length)
    return { verdict: 'clean', source: 'ransomware', data: [['Leak-Site Listings', 'Not found on ransom leak sites', 'success']] };
  const first = arr[0];
  return { verdict: 'malicious', source: 'ransomware', data: [
    ['Leak-Site Listings', `${arr.length} match(es) for "${keyword}"`, 'danger'],
    ['Most Recent Victim', first.victim || 'N/A', 'warning'],
    ['Ransom Group', first.group || 'N/A', 'danger'],
    ['Attack Date', first.attackdate ? String(first.attackdate).slice(0, 10) : 'N/A', ''],
    ['Country', first.country || 'N/A', ''],
  ]};
}

// ─── SOCIAL & IDENTITY ───────────────────────────────────────────────────────
async function querySocialSearcher(query, apiKey) {
  if (!apiKey) throw new Error('No Social-Searcher API key configured');
  const res = await fetch(`https://api.social-searcher.com/v2/search?q=${encodeURIComponent(query)}&key=${apiKey}&limit=5`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  const count = data.meta?.found||0, posts = data.posts||[];
  const networks = [...new Set(posts.map(p=>p.network))].join(', ')||'None';
  return { verdict:'clean', source:'socialsearcher', data:[
    ['Mentions Found',count,count>0?'warning':''],
    ['Networks',networks,''],
    ['Latest Post',posts[0]?.posted?new Date(posts[0].posted).toLocaleDateString():'N/A',''],
    ['Sentiment',posts[0]?.sentiment||'N/A',''],
  ]};
}
