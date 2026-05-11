const { app, BrowserWindow, ipcMain, dialog, shell, Menu } = require('electron');
const path = require('path');
const Store = require('electron-store');
const PDFDocument = require('pdfkit');
const fs = require('fs');

// Encrypted local storage for API keys
const store = new Store({ encryptionKey: 'tih-secure-key-2024' });

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 900,
    minHeight: 650,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: false,
    },
    title: 'Threat Intel Hub',
    backgroundColor: '#0a0e27',
    show: false,
    autoHideMenuBar: true,
  });

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  // Remove default menu
  Menu.setApplicationMenu(null);
}

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// ─── IPC: API Key Management ───────────────────────────────────────────────

ipcMain.handle('open-external', (event, url) => {
  if (url && url.startsWith('https://')) shell.openExternal(url);
});

ipcMain.handle('get-api-keys', () => {
  return store.get('apiKeys', {});
});

ipcMain.handle('save-api-keys', (event, keys) => {
  store.set('apiKeys', keys);
  return true;
});

// ─── IPC: Unified API Query ────────────────────────────────────────────────

ipcMain.handle('query-api', async (event, { source, ioc, type }) => {
  const keys = store.get('apiKeys', {});
  try {
    switch (source) {
      case 'virustotal':      return await queryVirusTotal(ioc, type, keys.virustotal);
      case 'abuseipdb':      return await queryAbuseIPDB(ioc, keys.abuseipdb);
      case 'shodan':         return await queryShodan(ioc, keys.shodan);
      case 'otx':            return await queryOTX(ioc, type, keys.otx);
      case 'urlscan':        return await queryURLScan(ioc, type, keys.urlscan);
      case 'hybrid':         return await queryHybridAnalysis(ioc, keys.hybrid);
      case 'maltiverse':     return await queryMaltiverse(ioc, keys.maltiverse);
      case 'greynoise':      return await queryGreyNoise(ioc, keys.greynoise);
      case 'ipinfo':         return await queryIPInfo(ioc);
      case 'bgpview':        return await queryBGPView(ioc);
      case 'securitytrails': return await querySecurityTrails(ioc, type, keys.securitytrails);
      case 'hibp':           return await queryHIBP(ioc, keys.hibp);
      case 'censys':         return await queryCensys(ioc, type, keys.censys_id, keys.censys_secret);
      default: throw new Error('Unknown source: ' + source);
    }
  } catch (error) {
    return { verdict: 'error', source, data: [['Error', error.message, 'danger']] };
  }
});

// ─── IPC: PDF Report Generation ───────────────────────────────────────────

ipcMain.handle('generate-report', async (event, { ioc, results, iocType }) => {
  const { filePath, canceled } = await dialog.showSaveDialog(mainWindow, {
    title: 'Save Threat Intelligence Report',
    defaultPath: path.join(app.getPath('documents'), `ThreatIntel_${ioc.substring(0, 20).replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}.pdf`),
    filters: [{ name: 'PDF Files', extensions: ['pdf'] }],
  });

  if (canceled || !filePath) return { success: false };

  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({ size: 'A4', margin: 0, bufferPages: true });
      const stream = fs.createWriteStream(filePath);
      doc.pipe(stream);

      const W = doc.page.width;   // 595
      const M = 50;               // margin

      // ── COVER HEADER ──────────────────────────────────────────────────────
      doc.rect(0, 0, W, 110).fill('#0a0e27');
      doc.rect(0, 108, W, 2).fill('#00f5ff');

      doc.fillColor('#00f5ff').font('Helvetica-Bold').fontSize(22)
        .text('THREAT INTELLIGENCE REPORT', M, 30);
      doc.fillColor('#94a3b8').font('Helvetica').fontSize(10)
        .text('Multi-Source Intelligence Aggregation Platform', M, 57);
      doc.fillColor('#475569').fontSize(8.5)
        .text(`Generated: ${new Date().toUTCString()}`, M, 74)
        .text(`Report ID: TI-${Date.now()}`, M, 87);

      // ── IOC BLOCK ─────────────────────────────────────────────────────────
      doc.rect(M, 126, W - M * 2, 52).fill('#0f172a').stroke('#1e2340');
      doc.fillColor('#64748b').font('Helvetica-Bold').fontSize(8).text('INDICATOR OF COMPROMISE', M + 14, 136);
      doc.fillColor('#e2e8f0').font('Helvetica').fontSize(12).text(ioc, M + 14, 149, { width: W - M * 2 - 80 });
      
      // IOC type badge
      const badgeColors = { ip: '#0ea5e9', domain: '#8b5cf6', hash: '#f97316', url: '#10b981', unknown: '#64748b' };
      const badgeColor = badgeColors[iocType] || '#64748b';
      doc.roundedRect(W - M - 70, 141, 60, 20, 4).fill(badgeColor);
      doc.fillColor('white').font('Helvetica-Bold').fontSize(8)
        .text(iocType.toUpperCase(), W - M - 64, 148);

      // ── OVERALL VERDICT ───────────────────────────────────────────────────
      const totalSources   = Object.keys(results).length;
      const maliciousCount = Object.values(results).filter(r => r.verdict === 'malicious').length;
      const suspiciousCount = Object.values(results).filter(r => r.verdict === 'suspicious').length;
      const cleanCount     = Object.values(results).filter(r => r.verdict === 'clean').length;

      let overallVerdict = 'CLEAN';
      let verdictColor   = '#10b981';
      let verdictBg      = '#052e16';
      if (maliciousCount > 0)   { overallVerdict = 'MALICIOUS';  verdictColor = '#ef4444'; verdictBg = '#1c0707'; }
      else if (suspiciousCount > 0) { overallVerdict = 'SUSPICIOUS'; verdictColor = '#f97316'; verdictBg = '#1c0e04'; }

      // Verdict card
      doc.rect(M, 192, 165, 80).fill(verdictBg).stroke(verdictColor);
      doc.rect(M, 192, 165, 4).fill(verdictColor);
      doc.fillColor('#94a3b8').font('Helvetica-Bold').fontSize(8).text('OVERALL VERDICT', M + 12, 204);
      doc.fillColor(verdictColor).font('Helvetica-Bold').fontSize(26).text(overallVerdict, M + 12, 218);

      // Stat boxes
      const statBoxes = [
        { label: 'SOURCES', value: totalSources,   color: '#94a3b8', bg: '#0f172a' },
        { label: 'MALICIOUS', value: maliciousCount, color: '#ef4444', bg: '#1c0707' },
        { label: 'SUSPICIOUS', value: suspiciousCount, color: '#f97316', bg: '#1c0e04' },
        { label: 'CLEAN', value: cleanCount, color: '#10b981', bg: '#052e16' },
      ];
      const boxW = (W - M * 2 - 165 - 12) / 4 - 4;
      statBoxes.forEach((box, i) => {
        const bx = M + 165 + 12 + i * (boxW + 4);
        doc.rect(bx, 192, boxW, 80).fill(box.bg).stroke(box.color);
        doc.rect(bx, 192, boxW, 4).fill(box.color);
        doc.fillColor(box.color).font('Helvetica-Bold').fontSize(32).text(String(box.value), bx + 10, 210);
        doc.fillColor('#64748b').font('Helvetica-Bold').fontSize(7.5).text(box.label, bx + 10, 251);
      });

      // ── EXECUTIVE SUMMARY ────────────────────────────────────────────────
      let y = 292;
      doc.rect(M, y, W - M * 2, 24).fill('#0f172a');
      doc.fillColor('#00f5ff').font('Helvetica-Bold').fontSize(10)
        .text('EXECUTIVE SUMMARY', M + 12, y + 8);
      y += 30;

      const summaryText = overallVerdict === 'MALICIOUS'
        ? `This indicator has been identified as MALICIOUS by ${maliciousCount} out of ${totalSources} intelligence sources. Immediate investigation and containment is recommended.`
        : overallVerdict === 'SUSPICIOUS'
        ? `This indicator has raised flags in ${suspiciousCount} out of ${totalSources} intelligence sources. Further investigation is recommended before allowing network access.`
        : `This indicator was found to be CLEAN across all ${totalSources} queried intelligence sources. No immediate threats detected.`;

      doc.rect(M, y, W - M * 2, 40).fill('#111827');
      doc.rect(M, y, 3, 40).fill(verdictColor);
      doc.fillColor('#cbd5e1').font('Helvetica').fontSize(9)
        .text(summaryText, M + 14, y + 8, { width: W - M * 2 - 24 });
      y += 50;

      // ── DETAILED RESULTS ─────────────────────────────────────────────────
      doc.rect(M, y, W - M * 2, 24).fill('#0f172a');
      doc.fillColor('#00f5ff').font('Helvetica-Bold').fontSize(10)
        .text('DETAILED SOURCE ANALYSIS', M + 12, y + 8);
      y += 30;

      const vColorMap = { malicious: '#ef4444', suspicious: '#f97316', clean: '#10b981', error: '#64748b' };
      const vBgMap    = { malicious: '#1c0707', suspicious: '#1c0e04', clean: '#052e16', error: '#0f172a' };

      Object.entries(results).forEach(([source, result]) => {
        const rowCount = result.data.length;
        const cardH = 22 + rowCount * 20 + 12;

        if (y + cardH > 780) {
          doc.addPage();
          // Repeat header on new page
          doc.rect(0, 0, W, 30).fill('#0a0e27');
          doc.fillColor('#00f5ff').font('Helvetica-Bold').fontSize(9)
            .text('THREAT INTELLIGENCE REPORT  —  CONTINUED', M, 10);
          doc.fillColor('#64748b').fontSize(8).font('Helvetica')
            .text(ioc, W - M - 200, 10, { width: 200, align: 'right' });
          y = 42;
        }

        const vColor = vColorMap[result.verdict] || '#64748b';
        const vBg    = vBgMap[result.verdict] || '#0f172a';

        // Source header bar
        doc.rect(M, y, W - M * 2, 22).fill('#0f172a');
        doc.rect(M, y, 3, 22).fill(vColor);
        doc.fillColor('#00f5ff').font('Helvetica-Bold').fontSize(9.5)
          .text(source.toUpperCase(), M + 12, y + 7);

        // Verdict pill
        const pillText = result.verdict.toUpperCase();
        doc.roundedRect(W - M - 80, y + 4, 70, 14, 3).fill(vColor);
        doc.fillColor('white').font('Helvetica-Bold').fontSize(7.5)
          .text(pillText, W - M - 74, y + 7);
        y += 22;

        // Data rows
        result.data.forEach(([key, value], idx) => {
          const rowBg = idx % 2 === 0 ? '#111827' : '#0d1424';
          doc.rect(M, y, W - M * 2, 20).fill(rowBg);
          doc.fillColor('#64748b').font('Helvetica-Bold').fontSize(8).text(String(key), M + 12, y + 6);
          doc.fillColor('#e2e8f0').font('Helvetica').fontSize(8)
            .text(String(value), M + 180, y + 6, { width: W - M - 180 - 20 });
          y += 20;
        });
        y += 12;
      });

      // ── FOOTER ────────────────────────────────────────────────────────────
      const pageCount = doc.bufferedPageRange().count;
      for (let i = 0; i < pageCount; i++) {
        doc.switchToPage(i);
        const pH = doc.page.height;
        doc.rect(0, pH - 28, W, 28).fill('#0a0e27');
        doc.rect(0, pH - 28, W, 1).fill('#1e2340');
        doc.fillColor('#334155').font('Helvetica').fontSize(7.5)
          .text('Threat Intel Hub  —  CONFIDENTIAL  —  For authorized use only', M, pH - 18)
          .text(`Page ${i + 1} of ${pageCount}`, 0, pH - 18, { align: 'right', width: W - M });
      }

      doc.end();

      stream.on('finish', () => {
        shell.openPath(filePath);
        resolve({ success: true, filePath });
      });
      stream.on('error', (err) => {
        reject({ success: false, error: err.message });
      });
    } catch (err) {
      reject({ success: false, error: err.message });
    }
  });
});

// ─── API Functions (Node.js — no CORS) ────────────────────────────────────

async function queryVirusTotal(ioc, type, apiKey) {
  if (!apiKey) throw new Error('No API key configured');
  let url;
  if (type === 'ip')          url = `https://www.virustotal.com/api/v3/ip_addresses/${ioc}`;
  else if (type === 'domain') url = `https://www.virustotal.com/api/v3/domains/${ioc}`;
  else if (type === 'hash')   url = `https://www.virustotal.com/api/v3/files/${ioc}`;
  else if (type === 'url') {
    const encoded = Buffer.from(ioc).toString('base64url');
    url = `https://www.virustotal.com/api/v3/urls/${encoded}`;
  }

  const res = await fetch(url, { headers: { 'x-apikey': apiKey } });
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);

  const data = await res.json();
  const stats = data.data?.attributes?.last_analysis_stats || {};
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const total = Object.values(stats).reduce((a, b) => a + b, 0);
  const verdict = malicious > 5 ? 'malicious' : malicious > 0 ? 'suspicious' : 'clean';

  return {
    verdict, source: 'virustotal',
    data: [
      ['Detection Ratio', `${malicious} / ${total}`, malicious > 5 ? 'danger' : malicious > 0 ? 'warning' : 'success'],
      ['Malicious',   malicious,              malicious > 0   ? 'danger'   : 'success'],
      ['Suspicious',  suspicious,             suspicious > 0  ? 'warning'  : ''],
      ['Undetected',  stats.undetected || 0,  'success'],
    ],
  };
}

async function queryAbuseIPDB(ip, apiKey) {
  if (!apiKey) throw new Error('No API key configured');
  const res = await fetch(
    `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90&verbose`,
    { headers: { 'Key': apiKey, 'Accept': 'application/json' } }
  );
  if (!res.ok) throw new Error(`HTTP ${res.status}`);

  const data = await res.json();
  const score = data.data.abuseConfidenceScore;
  const verdict = score > 75 ? 'malicious' : score > 25 ? 'suspicious' : 'clean';

  return {
    verdict, source: 'abuseipdb',
    data: [
      ['Confidence Score', `${score}%`,                     score > 75 ? 'danger' : score > 25 ? 'warning' : 'success'],
      ['Total Reports',    data.data.totalReports,          ''],
      ['Country',          data.data.countryCode || 'N/A',  ''],
      ['ISP',              data.data.isp          || 'N/A',  ''],
    ],
  };
}

async function queryShodan(ip, apiKey) {
  if (!apiKey) throw new Error('No API key configured');
  const res = await fetch(`https://api.shodan.io/shodan/host/${ip}?key=${apiKey}`);
  if (res.status === 401) throw new Error('Invalid API key or premium subscription required');
  if (!res.ok) throw new Error(`HTTP ${res.status}`);

  const data = await res.json();
  const ports = data.ports ? data.ports.join(', ') : 'None';
  const vulns = data.vulns ? Object.keys(data.vulns).length : 0;
  const verdict = vulns > 0 ? 'suspicious' : 'clean';

  return {
    verdict, source: 'shodan',
    data: [
      ['Open Ports',      ports,                          vulns > 0 ? 'warning' : ''],
      ['Vulnerabilities', vulns,                          vulns > 0 ? 'danger'  : 'success'],
      ['Organization',    data.org         || 'Unknown',  ''],
      ['Last Update',     data.last_update ? new Date(data.last_update).toLocaleDateString() : 'N/A', ''],
    ],
  };
}

async function queryOTX(ioc, type, apiKey) {
  if (!apiKey) throw new Error('No API key configured');
  let endpoint = '';
  if      (type === 'ip')     endpoint = `https://otx.alienvault.com/api/v1/indicators/IPv4/${ioc}/general`;
  else if (type === 'domain') endpoint = `https://otx.alienvault.com/api/v1/indicators/domain/${ioc}/general`;
  else if (type === 'hash')   endpoint = `https://otx.alienvault.com/api/v1/indicators/file/${ioc}/general`;
  else if (type === 'url')    endpoint = `https://otx.alienvault.com/api/v1/indicators/url/${encodeURIComponent(ioc)}/general`;

  const res = await fetch(endpoint, { headers: { 'X-OTX-API-KEY': apiKey } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);

  const data = await res.json();
  const pulseCount = data.pulse_info?.count ?? 0;
  const verdict = pulseCount > 3 ? 'malicious' : pulseCount > 0 ? 'suspicious' : 'clean';

  return {
    verdict, source: 'otx',
    data: [
      ['Pulse Count',  pulseCount,                                                           pulseCount > 3 ? 'danger' : pulseCount > 0 ? 'warning' : 'success'],
      ['Reputation',   pulseCount === 0 ? 'Good' : pulseCount > 3 ? 'Bad' : 'Suspicious',   ''],
      ['First Seen',   data.base_indicator?.created ? new Date(data.base_indicator.created).toLocaleDateString() : 'N/A', ''],
    ],
  };
}

async function queryURLScan(ioc, type, apiKey) {
  if (!apiKey) throw new Error('No API key configured');

  // URLScan uses Elasticsearch query syntax — never pass a raw URL as q
  let q;
  if (type === 'url') {
    try {
      const parsed = new URL(ioc);
      q = `domain:${parsed.hostname}`;        // search by extracted hostname
    } catch {
      q = `page.url:"${ioc}"`;               // fallback: quoted field search
    }
  } else {
    q = `domain:${ioc}`;
  }

  const res = await fetch(
    `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(q)}&size=10`,
    { headers: { 'API-Key': apiKey } }
  );

  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`HTTP ${res.status}${body ? ': ' + body.substring(0, 120) : ''}`);
  }

  const data = await res.json();
  const total = data.total || 0;
  const first = data.results?.[0];
  const isMalicious = first?.verdicts?.overall?.malicious ?? false;
  const score = first?.verdicts?.overall?.score ?? null;
  const verdict = first && isMalicious ? 'malicious' : 'clean';

  return {
    verdict, source: 'urlscan',
    data: [
      ['Scan Results', total,                                                              ''],
      ['Verdict',      first ? (isMalicious ? 'Malicious' : 'Clean') : 'No data found',  isMalicious ? 'danger' : 'success'],
      ['Risk Score',   score !== null ? score : 'N/A',                                    score > 50 ? 'danger' : score > 20 ? 'warning' : 'success'],
      ['Last Scan',    first?.task?.time ? new Date(first.task.time).toLocaleDateString() : 'N/A', ''],
    ],
  };
}

async function queryHybridAnalysis(hash, apiKey) {
  if (!apiKey) throw new Error('No API key configured');
  const res = await fetch('https://www.hybrid-analysis.com/api/v2/search/hash', {
    method: 'POST',
    headers: { 'api-key': apiKey, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `hash=${hash}`,
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);

  const data = await res.json();
  if (!data || data.length === 0) {
    return {
      verdict: 'clean', source: 'hybrid',
      data: [['Status', 'Not found in database', 'success'], ['Verdict', 'Unknown', '']],
    };
  }

  const result = data[0];
  const threatScore = result.threat_score || 0;
  const verdict = threatScore > 70 ? 'malicious' : threatScore > 30 ? 'suspicious' : 'clean';

  return {
    verdict, source: 'hybrid',
    data: [
      ['Threat Score', `${threatScore}/100`,                    threatScore > 70 ? 'danger' : threatScore > 30 ? 'warning' : 'success'],
      ['Verdict',      result.verdict              || 'Unknown', ''],
      ['AV Detections', result.av_detect           || '0',       ''],
      ['Environment',  result.environment_description || 'N/A', ''],
    ],
  };
}

async function queryMaltiverse(ioc, apiKey) {
  if (!apiKey) throw new Error('No API key configured');
  const res = await fetch(`https://api.maltiverse.com/v1/hash/${ioc}`, {
    headers: { 'Authorization': `Bearer ${apiKey}` },
  });
  if (res.status === 404) {
    return {
      verdict: 'clean', source: 'maltiverse',
      data: [['Status', 'Not found in database', 'success'], ['Classification', 'Unknown', '']],
    };
  }
  if (!res.ok) throw new Error(`HTTP ${res.status}`);

  const data = await res.json();
  const classification = data.classification || 'unknown';
  const verdict = classification === 'malicious' ? 'malicious' : classification === 'suspicious' ? 'suspicious' : 'clean';

  return {
    verdict, source: 'maltiverse',
    data: [
      ['Classification', classification.toUpperCase(), verdict === 'malicious' ? 'danger' : verdict === 'suspicious' ? 'warning' : 'success'],
      ['Score',          data.score ? `${data.score}/100` : 'N/A', ''],
      ['First Seen',     data.creation_time ? new Date(data.creation_time * 1000).toLocaleDateString() : 'N/A', ''],
    ],
  };
}

// ─── NEW OSINT API Functions ────────────────────────────────────────────────

async function queryGreyNoise(ip, apiKey) {
  if (!apiKey) throw new Error('No GreyNoise API key configured');
  const res = await fetch(`https://api.greynoise.io/v3/community/${ip}`, {
    headers: { 'key': apiKey }
  });
  if (res.status === 404) {
    return {
      verdict: 'clean', source: 'greynoise',
      data: [
        ['Classification', 'Not seen', 'success'],
        ['Noise',          'No',       'success'],
        ['RIOT',           'Unknown',  ''],
      ],
    };
  }
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();

  const classification = data.classification || 'unknown';
  const isNoise = data.noise ?? false;
  const isRiot  = data.riot  ?? false;
  const verdict = classification === 'malicious' ? 'malicious'
                : classification === 'benign'    ? 'clean'
                : isNoise ? 'suspicious' : 'clean';

  return {
    verdict, source: 'greynoise',
    data: [
      ['Classification', classification.charAt(0).toUpperCase() + classification.slice(1),
        classification === 'malicious' ? 'danger' : classification === 'benign' ? 'success' : 'warning'],
      ['Internet Noise', isNoise ? 'Yes (mass scanner)' : 'No', isNoise ? 'warning' : 'success'],
      ['RIOT (trusted)', isRiot  ? 'Yes' : 'No', isRiot ? 'success' : ''],
      ['Name',           data.name || 'Unknown', ''],
      ['Last Seen',      data.last_seen || 'N/A', ''],
    ],
  };
}

async function queryIPInfo(ip) {
  // Free, no API key needed (50k/month)
  const res = await fetch(`https://ipinfo.io/${ip}/json`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();

  const isHosting = ['amazon','google','microsoft','cloudflare','digitalocean','linode','vultr','ovh','hetzner']
    .some(h => (data.org || '').toLowerCase().includes(h));

  return {
    verdict: 'clean', source: 'ipinfo',
    data: [
      ['Organization', data.org      || 'Unknown', ''],
      ['Location',     [data.city, data.region, data.country].filter(Boolean).join(', ') || 'Unknown', ''],
      ['Hostname',     data.hostname  || 'None',    ''],
      ['Hosting/VPS',  isHosting ? 'Yes' : 'No',   isHosting ? 'warning' : ''],
      ['Timezone',     data.timezone  || 'Unknown', ''],
    ],
  };
}

async function queryBGPView(ip) {
  // Completely free, no auth ever needed
  const res = await fetch(`https://api.bgpview.io/ip/${ip}`, {
    headers: { 'Accept': 'application/json' }
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();

  const prefixes = data.data?.prefixes ?? [];
  const prefix   = prefixes[0];
  const asn      = prefix?.asn?.asn       || 'Unknown';
  const asnName  = prefix?.asn?.name      || 'Unknown';
  const asnDesc  = prefix?.asn?.description_short || '';
  const pfxCidr  = prefix?.prefix         || 'Unknown';
  const cc       = prefix?.asn?.country_code || 'Unknown';

  return {
    verdict: 'clean', source: 'bgpview',
    data: [
      ['ASN',            asn !== 'Unknown' ? `AS${asn}` : 'Unknown', ''],
      ['ASN Name',       asnName,  ''],
      ['Description',    asnDesc || asnName, ''],
      ['Prefix (CIDR)',  pfxCidr,  ''],
      ['Country',        cc,       ''],
    ],
  };
}

async function querySecurityTrails(ioc, type, apiKey) {
  if (!apiKey) throw new Error('No SecurityTrails API key configured');

  let url;
  if (type === 'domain') {
    url = `https://api.securitytrails.com/v1/domain/${ioc}`;
  } else if (type === 'ip') {
    url = `https://api.securitytrails.com/v1/ips/nearby/${ioc}`;
  } else {
    throw new Error('SecurityTrails supports domain and IP lookups only');
  }

  const res = await fetch(url, { headers: { 'apikey': apiKey } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();

  if (type === 'domain') {
    const mx  = data.current_dns?.mx?.values?.map(v => v.value).join(', ')  || 'None';
    const ns  = data.current_dns?.ns?.values?.map(v => v.value).join(', ')  || 'None';
    const a   = data.current_dns?.a?.values?.map(v => v.ip).join(', ')      || 'None';
    const sub = data.subdomain_count ?? 'Unknown';
    return {
      verdict: 'clean', source: 'securitytrails',
      data: [
        ['A Records',      a,   ''],
        ['Nameservers',    ns,  ''],
        ['MX Records',     mx,  ''],
        ['Subdomains',     sub, sub > 50 ? 'warning' : ''],
        ['Alexa Rank',     data.alexa_rank || 'Not ranked', ''],
      ],
    };
  } else {
    const nearby = data.records?.slice(0, 3).map(r => r.hostname).join(', ') || 'None';
    return {
      verdict: 'clean', source: 'securitytrails',
      data: [
        ['Nearby Domains', nearby || 'None', ''],
      ],
    };
  }
}

async function queryHIBP(email, apiKey) {
  if (!apiKey) throw new Error('No HIBP API key configured');
  const res = await fetch(
    `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`,
    {
      headers: {
        'hibp-api-key': apiKey,
        'User-Agent':   'ThreatIntelHub-Desktop',
      }
    }
  );
  if (res.status === 404) {
    return {
      verdict: 'clean', source: 'hibp',
      data: [
        ['Status',   'Not found in any breach', 'success'],
        ['Breaches', '0', 'success'],
      ],
    };
  }
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const breaches = await res.json();
  const count = breaches.length;
  const names = breaches.slice(0, 4).map(b => b.Name).join(', ');
  const latest = breaches.sort((a, b) => new Date(b.BreachDate) - new Date(a.BreachDate))[0];

  return {
    verdict: count > 0 ? 'malicious' : 'clean', source: 'hibp',
    data: [
      ['Breach Count',   count,                                         count > 5 ? 'danger' : count > 0 ? 'warning' : 'success'],
      ['Known Breaches', names || 'None',                               count > 0 ? 'danger' : ''],
      ['Latest Breach',  latest?.BreachDate || 'N/A',                   ''],
      ['Data Classes',   latest?.DataClasses?.slice(0,3).join(', ') || 'N/A', ''],
    ],
  };
}

async function queryCensys(ioc, type, apiId, apiSecret) {
  if (!apiId || !apiSecret) throw new Error('No Censys API credentials configured');
  const auth = Buffer.from(`${apiId}:${apiSecret}`).toString('base64');

  let url, body;
  if (type === 'ip') {
    url  = `https://search.censys.io/api/v2/hosts/${ioc}`;
    body = null;
  } else if (type === 'domain') {
    url  = 'https://search.censys.io/api/v2/certificates/search';
    body = JSON.stringify({ q: `parsed.names: ${ioc}`, per_page: 5 });
  } else {
    throw new Error('Censys supports IP and domain lookups only');
  }

  const options = {
    headers: { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/json' },
  };
  if (body) { options.method = 'POST'; options.body = body; }

  const res = await fetch(url, options);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();

  if (type === 'ip') {
    const result   = data.result || {};
    const services = result.services || [];
    const ports    = services.map(s => `${s.port}/${s.transport_protocol}`).slice(0,5).join(', ') || 'None';
    const labels   = result.labels?.join(', ') || 'None';
    const lastSeen = result.last_updated_at ? new Date(result.last_updated_at).toLocaleDateString() : 'N/A';
    const verdict  = labels.toLowerCase().includes('malicious') ? 'malicious'
                   : services.length > 10 ? 'suspicious' : 'clean';

    return {
      verdict, source: 'censys',
      data: [
        ['Open Ports',   ports,             services.length > 10 ? 'warning' : ''],
        ['Port Count',   services.length,   services.length > 10 ? 'warning' : 'success'],
        ['Labels',       labels,            ''],
        ['Last Updated', lastSeen,          ''],
      ],
    };
  } else {
    const hits  = data.result?.hits || [];
    const count = data.result?.total || 0;
    const certs = hits.slice(0,3).map(h => h.parsed?.subject_dn || '').filter(Boolean).join(' | ') || 'None';
    return {
      verdict: 'clean', source: 'censys',
      data: [
        ['Certificates Found', count,  ''],
        ['Subject DNs',        certs,  ''],
      ],
    };
  }
}
