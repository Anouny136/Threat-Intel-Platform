let analysisResults = {};
let currentIOC      = '';
let currentIOCType  = '';
let API_KEYS        = {};
let activeTab       = 'ioc';

// ─── INIT ──────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  API_KEYS = await window.electronAPI.getAPIKeys();
  populateKeyInputs();
  renderAPIStatus();
  renderOSINTDirectory();

  document.getElementById('ioc-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') analyzeIOC();
  });
  document.getElementById('settings-modal').addEventListener('click', e => {
    if (e.target.id === 'settings-modal') closeSettings();
  });
});

// ─── TAB SWITCHING ─────────────────────────────────────────────────────────
function switchTab(tab) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  document.getElementById(`tab-btn-${tab}`).classList.add('active');
  document.getElementById(`tab-${tab}`).classList.add('active');
  activeTab = tab;
}

// ─── API KEYS ───────────────────────────────────────────────────────────────
const ALL_KEYS = [
  'virustotal','abuseipdb','hybrid','otx','shodan','maltiverse','urlscan',
  'greynoise','securitytrails','hibp','censys_id','censys_secret',
];

function populateKeyInputs() {
  ALL_KEYS.forEach(k => {
    const el = document.getElementById(`key-${k}`);
    if (el && API_KEYS[k]) el.value = API_KEYS[k];
  });
}

async function saveAPIKeys() {
  const newKeys = {};
  ALL_KEYS.forEach(k => {
    const v = document.getElementById(`key-${k}`)?.value?.trim();
    if (v) newKeys[k] = v;
  });
  API_KEYS = newKeys;
  await window.electronAPI.saveAPIKeys(newKeys);
  renderAPIStatus();
  closeSettings();
  showToast('API keys saved successfully', 'success');
}

function renderAPIStatus() {
  const apis = [
    { name: 'VirusTotal',      key: 'virustotal',  premium: false },
    { name: 'AbuseIPDB',       key: 'abuseipdb',   premium: false },
    { name: 'Hybrid Analysis', key: 'hybrid',      premium: false },
    { name: 'AlienVault OTX',  key: 'otx',         premium: false },
    { name: 'Shodan',          key: 'shodan',       premium: true  },
    { name: 'Maltiverse',      key: 'maltiverse',  premium: false },
    { name: 'URLScan.io',      key: 'urlscan',     premium: false },
    { name: 'GreyNoise',       key: 'greynoise',   premium: false },
    { name: 'SecurityTrails',  key: 'securitytrails', premium: false },
    { name: 'HIBP',            key: 'hibp',        premium: false },
    { name: 'Censys',          key: 'censys_id',   premium: false },
    { name: 'IPInfo',          key: null,           premium: false }, // no key
    { name: 'BGPView',         key: null,           premium: false }, // no key
  ];
  document.getElementById('api-status').innerHTML = apis.map(api => `
    <div class="api-status-card ${api.premium ? 'premium' : ''}">
      <span class="api-name">${api.name}</span>
      <div class="api-dot ${api.key === null || API_KEYS[api.key] ? 'active' : ''}"></div>
    </div>`).join('');
}

function openSettings()  { document.getElementById('settings-modal').classList.add('active'); }
function closeSettings() { document.getElementById('settings-modal').classList.remove('active'); }

// ─── IOC TYPE DETECTION ─────────────────────────────────────────────────────
function detectIOCType(ioc) {
  ioc = ioc.trim();
  if (/^https?:\/\//i.test(ioc)) return 'url';
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(ioc)) return 'ip';
  if (/^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$/.test(ioc)) return 'hash';
  if (/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(ioc)) return 'email';
  if (/^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$/.test(ioc)) return 'domain';
  return 'unknown';
}

// ─── SOURCE URLS ────────────────────────────────────────────────────────────
function getSourceURL(source, ioc, type) {
  switch (source) {
    case 'virustotal':
      if (type === 'ip')     return `https://www.virustotal.com/gui/ip-address/${ioc}`;
      if (type === 'domain') return `https://www.virustotal.com/gui/domain/${ioc}`;
      if (type === 'hash')   return `https://www.virustotal.com/gui/file/${ioc}`;
      if (type === 'url')    return `https://www.virustotal.com/gui/url/${btoa(ioc).replace(/=+$/,'')}`;
      break;
    case 'abuseipdb':      return `https://www.abuseipdb.com/check/${ioc}`;
    case 'shodan':         return `https://www.shodan.io/host/${ioc}`;
    case 'greynoise':      return `https://viz.greynoise.io/ip/${ioc}`;
    case 'ipinfo':         return `https://ipinfo.io/${ioc}`;
    case 'bgpview':        return `https://bgpview.io/ip/${ioc}`;
    case 'censys':
      if (type === 'ip')     return `https://search.censys.io/hosts/${ioc}`;
      if (type === 'domain') return `https://search.censys.io/search?resource=hosts&q=${ioc}`;
      break;
    case 'otx':
      if (type === 'ip')     return `https://otx.alienvault.com/indicator/ip/${ioc}`;
      if (type === 'domain') return `https://otx.alienvault.com/indicator/domain/${ioc}`;
      if (type === 'hash')   return `https://otx.alienvault.com/indicator/file/${ioc}`;
      break;
    case 'urlscan':        return `https://urlscan.io/search/#${encodeURIComponent(ioc)}`;
    case 'hybrid':         return `https://www.hybrid-analysis.com/search?query=${encodeURIComponent(ioc)}`;
    case 'maltiverse':     return `https://maltiverse.com/search;query=${encodeURIComponent(ioc)}`;
    case 'securitytrails':
      if (type === 'domain') return `https://securitytrails.com/domain/${ioc}/dns`;
      if (type === 'ip')     return `https://securitytrails.com/list/ip/${ioc}`;
      break;
    case 'hibp':           return `https://haveibeenpwned.com/`;
  }
  return null;
}

function openLink(url) { if (url) window.electronAPI.openExternal(url); }

// ─── SOURCE MAP (which APIs to query per IOC type) ──────────────────────────
const SOURCE_MAP = {
  ip:     ['virustotal','abuseipdb','greynoise','ipinfo','bgpview','shodan','otx','censys'],
  domain: ['virustotal','otx','urlscan','securitytrails','censys'],
  hash:   ['virustotal','hybrid','maltiverse'],
  url:    ['virustotal','urlscan'],
  email:  ['hibp'],
};

// Keys required (null = no key needed)
const KEY_REQUIRED = {
  virustotal: 'virustotal', abuseipdb: 'abuseipdb', shodan: 'shodan',
  otx: 'otx', urlscan: 'urlscan', hybrid: 'hybrid', maltiverse: 'maltiverse',
  greynoise: 'greynoise', securitytrails: 'securitytrails', hibp: 'hibp',
  censys: 'censys_id',
  ipinfo: null, bgpview: null,
};

function sourceHasKey(source) {
  const req = KEY_REQUIRED[source];
  return req === null || !!API_KEYS[req];
}

// ─── ANALYZE IOC ───────────────────────────────────────────────────────────
async function analyzeIOC() {
  const ioc = document.getElementById('ioc-input').value.trim();
  if (!ioc) return;

  let type = document.getElementById('ioc-type').value;
  if (type === 'auto') type = detectIOCType(ioc);
  if (type === 'unknown') { showToast('Could not detect IOC type. Select manually.', 'error'); return; }

  currentIOC      = ioc;
  currentIOCType  = type;
  analysisResults = {};

  const btn = document.getElementById('analyze-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Scanning…';
  document.getElementById('download-report-btn').disabled = true;

  const sources = (SOURCE_MAP[type] || []).filter(s => sourceHasKey(s));

  if (sources.length === 0) {
    document.getElementById('results-ioc').innerHTML = `
      <div class="empty-state" style="grid-column:1/-1;">
        <div class="empty-icon">⚙</div>
        <p style="color:var(--accent-orange);">No API keys configured for ${type.toUpperCase()} analysis</p>
        <p style="font-size:13px;margin-top:8px;">Click ⚙ API Settings to add keys</p>
      </div>`;
    btn.disabled = false; btn.innerHTML = '<span>⚡ Analyze</span>';
    return;
  }

  document.getElementById('overview-ioc').style.display = 'none';
  document.getElementById('results-ioc').innerHTML = sources.map(s => loadingCard(s)).join('');

  await Promise.allSettled(
    sources.map(source =>
      window.electronAPI.queryAPI({ source, ioc, type }).then(result => updateCard(source, result, type))
    )
  );

  renderOverview('ioc', analysisResults);
  btn.disabled = false; btn.innerHTML = '<span>⚡ Analyze</span>';
  document.getElementById('download-report-btn').disabled = false;
}

// ─── ANALYZE FILE ──────────────────────────────────────────────────────────
async function analyzeFile() {
  const fileInput = document.getElementById('file-input');
  if (!fileInput.files?.[0]) { showToast('Please select a file first', 'error'); return; }

  const file = fileInput.files[0];
  const btn  = document.getElementById('analyze-file-btn');
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Hashing…';
  document.getElementById('download-report-btn').disabled = true;

  try {
    const hash = await hashFileSHA256(file);
    currentIOC = hash; currentIOCType = 'hash'; analysisResults = {};

    const sources = (SOURCE_MAP['hash'] || []).filter(s => sourceHasKey(s));
    if (sources.length === 0) { showToast('Configure VirusTotal, Hybrid Analysis, or Maltiverse keys first', 'error'); return; }

    document.getElementById('overview-file').style.display = 'none';
    document.getElementById('results-file').innerHTML = `
      <div class="result-card">
        <div class="verdict-bar" style="background:var(--accent-cyan)"></div>
        <div class="card-header">
          <div class="card-header-left"><span class="source-name">📁 FILE INFO</span></div>
          <span class="verdict-badge verdict-clean">LOCAL HASH</span>
        </div>
        <div class="card-body">
          <div class="data-row"><span class="data-key">Filename</span><span class="data-value">${file.name}</span></div>
          <div class="data-row"><span class="data-key">Size</span><span class="data-value">${(file.size/1024).toFixed(2)} KB</span></div>
          <div class="data-row"><span class="data-key">SHA-256</span><span class="data-value" style="font-size:10px;">${hash}</span></div>
        </div>
      </div>
      ${sources.map(s => loadingCard(s)).join('')}`;

    btn.innerHTML = '<span class="spinner"></span> Querying APIs…';
    await Promise.allSettled(
      sources.map(s =>
        window.electronAPI.queryAPI({ source: s, ioc: hash, type: 'hash' }).then(r => updateCard(s, r, 'hash'))
      )
    );

    renderOverview('file', analysisResults);
    document.getElementById('download-report-btn').disabled = false;
  } catch (err) {
    showToast('Error: ' + err.message, 'error');
  } finally {
    btn.disabled = false; btn.innerHTML = '<span>🔍 Analyze File</span>';
  }
}

async function hashFileSHA256(file) {
  const buf = await file.arrayBuffer();
  const h   = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(h)).map(b => b.toString(16).padStart(2,'0')).join('');
}

// ─── CARD RENDERING ────────────────────────────────────────────────────────
function loadingCard(source) {
  return `
    <div class="result-card scanning" id="card-${source}">
      <div class="verdict-bar" style="background:var(--text-muted)"></div>
      <div class="card-header">
        <div class="card-header-left"><span class="source-name">${source.toUpperCase()}</span></div>
        <span class="verdict-badge verdict-loading"><span class="spinner"></span> QUERYING</span>
      </div>
      <div class="card-body">
        <div class="data-row"><span class="data-key">Status</span><span class="data-value">Contacting API…</span></div>
      </div>
    </div>`;
}

function updateCard(source, result, type) {
  const card = document.getElementById(`card-${source}`);
  if (!card) return;

  const { verdict = 'error', data = [] } = result;
  card.classList.remove('scanning');

  const cls = { malicious:'verdict-malicious', suspicious:'verdict-suspicious', clean:'verdict-clean', error:'verdict-error' }[verdict] || 'verdict-loading';
  const bar = { malicious:'var(--accent-red)', suspicious:'var(--accent-orange)', clean:'var(--accent-green)', error:'var(--text-muted)' }[verdict] || 'var(--text-muted)';

  const url = getSourceURL(source, currentIOC, type || currentIOCType);
  const linkBtn = url
    ? `<button class="ext-link-btn" onclick="openLink('${url}')">↗ View on Site</button>`
    : '';

  card.innerHTML = `
    <div class="verdict-bar" style="background:${bar}"></div>
    <div class="card-header">
      <div class="card-header-left"><span class="source-name">${source.toUpperCase()}</span></div>
      <div class="card-header-right">
        <span class="verdict-badge ${cls}">${verdict.toUpperCase()}</span>
        ${linkBtn}
      </div>
    </div>
    <div class="card-body">
      ${data.map(([k,v,vc]) => `
        <div class="data-row">
          <span class="data-key">${k}</span>
          <span class="data-value ${vc||''}">${v}</span>
        </div>`).join('')}
    </div>`;

  analysisResults[source] = { verdict, data };
}

// ─── OVERVIEW PANEL ────────────────────────────────────────────────────────
function renderOverview(tab, results) {
  const panel = document.getElementById(`overview-${tab}`);
  if (!panel) return;

  const entries     = Object.values(results);
  const total       = entries.length;
  const malicious   = entries.filter(r => r.verdict === 'malicious').length;
  const suspicious  = entries.filter(r => r.verdict === 'suspicious').length;
  const clean       = entries.filter(r => r.verdict === 'clean').length;
  const errored     = entries.filter(r => r.verdict === 'error').length;
  const scored      = total - errored;
  const threatScore = scored > 0 ? Math.round((malicious + suspicious * 0.5) / scored * 100) : 0;

  let ov = 'CLEAN', vColor = '#10b981', vBg = 'rgba(16,185,129,0.12)', vBorder = 'rgba(16,185,129,0.3)';
  if (malicious > 0)  { ov = 'MALICIOUS';  vColor = '#ef4444'; vBg = 'rgba(239,68,68,0.12)';   vBorder = 'rgba(239,68,68,0.35)'; }
  else if (suspicious > 0) { ov = 'SUSPICIOUS'; vColor = '#f97316'; vBg = 'rgba(249,115,22,0.12)'; vBorder = 'rgba(249,115,22,0.3)'; }

  const R  = 62, CX = 78, CY = 78, SW = 13;
  const circ = 2 * Math.PI * R;
  const segs = [
    { count: malicious,  color: '#ef4444' },
    { count: suspicious, color: '#f97316' },
    { count: clean,      color: '#10b981' },
    { count: errored,    color: '#475569' },
  ];
  let cum = 0;
  const segSVG = segs.filter(s => s.count > 0).map(seg => {
    const frac = seg.count / total;
    const dash = frac * circ, gap = circ - dash;
    const rot  = cum * 360 - 90;
    cum += frac;
    return `<circle cx="${CX}" cy="${CY}" r="${R}" fill="none" stroke="${seg.color}" stroke-width="${SW}"
      stroke-dasharray="${dash.toFixed(2)} ${gap.toFixed(2)}"
      transform="rotate(${rot.toFixed(2)} ${CX} ${CY})" stroke-linecap="butt"/>`;
  }).join('');

  const sColor = threatScore >= 75 ? '#ef4444' : threatScore >= 40 ? '#f97316' : '#10b981';
  const bars = [
    { label:'Malicious',  count:malicious,  color:'#ef4444', pct:total>0?malicious/total*100:0 },
    { label:'Suspicious', count:suspicious, color:'#f97316', pct:total>0?suspicious/total*100:0 },
    { label:'Clean',      count:clean,      color:'#10b981', pct:total>0?clean/total*100:0 },
  ].map(b => `
    <div class="breakdown-row">
      <span class="breakdown-name">${b.label}</span>
      <div class="breakdown-bar-wrap"><div class="breakdown-bar" style="width:${b.pct}%;background:${b.color}"></div></div>
      <span class="breakdown-count" style="color:${b.color}">${b.count}</span>
    </div>`).join('');

  panel.innerHTML = `
    <div class="overview-inner">
      <div class="donut-wrap">
        <svg width="156" height="156" viewBox="0 0 156 156">
          <circle cx="${CX}" cy="${CY}" r="${R}" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="${SW}"/>
          ${segSVG}
        </svg>
        <div class="donut-center">
          <div class="donut-score" style="color:${sColor}">${threatScore}</div>
          <div class="donut-label">THREAT<br>SCORE</div>
        </div>
      </div>
      <div class="overview-details">
        <div class="overall-verdict-row">
          <div class="overall-verdict-badge" style="color:${vColor};background:${vBg};border:1px solid ${vBorder}">${ov}</div>
          <div>
            <div style="font-size:12px;color:var(--text-muted);font-family:'Space Mono',monospace;letter-spacing:1px;">OVERALL VERDICT</div>
            <div style="font-size:12px;color:var(--text-secondary);margin-top:2px;">${total} sources queried</div>
          </div>
        </div>
        <div class="breakdown-bars">${bars}</div>
      </div>
      <div class="source-stats">
        <div class="stat-pill"><div class="stat-pill-value" style="color:var(--accent-cyan)">${total}</div><div class="stat-pill-label">Sources</div></div>
        <div class="stat-pill"><div class="stat-pill-value" style="color:#ef4444">${malicious}</div><div class="stat-pill-label">Malicious</div></div>
        <div class="stat-pill"><div class="stat-pill-value" style="color:#10b981">${clean}</div><div class="stat-pill-label">Clean</div></div>
      </div>
    </div>`;

  panel.style.display = 'block';
}

// ─── PDF REPORT ────────────────────────────────────────────────────────────
async function downloadReport() {
  if (!currentIOC || Object.keys(analysisResults).length === 0) {
    showToast('No results to export. Run an analysis first.', 'error'); return;
  }
  const btn = document.getElementById('download-report-btn');
  btn.disabled = true; btn.textContent = '⏳ Generating…';
  showToast('Generating PDF report…', 'info');
  try {
    const result = await window.electronAPI.generateReport({
      ioc: currentIOC, results: analysisResults, iocType: currentIOCType,
    });
    if (result.success) showToast('Report saved and opened!', 'success');
    else showToast('Cancelled.', 'error');
  } catch (err) {
    showToast('Error: ' + err.message, 'error');
  } finally {
    btn.disabled = false; btn.textContent = '📄 Download Report';
  }
}

// ─── OSINT TOOL DIRECTORY ──────────────────────────────────────────────────
const OSINT_TOOLS = [
  {
    category: 'Infrastructure & Network',
    icon: '🌐',
    color: '#00f5ff',
    tools: [
      { name: 'Shodan',      desc: 'Internet-connected device search. Indexes ports, banners, SSL certs, IoT, ICS/SCADA.', url: 'https://www.shodan.io', free: false, tier: 'Paid' },
      { name: 'Censys',      desc: 'Host and certificate search engine. Best for attack surface mapping and cert tracking.', url: 'https://search.censys.io', free: true, tier: 'Freemium' },
      { name: 'GreyNoise',   desc: 'Classifies IPs as internet noise vs targeted attacks. Reduces false positives in SIEM.', url: 'https://viz.greynoise.io', free: true, tier: 'Freemium' },
      { name: 'ZoomEye',     desc: 'Chinese Shodan alternative. Broad global coverage, good for finding exposed services.', url: 'https://www.zoomeye.hk', free: true, tier: 'Freemium' },
      { name: 'BGPView',     desc: 'ASN routing, prefix data, and IP-to-ASN mapping. Completely free, no account needed.', url: 'https://bgpview.io', free: true, tier: 'Free' },
      { name: 'Netlas',      desc: 'Internet intelligence platform. Scans all IPv4, tracks changes over time.', url: 'https://netlas.io', free: true, tier: 'Freemium' },
    ]
  },
  {
    category: 'Threat Intelligence',
    icon: '🛡️',
    color: '#ef4444',
    tools: [
      { name: 'VirusTotal',    desc: 'Aggregates 70+ AV engines and sandbox results. Gold standard for file, hash, IP, domain, URL.', url: 'https://www.virustotal.com', free: true, tier: 'Freemium' },
      { name: 'MalwareBazaar', desc: 'Free malware sample repository by Abuse.ch. Search by hash, tag, signature, YARA.', url: 'https://bazaar.abuse.ch', free: true, tier: 'Free' },
      { name: 'ThreatFox',     desc: 'IOC database from Abuse.ch. Fresh C2 indicators, malware families, and TTPs.', url: 'https://threatfox.abuse.ch', free: true, tier: 'Free' },
      { name: 'URLhaus',       desc: 'Tracks malicious URLs used for malware distribution. Submit and query in real time.', url: 'https://urlhaus.abuse.ch', free: true, tier: 'Free' },
      { name: 'AlienVault OTX',desc: 'Community threat feeds (pulses). IPs, domains, hashes tied to threat actors and campaigns.', url: 'https://otx.alienvault.com', free: true, tier: 'Free' },
      { name: 'Feodo Tracker', desc: 'Tracks Dridex, Emotet, TrickBot, QakBot, Bazarloader botnet C2 servers.', url: 'https://feodotracker.abuse.ch', free: true, tier: 'Free' },
    ]
  },
  {
    category: 'Domain & DNS Analysis',
    icon: '🔍',
    color: '#a855f7',
    tools: [
      { name: 'SecurityTrails',  desc: 'Full DNS history, subdomain discovery, WHOIS history. Best for domain pivot analysis.', url: 'https://securitytrails.com', free: true, tier: 'Freemium' },
      { name: 'DNSDumpster',     desc: 'Free DNS recon. Finds hosts, MX, TXT, subdomains without brute-forcing.', url: 'https://dnsdumpster.com', free: true, tier: 'Free' },
      { name: 'ViewDNS',         desc: 'Suite of DNS tools: reverse IP, WHOIS, port scan, IP history, propagation checker.', url: 'https://viewdns.info', free: true, tier: 'Freemium' },
      { name: 'Robtex',          desc: 'Network tool aggregating DNS, BGP, ASN, and WHOIS into one view. Good for pivoting.', url: 'https://www.robtex.com', free: true, tier: 'Free' },
      { name: 'Passive DNS (DNSDB)', desc: 'Farsight DNSDB — largest passive DNS database. Essential for historical domain tracking.', url: 'https://www.farsightsecurity.com/solutions/dnsdb', free: false, tier: 'Paid' },
      { name: 'URLScan.io',      desc: 'Scans and screenshots URLs. Shows loaded resources, network calls, DOM changes.', url: 'https://urlscan.io', free: true, tier: 'Freemium' },
    ]
  },
  {
    category: 'Search & OSINT Frameworks',
    icon: '🕸️',
    color: '#f97316',
    tools: [
      { name: 'Maltego',         desc: 'Link analysis and data visualization. Maps relationships between entities. Industry standard.', url: 'https://www.maltego.com', free: true, tier: 'Freemium' },
      { name: 'SpiderFoot',      desc: 'Automated recon across 200+ data sources. Self-hosted (free) or cloud (paid). Best all-rounder.', url: 'https://www.spiderfoot.net', free: true, tier: 'Freemium' },
      { name: 'OSINT Framework', desc: 'Curated directory of 300+ OSINT tools organized by category. Essential starting point.', url: 'https://osintframework.com', free: true, tier: 'Free' },
      { name: 'IntelligenceX',   desc: 'Search engine for leaked data, dark web, Tor, I2P, Pastebin, and historical web data.', url: 'https://intelx.io', free: true, tier: 'Freemium' },
      { name: 'Recon-ng',        desc: 'Web reconnaissance framework. Modular, CLI-based, integrates with many data sources.', url: 'https://github.com/lanmaster53/recon-ng', free: true, tier: 'Free' },
      { name: 'SOCRadar Labs',   desc: 'Free browser-based OSINT hub: IP/domain reputation, WHOIS, dark web search, IOC enrichment.', url: 'https://socradar.io/labs', free: true, tier: 'Free' },
    ]
  },
  {
    category: 'Breach & Credential Intelligence',
    icon: '🔓',
    color: '#ec4899',
    tools: [
      { name: 'HaveIBeenPwned',  desc: 'Checks email addresses against 800+ breach databases. API available, trusted globally.', url: 'https://haveibeenpwned.com', free: true, tier: 'Freemium' },
      { name: 'DeHashed',        desc: 'Credential search across breach datasets. Useful for finding leaked passwords and emails.', url: 'https://dehashed.com', free: false, tier: 'Paid' },
      { name: 'LeakCheck',       desc: 'Email and username breach search. Covers 7B+ records across 9000+ sources.', url: 'https://leakcheck.io', free: true, tier: 'Freemium' },
      { name: 'IntelligenceX',   desc: 'Indexes leaked databases including email, password, and PII dumps from major breaches.', url: 'https://intelx.io', free: true, tier: 'Freemium' },
      { name: 'Snusbase',        desc: 'Real-time breach database lookup. Username, email, IP, hash, and password search.', url: 'https://snusbase.com', free: false, tier: 'Paid' },
    ]
  },
  {
    category: 'Social Media & Identity',
    icon: '👤',
    color: '#10b981',
    tools: [
      { name: 'Sherlock',        desc: 'Hunt usernames across 300+ social networks. CLI tool, Python-based, widely trusted.', url: 'https://github.com/sherlock-project/sherlock', free: true, tier: 'Free' },
      { name: 'Maigret',         desc: 'Username OSINT across 3000+ sites. More coverage than Sherlock, also checks dark web.', url: 'https://github.com/soxoj/maigret', free: true, tier: 'Free' },
      { name: 'Social-Searcher', desc: 'Real-time social media monitoring. Track keywords, mentions, sentiment across platforms.', url: 'https://www.social-searcher.com', free: true, tier: 'Freemium' },
      { name: 'Namechk',         desc: 'Username and domain availability checker across 100+ platforms. Fast and free.', url: 'https://namechk.com', free: true, tier: 'Free' },
    ]
  },
  {
    category: 'Automated Recon',
    icon: '🤖',
    color: '#0ea5e9',
    tools: [
      { name: 'theHarvester',  desc: 'Passive email, subdomain, and name harvesting from public sources. Pre-installed in Kali.', url: 'https://github.com/laramies/theHarvester', free: true, tier: 'Free' },
      { name: 'Amass',         desc: 'OWASP subdomain enumeration. Active and passive, integrates 50+ data sources. Best in class.', url: 'https://github.com/owasp-amass/amass', free: true, tier: 'Free' },
      { name: 'Subfinder',     desc: 'Fast passive subdomain discovery. Integrates with Certificate Transparency, Shodan, and more.', url: 'https://github.com/projectdiscovery/subfinder', free: true, tier: 'Free' },
      { name: 'Nuclei',        desc: 'Fast vulnerability scanner using community templates. Finds misconfigs, CVEs, exposed panels.', url: 'https://github.com/projectdiscovery/nuclei', free: true, tier: 'Free' },
    ]
  },
  {
    category: 'Dark Web Monitoring',
    icon: '🌑',
    color: '#64748b',
    tools: [
      { name: 'Ahmia',         desc: 'Clearnet search engine for Tor .onion sites. Filters illegal content. Good for quick dark web recon.', url: 'https://ahmia.fi', free: true, tier: 'Free' },
      { name: 'DarkSearch',    desc: 'Dark web search engine indexing Tor sites. Updated frequently, API available.', url: 'https://darksearch.io', free: true, tier: 'Freemium' },
      { name: 'SOCRadar Dark', desc: 'Dark web threat intelligence covering markets, forums, Telegram, Ransomware groups.', url: 'https://socradar.io', free: false, tier: 'Paid' },
      { name: 'IntelligenceX', desc: 'Indexes dark web, I2P, Tor, and Freenet alongside surface web leaked data.', url: 'https://intelx.io', free: true, tier: 'Freemium' },
    ]
  },
];

function renderOSINTDirectory() {
  const container = document.getElementById('osint-directory');
  if (!container) return;

  container.innerHTML = OSINT_TOOLS.map(cat => `
    <div class="osint-category">
      <div class="osint-cat-header">
        <span class="osint-cat-icon">${cat.icon}</span>
        <span class="osint-cat-name" style="color:${cat.color}">${cat.category}</span>
        <span class="osint-cat-count">${cat.tools.length} tools</span>
      </div>
      <div class="osint-tools-grid">
        ${cat.tools.map(tool => `
          <div class="osint-tool-card" onclick="openLink('${tool.url}')">
            <div class="osint-tool-top">
              <span class="osint-tool-name">${tool.name}</span>
              <span class="osint-tier-badge ${tool.free ? 'tier-free' : 'tier-paid'}">${tool.tier}</span>
            </div>
            <p class="osint-tool-desc">${tool.desc}</p>
            <div class="osint-tool-link">↗ Open Tool</div>
          </div>`).join('')}
      </div>
    </div>`).join('');
}

// ─── TOAST ────────────────────────────────────────────────────────────────
function showToast(message, type = 'info') {
  document.querySelector('.toast')?.remove();
  const icons = { success:'✅', error:'❌', info:'ℹ️' };
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.innerHTML = `<span>${icons[type]||'ℹ️'}</span><span>${message}</span>`;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 3500);
}
