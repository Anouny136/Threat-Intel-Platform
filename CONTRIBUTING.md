# Contributing to Threat Intel Hub

## Development Setup

```bash
git clone https://github.com/YOUR_USERNAME/threat-intel-hub.git
cd threat-intel-hub
npm install
npm start
```

Changes to `renderer/index.html` and `renderer/renderer.js` hot-reload when you save — just close and reopen with `npm start`.

Changes to `main.js` or `preload.js` require restarting `npm start`.

## Adding a New API Source

**1. Add the API function in `main.js`**

```javascript
async function queryMyNewSource(ioc, apiKey) {
  if (!apiKey) throw new Error('No API key configured');
  const res = await fetch(`https://api.example.com/v1/check/${ioc}`, {
    headers: { 'Authorization': `Bearer ${apiKey}` }
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();

  return {
    verdict: 'clean',           // 'clean' | 'suspicious' | 'malicious' | 'error'
    source: 'mynewsource',
    data: [
      ['Field Name', data.someValue, ''],    // ['key', value, cssClass]
      ['Risk',       data.risk,      data.risk > 50 ? 'danger' : 'success'],
    ],
  };
}
```

**2. Add a case in the switch statement in `main.js`**

```javascript
case 'mynewsource': return await queryMyNewSource(ioc, keys.mynewsource);
```

**3. Add to `SOURCE_MAP` in `renderer.js`**

```javascript
const SOURCE_MAP = {
  ip: ['virustotal', 'abuseipdb', ..., 'mynewsource'],
  // ...
};
```

**4. Add to `KEY_REQUIRED` in `renderer.js`**

```javascript
const KEY_REQUIRED = {
  // ...
  mynewsource: 'mynewsource',   // or null if no key needed
};
```

**5. Add a key input in `index.html` settings modal**

```html
<div class="api-config-group">
  <label class="api-config-label">My New Source <span class="free-badge">FREE TIER</span></label>
  <input type="password" class="api-config-input" id="key-mynewsource" placeholder="API key" />
  <p class="api-helper-text">example.com</p>
</div>
```

**6. Add to `ALL_KEYS` array in `renderer.js`**

```javascript
const ALL_KEYS = [..., 'mynewsource'];
```

**7. Add external link URL in `getSourceURL()` in `renderer.js`**

```javascript
case 'mynewsource': return `https://example.com/lookup/${ioc}`;
```

## Submitting a PR

1. Fork the repository
2. Create a branch: `git checkout -b feature/add-mynewsource`
3. Make changes, test with `npm start`
4. Commit: `git commit -m "Add MyNewSource API integration"`
5. Push: `git push origin feature/add-mynewsource`
6. Open a PR against `main`
