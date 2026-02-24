// ═══════════════════════════════════════════════════════════════
//  Render Shield Proxy v2.0
//  Lightweight Cloudflare-like reverse proxy for Render.com
// ═══════════════════════════════════════════════════════════════

const express = require('express');
const { Agent } = require('undici');
const crypto = require('crypto');
const { Readable } = require('stream');

const app = express();
const PORT = process.env.PORT || 10000;
const SECRET = process.env.SECRET || crypto.randomBytes(32).toString('hex');
const CONFIG_URL = process.env.CONFIG_URL;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';
const CONFIG_INTERVAL = 5 * 60_000;

// ═══════════════════════════════════════════════════════════════
//  MEMORY LIMITS
// ═══════════════════════════════════════════════════════════════

const CACHE_MAX_BYTES = 15 * 1024 * 1024;   // 15MB total
const CACHE_MAX_ITEM  = 50 * 1024;           // 50KB per item
const CACHE_TTL       = 3600_000;            // 1h
const STREAM_THRESHOLD = 512 * 1024;         // >512KB → stream
const RATE_MAP_MAX    = 5000;
const CLEANUP_INTERVAL = 30_000;

// ═══════════════════════════════════════════════════════════════
//  STATE
// ═══════════════════════════════════════════════════════════════

let domainMap = new Map();
let configLoaded = false;
let attackMode = false;

let sec = {
    blocked_ips: [], blocked_cidrs: [], blocked_ua: [],
    allowed_ips: [],
    rate_limit: { window_s: 60, max: 100 },
    waf: true,
    challenge: { mode: 'off', type: 'js', duration_h: 24 },
    hcaptcha_sitekey: '', hcaptcha_secret: '',
    security_headers: true,
};

const stats = { req: 0, blocked: 0, challenged: 0, cached: 0, waf: 0 };
const cache = new Map();
let cacheBytes = 0;
const rateMap = new Map();
const agents = new Map();

// ═══════════════════════════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════════════════════════

const hmac = (d) => crypto.createHmac('sha256', SECRET).update(d).digest('hex');

function clientIP(req) {
    return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.ip || '0.0.0.0';
}

function ip2num(ip) {
    return ip.split('.').reduce((a, o) => (a << 8) + (+o), 0) >>> 0;
}

function cidrMatch(ip, cidr) {
    const [range, bits] = cidr.split('/');
    if (!bits) return ip === range;
    const mask = ~(2 ** (32 - +bits) - 1) >>> 0;
    return (ip2num(ip) & mask) === (ip2num(range) & mask);
}

function parseCookie(str, name) {
    if (!str) return null;
    const m = str.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
    return m ? m[1] : null;
}

function getAgent(host) {
    let a = agents.get(host);
    if (!a) {
        a = new Agent({
            connect: { rejectUnauthorized: false, servername: host },
            connections: 4, pipelining: 1,
            bodyTimeout: 30_000, headersTimeout: 30_000,
        });
        agents.set(host, a);
    }
    return a;
}

function originFetch(target, path, opts = {}) {
    return fetch(target.origin + path, {
        ...opts,
        dispatcher: getAgent(target.host),
        headers: { Host: target.host, 'Accept-Encoding': 'identity', ...(opts.headers || {}) },
    });
}

// ═══════════════════════════════════════════════════════════════
//  CACHE (byte-limited)
// ═══════════════════════════════════════════════════════════════

function cacheGet(key) {
    const it = cache.get(key);
    if (!it) return null;
    if (Date.now() - it.ts > CACHE_TTL) { cacheBytes -= it.data.length; cache.delete(key); return null; }
    return it;
}

function cacheSet(key, data, type) {
    if (data.length > CACHE_MAX_ITEM) return;
    while (cacheBytes + data.length > CACHE_MAX_BYTES && cache.size) {
        const k = cache.keys().next().value;
        cacheBytes -= cache.get(k).data.length;
        cache.delete(k);
    }
    cache.set(key, { data, type, ts: Date.now() });
    cacheBytes += data.length;
}

// ═══════════════════════════════════════════════════════════════
//  RATE LIMITING
// ═══════════════════════════════════════════════════════════════

function rateOk(ip) {
    const now = Date.now(), win = (sec.rate_limit.window_s || 60) * 1000;
    let e = rateMap.get(ip);
    if (!e || now - e.ts > win) { e = { c: 0, ts: now }; rateMap.set(ip, e); }
    e.c++;
    return e.c <= (sec.rate_limit.max || 100);
}

// ═══════════════════════════════════════════════════════════════
//  WAF
// ═══════════════════════════════════════════════════════════════

const WAF_RE = [
    /(\b(union\s+select|insert\s+into|drop\s+table|delete\s+from|update\s+.+\s+set)\b)/i,
    /(['"];?\s*(drop|delete|update|insert|alter)\b)/i,
    /(\bor\b|\band\b)\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i,
    /<script[\s>]/i, /javascript\s*:/i,
    /on(error|load|click|mouse|focus|blur)\s*=/i,
    /\.\.[\/\\]/, /%2e%2e[\/\\%]/i,
    /;\s*(ls|cat|rm|wget|curl|bash|sh|python|perl|nc)\b/i,
    /\|\s*(ls|cat|rm|wget|curl|bash|sh)\b/i,
];

function wafOk(req) {
    if (!sec.waf) return true;
    try {
        const s = decodeURIComponent(req.originalUrl);
        return !WAF_RE.some(r => r.test(s));
    } catch { return true; }
}

// ═══════════════════════════════════════════════════════════════
//  BOT DETECTION
// ═══════════════════════════════════════════════════════════════

const DEFAULT_BOTS = [
    'semrushbot','ahrefsbot','mj12bot','dotbot','blexbot','petalbot',
    'bytespider','gptbot','ccbot','dataforseobot','sogou','baiduspider',
    'claudebot','anthropic','opensiteexplorer','screaming frog',
];

function isBot(ua) {
    if (!ua) return true; // empty UA = suspicious
    const low = ua.toLowerCase();
    const list = sec.blocked_ua.length ? sec.blocked_ua : DEFAULT_BOTS;
    return list.some(b => low.includes(b.toLowerCase()));
}

// ═══════════════════════════════════════════════════════════════
//  CHALLENGE / CAPTCHA
// ═══════════════════════════════════════════════════════════════

const COOKIE_NAME = '__rv';

function makeVerifyCookie(ip) {
    const exp = Date.now() + (sec.challenge.duration_h || 24) * 3600_000;
    return `${hmac(ip + ':' + exp)}:${exp}`;
}

function cookieValid(req) {
    const ip = clientIP(req);
    const val = parseCookie(req.headers.cookie, COOKIE_NAME);
    if (!val) return false;
    const [sig, exp] = val.split(':');
    if (!sig || !exp || Date.now() > +exp) return false;
    return sig === hmac(ip + ':' + exp);
}

function shouldChallenge(req) {
    if (/\.(js|css|png|jpe?g|gif|ico|svg|woff2?|ttf|eot|map|webp|avif)$/i.test(req.path)) return false;
    if (req.path.startsWith('/__')) return false;
    if (cookieValid(req)) return false;
    if (attackMode || sec.challenge.mode === 'all') return true;
    if (sec.challenge.mode === 'suspicious') return isBot(req.get('User-Agent'));
    return false;
}

// ─── Challenge Pages ───

function jsChallengePage(url) {
    const a = Math.floor(Math.random() * 1000);
    const b = Math.floor(Math.random() * 1000);
    const ts = Date.now();
    const ans = a * a + b * b + a * b;
    const tok = hmac(`${a}:${b}:${ts}:${ans}`);
    const redir = encodeURIComponent(url);
    return `<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Checking your browser…</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;background:#f0f2f5}.c{background:#fff;padding:48px;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.08);text-align:center;max-width:400px}.s{width:48px;height:48px;border:4px solid #e0e0e0;border-top:4px solid #1a73e8;border-radius:50%;animation:r 1s linear infinite;margin:0 auto 24px}@keyframes r{to{transform:rotate(360deg)}}h2{color:#202124;margin-bottom:8px}p{color:#5f6368;font-size:14px}</style></head>
<body><div class="c"><div class="s"></div><h2>Checking your browser</h2><p>This will only take a moment…</p>
<form id="f" method="POST" action="/__verify"><input type="hidden" name="a" value="${a}"><input type="hidden" name="b" value="${b}"><input type="hidden" name="ts" value="${ts}"><input type="hidden" name="tok" value="${tok}"><input type="hidden" name="ans" id="a"><input type="hidden" name="r" value="${redir}"></form>
<script>document.getElementById('a').value=${a}*${a}+${b}*${b}+${a}*${b};setTimeout(()=>document.getElementById('f').submit(),3e3)</script>
</div></body></html>`;
}

function mathCaptchaPage(url) {
    const a = 1 + Math.floor(Math.random() * 20);
    const b = 1 + Math.floor(Math.random() * 20);
    const ts = Date.now();
    const ans = a + b;
    const tok = hmac(`${a}:${b}:${ts}:${ans}`);
    const redir = encodeURIComponent(url);
    return `<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Check</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;background:#f0f2f5}.c{background:#fff;padding:48px;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.08);text-align:center;max-width:400px}h2{color:#202124;margin-bottom:16px}p{color:#5f6368;margin-bottom:16px}input[type=number]{font-size:24px;width:100px;text-align:center;padding:8px;border:2px solid #dadce0;border-radius:8px;outline:none}input:focus{border-color:#1a73e8}button{margin-top:16px;font-size:16px;padding:10px 32px;background:#1a73e8;color:#fff;border:none;border-radius:8px;cursor:pointer}button:hover{background:#1557b0}</style></head>
<body><div class="c"><h2>Security Check</h2><p>What is <b>${a} + ${b}</b> ?</p>
<form method="POST" action="/__verify"><input type="hidden" name="a" value="${a}"><input type="hidden" name="b" value="${b}"><input type="hidden" name="ts" value="${ts}"><input type="hidden" name="tok" value="${tok}"><input type="number" name="ans" autofocus required><input type="hidden" name="r" value="${redir}"><br><button type="submit">Verify</button></form>
</div></body></html>`;
}

function hcaptchaPage(url) {
    const redir = encodeURIComponent(url);
    return `<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Check</title>
<script src="https://js.hcaptcha.com/1/api.js" async defer></script>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;background:#f0f2f5}.c{background:#fff;padding:48px;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.08);text-align:center;max-width:400px}h2{margin-bottom:16px}button{margin-top:16px;font-size:16px;padding:10px 32px;background:#1a73e8;color:#fff;border:none;border-radius:8px;cursor:pointer}</style></head>
<body><div class="c"><h2>Verify you are human</h2>
<form method="POST" action="/__verify_h"><div class="h-captcha" data-sitekey="${sec.hcaptcha_sitekey}"></div><input type="hidden" name="r" value="${redir}"><br><button type="submit">Continue</button></form>
</div></body></html>`;
}

function challengePage(req) {
    const url = req.originalUrl;
    const type = sec.challenge.type || 'js';
    if (type === 'math') return mathCaptchaPage(url);
    if (type === 'hcaptcha' && sec.hcaptcha_sitekey) return hcaptchaPage(url);
    return jsChallengePage(url);
}

// ═══════════════════════════════════════════════════════════════
//  CONFIG LOADER
// ═══════════════════════════════════════════════════════════════

async function loadConfig() {
    if (!CONFIG_URL) return;
    try {
        const r = await fetch(CONFIG_URL);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const json = await r.json();
        const sites = json.sites || json;

        const m = new Map();
        for (const s of sites) {
            const o = s.origin, h = s.host || s.domains[0];
            for (const d of s.domains) m.set(d, { origin: o, host: h });
        }
        domainMap = m;

        if (json.security) {
            const s = json.security;
            sec.blocked_ips = s.blocked_ips || [];
            sec.blocked_cidrs = (s.blocked_ips || []).filter(x => x.includes('/'));
            sec.blocked_ips = (s.blocked_ips || []).filter(x => !x.includes('/'));
            sec.blocked_ua = s.blocked_ua || [];
            sec.allowed_ips = s.allowed_ips || [];
            if (s.rate_limit) sec.rate_limit = s.rate_limit;
            if (s.waf !== undefined) sec.waf = s.waf;
            if (s.challenge) sec.challenge = { ...sec.challenge, ...s.challenge };
            if (s.hcaptcha_sitekey) sec.hcaptcha_sitekey = s.hcaptcha_sitekey;
            if (s.hcaptcha_secret) sec.hcaptcha_secret = s.hcaptcha_secret;
            if (s.security_headers !== undefined) sec.security_headers = s.security_headers;
        }

        configLoaded = true;
    } catch (e) {
        console.error('Config error:', e.message);
    }
}

// ═══════════════════════════════════════════════════════════════
//  PERIODIC CLEANUP
// ═══════════════════════════════════════════════════════════════

setInterval(() => {
    const now = Date.now(), win = (sec.rate_limit.window_s || 60) * 1000;
    for (const [k, v] of rateMap) { if (now - v.ts > win) rateMap.delete(k); }
    if (rateMap.size > RATE_MAP_MAX) rateMap.clear();
    for (const [k, v] of cache) {
        if (now - v.ts > CACHE_TTL) { cacheBytes -= v.data.length; cache.delete(k); }
    }
}, CLEANUP_INTERVAL);

// ═══════════════════════════════════════════════════════════════
//  MIDDLEWARE & ROUTES
// ═══════════════════════════════════════════════════════════════

// ─── Security headers ───
app.use((req, res, next) => {
    if (sec.security_headers) {
        res.set({
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'SAMEORIGIN',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
        });
    }
    next();
});

// ─── Verify endpoints (before security checks) ───
app.post('/__verify', express.urlencoded({ extended: false, limit: '1kb' }), (req, res) => {
    const { a, b, ts, tok, ans, r } = req.body;
    const expected = (+a) * (+a) + (+b) * (+b) + (+a) * (+b);
    const expectedTok = hmac(`${a}:${b}:${ts}:${expected}`);

    if (+ans !== expected || tok !== expectedTok || Date.now() - (+ts) > 300_000) {
        stats.blocked++;
        return res.status(403).send('Verification failed. <a href="' + decodeURIComponent(r || '/') + '">Retry</a>');
    }

    const cookie = makeVerifyCookie(clientIP(req));
    res.cookie(COOKIE_NAME, cookie, {
        maxAge: (sec.challenge.duration_h || 24) * 3600_000,
        httpOnly: true, sameSite: 'Lax', path: '/',
    });
    stats.challenged++;
    res.redirect(302, decodeURIComponent(r || '/'));
});

app.post('/__verify_h', express.urlencoded({ extended: false, limit: '4kb' }), async (req, res) => {
    const { r } = req.body;
    const token = req.body['h-captcha-response'];

    if (sec.hcaptcha_secret && token) {
        try {
            const v = await fetch('https://hcaptcha.com/siteverify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `response=${token}&secret=${sec.hcaptcha_secret}`,
            });
            const j = await v.json();
            if (!j.success) return res.status(403).send('Captcha failed. <a href="' + decodeURIComponent(r || '/') + '">Retry</a>');
        } catch { return res.status(502).send('Captcha verification error'); }
    }

    const cookie = makeVerifyCookie(clientIP(req));
    res.cookie(COOKIE_NAME, cookie, {
        maxAge: (sec.challenge.duration_h || 24) * 3600_000,
        httpOnly: true, sameSite: 'Lax', path: '/',
    });
    stats.challenged++;
    res.redirect(302, decodeURIComponent(r || '/'));
});

// ─── Admin / Health ───
app.get('/health', (req, res) => {
    res.json({
        ok: true, configLoaded, attackMode, stats,
        sites: domainMap.size, cache: cache.size,
        cacheMB: (cacheBytes / 1048576).toFixed(1),
        rateSessions: rateMap.size,
        memMB: (process.memoryUsage.rss() / 1048576).toFixed(1),
    });
});

app.get('/reload', async (req, res) => {
    if (req.query.token !== ADMIN_TOKEN) return res.sendStatus(403);
    await loadConfig();
    res.json({ ok: true, sites: [...domainMap.keys()] });
});

app.get('/attack', (req, res) => {
    if (req.query.token !== ADMIN_TOKEN) return res.sendStatus(403);
    attackMode = req.query.on !== 'false';
    res.json({ attackMode });
});

// ─── Security middleware ───
app.use((req, res, next) => {
    stats.req++;
    const ip = clientIP(req);

    // IP whitelist/blacklist
    if (sec.allowed_ips.length && sec.allowed_ips.includes(ip)) return next();
    if (sec.blocked_ips.includes(ip) || sec.blocked_cidrs.some(c => cidrMatch(ip, c))) {
        stats.blocked++;
        return res.status(403).send('Access denied');
    }

    // Rate limit
    if (!rateOk(ip)) {
        stats.blocked++;
        return res.status(429).set('Retry-After', String(sec.rate_limit.window_s || 60)).send('Too many requests');
    }

    // WAF
    if (!wafOk(req)) {
        stats.waf++;
        return res.status(403).send('Blocked by WAF');
    }

    // Bot check (block known bad bots completely)
    if (isBot(req.get('User-Agent')) && sec.challenge.mode !== 'suspicious') {
        stats.blocked++;
        return res.status(403).send('Access denied');
    }

    // Challenge
    if (shouldChallenge(req)) {
        return res.status(503).send(challengePage(req));
    }

    next();
});

// ─── Static with cache ───
app.get(/\.(js|css|png|jpe?g|gif|ico|svg|woff2?|ttf|eot|map|webp|avif)$/i, async (req, res) => {
    const target = domainMap.get(req.hostname);
    if (!target) return res.sendStatus(404);

    const key = req.hostname + req.originalUrl;
    const hit = cacheGet(key);
    if (hit) {
        stats.cached++;
        res.set('Content-Type', hit.type);
        res.set('X-Cache', 'HIT');
        res.set('Cache-Control', 'public, max-age=86400');
        return res.send(hit.data);
    }

    try {
        const r = await originFetch(target, req.originalUrl, {
            headers: { 'User-Agent': req.get('User-Agent') || 'Proxy/2.0' },
        });
        if (!r.ok) return res.sendStatus(r.status);

        const type = r.headers.get('content-type') || 'application/octet-stream';
        const len = +(r.headers.get('content-length') || 0);

        // Stream large files directly
        if (len > STREAM_THRESHOLD) {
            res.status(r.status);
            res.set('Content-Type', type);
            res.set('Cache-Control', 'public, max-age=86400');
            Readable.fromWeb(r.body).pipe(res);
            return;
        }

        const data = Buffer.from(await r.arrayBuffer());
        cacheSet(key, data, type);

        res.set('Content-Type', type);
        res.set('X-Cache', 'MISS');
        res.set('Cache-Control', 'public, max-age=86400');
        res.send(data);
    } catch (e) {
        res.status(502).send('Origin error');
    }
});

// ─── Dynamic content ───
app.use(async (req, res) => {
    const target = domainMap.get(req.hostname);
    if (!target) {
        return res.status(404).send('Unknown host: ' + req.hostname);
    }

    try {
        const hdrs = {
            'X-Real-IP': clientIP(req),
            'X-Forwarded-For': clientIP(req),
            'X-Forwarded-Proto': 'https',
            'X-Forwarded-Port': '443',
            'User-Agent': req.get('User-Agent') || '',
            'Accept': req.get('Accept') || '*/*',
            'Accept-Language': req.get('Accept-Language') || '',
            'Referer': req.get('Referer') || '',
        };
        if (req.get('Cookie')) hdrs['Cookie'] = req.get('Cookie');
        if (req.get('Content-Type')) hdrs['Content-Type'] = req.get('Content-Type');
        if (req.get('Authorization')) hdrs['Authorization'] = req.get('Authorization');

        const opts = { method: req.method, headers: hdrs, redirect: 'manual' };

        if (!['GET', 'HEAD'].includes(req.method)) {
            const chunks = [];
            for await (const c of req) chunks.push(c);
            opts.body = Buffer.concat(chunks);
            opts.duplex = 'half';
        }

        const r = await originFetch(target, req.originalUrl, opts);
        const ct = r.headers.get('content-type') || '';

        // Cookies
        const cookies = r.headers.getSetCookie?.() || [];
        cookies.forEach(c => {
            res.append('Set-Cookie',
                c.replace(/domain=[^;]+;?/gi, '').replace(/;\s*secure/gi, '')
            );
        });

        // Redirects
        if ([301, 302, 303, 307, 308].includes(r.status)) {
            let loc = r.headers.get('location') || '';
            loc = loc
                .replace(target.origin, `https://${req.hostname}`)
                .replace(`//${target.host}`, `//${req.hostname}`);
            return res.redirect(r.status, loc);
        }

        res.status(r.status);
        res.set('Content-Type', ct);

        // HTML — URL rewriting
        if (ct.includes('text/html')) {
            let html = await r.text();
            html = html
                .replaceAll(target.origin, `https://${req.hostname}`)
                .replaceAll(`//${target.host}`, `//${req.hostname}`);
            return res.send(html);
        }

        // Non-HTML — stream through
        if (r.body) {
            Readable.fromWeb(r.body).pipe(res);
        } else {
            res.end();
        }
    } catch (e) {
        res.status(502).send('Origin unavailable');
    }
});

// ═══════════════════════════════════════════════════════════════
//  STARTUP
// ═══════════════════════════════════════════════════════════════

(async () => {
    await loadConfig();
    setInterval(loadConfig, CONFIG_INTERVAL);

    const SELF = process.env.RENDER_EXTERNAL_URL;
    if (SELF) setInterval(() => fetch(SELF + '/health').catch(() => {}), 14 * 60_000);

    app.listen(PORT, () => console.log(`Shield Proxy on :${PORT}`));
})();
