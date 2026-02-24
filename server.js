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

const CACHE_MAX_BYTES = 15 * 1024 * 1024;
const CACHE_MAX_ITEM  = 50 * 1024;
const CACHE_TTL       = 3600_000;
const STREAM_THRESHOLD = 512 * 1024;
const RATE_MAP_MAX    = 5000;
const CLEANUP_INTERVAL = 30_000;

// ═══════════════════════════════════════════════════════════════
//  STATE
// ═══════════════════════════════════════════════════════════════

// domain → { origin, host, sec }
let domainMap = new Map();
let configLoaded = false;
// domain → attackMode
const attackModes = new Map();

const DEFAULT_SEC = {
    blocked_ips: [], blocked_cidrs: [], allowed_ips: [], blocked_ua: [],
    rate_limit: { window_s: 60, max: 100 },
    waf: true,
    challenge: { mode: 'off', type: 'js', duration_h: 24 },
    hcaptcha_sitekey: '', hcaptcha_secret: '',
    security_headers: true,
};

const DEFAULT_BOTS = [
    'semrushbot','ahrefsbot','mj12bot','dotbot','blexbot','petalbot',
    'bytespider','gptbot','ccbot','dataforseobot','sogou','baiduspider',
    'claudebot','anthropic','screaming frog',
];

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
    return (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
        || req.ip || '0.0.0.0';
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

function getSec(hostname) {
    const entry = domainMap.get(hostname);
    return entry ? entry.sec : DEFAULT_SEC;
}

function getTarget(hostname) {
    const entry = domainMap.get(hostname);
    return entry ? { origin: entry.origin, host: entry.host } : null;
}

function isAttackMode(hostname) {
    return attackModes.get(hostname) || false;
}

// ═══════════════════════════════════════════════════════════════
//  CACHE
// ═══════════════════════════════════════════════════════════════

function cacheGet(key) {
    const it = cache.get(key);
    if (!it) return null;
    if (Date.now() - it.ts > CACHE_TTL) {
        cacheBytes -= it.data.length; cache.delete(key); return null;
    }
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
//  RATE LIMITING (per domain + IP)
// ═══════════════════════════════════════════════════════════════

function rateOk(ip, sec) {
    const now = Date.now(), win = (sec.rate_limit.window_s || 60) * 1000;
    const key = ip;
    let e = rateMap.get(key);
    if (!e || now - e.ts > win) { e = { c: 0, ts: now }; rateMap.set(key, e); }
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

function wafOk(req, sec) {
    if (!sec.waf) return true;
    try {
        const s = decodeURIComponent(req.originalUrl);
        return !WAF_RE.some(r => r.test(s));
    } catch { return true; }
}

// ═══════════════════════════════════════════════════════════════
//  BOT DETECTION
// ═══════════════════════════════════════════════════════════════

function isBot(ua, sec) {
    if (!ua) return true;
    const low = ua.toLowerCase();
    const list = sec.blocked_ua.length ? sec.blocked_ua : DEFAULT_BOTS;
    return list.some(b => low.includes(b.toLowerCase()));
}

// ═══════════════════════════════════════════════════════════════
//  CHALLENGE
// ═══════════════════════════════════════════════════════════════

const COOKIE_NAME = '__rv';

function makeVerifyCookie(ip) {
    const exp = Date.now() + 24 * 3600_000;
    return `${hmac(ip + ':' + exp)}:${exp}`;
}

function makeVerifyCookieSec(ip, sec) {
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

function shouldChallenge(req, sec) {
    if (/\.(js|css|png|jpe?g|gif|ico|svg|woff2?|ttf|eot|map|webp|avif)$/i.test(req.path)) return false;
    if (req.path.startsWith('/__')) return false;
    if (cookieValid(req)) return false;
    if (isAttackMode(req.hostname) || sec.challenge.mode === 'all') return true;
    if (sec.challenge.mode === 'suspicious') return isBot(req.get('User-Agent'), sec);
    return false;
}

// ─── Challenge Pages ───

function jsChallengePage(url) {
    const a = Math.floor(Math.random() * 1000), b = Math.floor(Math.random() * 1000);
    const ts = Date.now(), ans = a * a + b * b + a * b;
    const tok = hmac(`${a}:${b}:${ts}:${ans}`);
    return `<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Checking your browser…</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;background:#f0f2f5}.c{background:#fff;padding:48px;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.08);text-align:center;max-width:400px}.s{width:48px;height:48px;border:4px solid #e0e0e0;border-top:4px solid #1a73e8;border-radius:50%;animation:r 1s linear infinite;margin:0 auto 24px}@keyframes r{to{transform:rotate(360deg)}}h2{color:#202124;margin-bottom:8px}p{color:#5f6368;font-size:14px}</style></head>
<body><div class="c"><div class="s"></div><h2>Checking your browser</h2><p>This will only take a moment…</p>
<form id="f" method="POST" action="/__verify"><input type="hidden" name="a" value="${a}"><input type="hidden" name="b" value="${b}"><input type="hidden" name="ts" value="${ts}"><input type="hidden" name="tok" value="${tok}"><input type="hidden" name="ans" id="a"><input type="hidden" name="r" value="${encodeURIComponent(url)}"></form>
<script>document.getElementById('a').value=${a}*${a}+${b}*${b}+${a}*${b};setTimeout(()=>document.getElementById('f').submit(),3e3)</script>
</div></body></html>`;
}

function mathCaptchaPage(url) {
    const a = 1 + Math.floor(Math.random() * 20), b = 1 + Math.floor(Math.random() * 20);
    const ts = Date.now(), ans = a + b;
    const tok = hmac(`${a}:${b}:${ts}:${ans}`);
    return `<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Check</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;background:#f0f2f5}.c{background:#fff;padding:48px;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.08);text-align:center;max-width:400px}h2{color:#202124;margin-bottom:16px}p{color:#5f6368;margin-bottom:16px}input[type=number]{font-size:24px;width:100px;text-align:center;padding:8px;border:2px solid #dadce0;border-radius:8px;outline:none}input:focus{border-color:#1a73e8}button{margin-top:16px;font-size:16px;padding:10px 32px;background:#1a73e8;color:#fff;border:none;border-radius:8px;cursor:pointer}button:hover{background:#1557b0}</style></head>
<body><div class="c"><h2>Security Check</h2><p>What is <b>${a} + ${b}</b> ?</p>
<form method="POST" action="/__verify"><input type="hidden" name="a" value="${a}"><input type="hidden" name="b" value="${b}"><input type="hidden" name="ts" value="${ts}"><input type="hidden" name="tok" value="${tok}"><input type="number" name="ans" autofocus required><input type="hidden" name="r" value="${encodeURIComponent(url)}"><br><button type="submit">Verify</button></form>
</div></body></html>`;
}

function hcaptchaPage(url, sitekey) {
    return `<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Check</title>
<script src="https://js.hcaptcha.com/1/api.js" async defer></script>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;background:#f0f2f5}.c{background:#fff;padding:48px;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.08);text-align:center;max-width:400px}h2{margin-bottom:16px}button{margin-top:16px;font-size:16px;padding:10px 32px;background:#1a73e8;color:#fff;border:none;border-radius:8px;cursor:pointer}</style></head>
<body><div class="c"><h2>Verify you are human</h2>
<form method="POST" action="/__verify_h"><div class="h-captcha" data-sitekey="${sitekey}"></div><input type="hidden" name="r" value="${encodeURIComponent(url)}"><br><button type="submit">Continue</button></form>
</div></body></html>`;
}

function challengePage(req, sec) {
    const url = req.originalUrl;
    const type = sec.challenge.type || 'js';
    if (type === 'math') return mathCaptchaPage(url);
    if (type === 'hcaptcha' && sec.hcaptcha_sitekey) return hcaptchaPage(url, sec.hcaptcha_sitekey);
    return jsChallengePage(url);
}

// ═══════════════════════════════════════════════════════════════
//  CONFIG LOADER
// ═══════════════════════════════════════════════════════════════

function parseSecurity(raw, defaults) {
    if (!raw) return { ...defaults };
    const ips = raw.blocked_ips || defaults.blocked_ips || [];
    return {
        blocked_ips: ips.filter(x => !x.includes('/')),
        blocked_cidrs: ips.filter(x => x.includes('/')),
        allowed_ips: raw.allowed_ips || defaults.allowed_ips || [],
        blocked_ua: raw.blocked_ua || defaults.blocked_ua || [],
        rate_limit: raw.rate_limit || defaults.rate_limit || { window_s: 60, max: 100 },
        waf: raw.waf !== undefined ? raw.waf : (defaults.waf !== undefined ? defaults.waf : true),
        challenge: { ...(defaults.challenge || {}), ...(raw.challenge || {}) },
        hcaptcha_sitekey: raw.hcaptcha_sitekey || defaults.hcaptcha_sitekey || '',
        hcaptcha_secret: raw.hcaptcha_secret || defaults.hcaptcha_secret || '',
        security_headers: raw.security_headers !== undefined
            ? raw.security_headers
            : (defaults.security_headers !== undefined ? defaults.security_headers : true),
    };
}

async function loadConfig() {
    if (!CONFIG_URL) return;
    try {
        const r = await fetch(CONFIG_URL);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const json = await r.json();
        const sites = json.sites || json;
        const defaults = parseSecurity(json.security_defaults, DEFAULT_SEC);

        const m = new Map();
        for (const s of sites) {
            const o = s.origin, h = s.host || s.domains[0];
            const sec = parseSecurity(s.security, defaults);
            for (const d of s.domains) {
                m.set(d, { origin: o, host: h, sec });
            }
        }
        domainMap = m;
        configLoaded = true;
    } catch (e) {
        console.error('Config error:', e.message);
    }
}

// ═══════════════════════════════════════════════════════════════
//  CLEANUP
// ═══════════════════════════════════════════════════════════════

setInterval(() => {
    const now = Date.now();
    for (const [k, v] of rateMap) {
        if (now - v.ts > 120_000) rateMap.delete(k);
    }
    if (rateMap.size > RATE_MAP_MAX) rateMap.clear();
    for (const [k, v] of cache) {
        if (now - v.ts > CACHE_TTL) { cacheBytes -= v.data.length; cache.delete(k); }
    }
}, CLEANUP_INTERVAL);

// ═══════════════════════════════════════════════════════════════
//  ROUTES
// ═══════════════════════════════════════════════════════════════

// ─── Verify endpoints ───
app.post('/__verify', express.urlencoded({ extended: false, limit: '1kb' }), (req, res) => {
    const { a, b, ts, tok, ans, r } = req.body;
    const expected = (+a) * (+a) + (+b) * (+b) + (+a) * (+b);
    const expectedTok = hmac(`${a}:${b}:${ts}:${expected}`);
    const sec = getSec(req.hostname);

    if (+ans !== expected || tok !== expectedTok || Date.now() - (+ts) > 300_000) {
        stats.blocked++;
        return res.status(403).send('Verification failed. <a href="' +
            decodeURIComponent(r || '/') + '">Retry</a>');
    }

    const cookie = makeVerifyCookieSec(clientIP(req), sec);
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
    const sec = getSec(req.hostname);

    if (sec.hcaptcha_secret && token) {
        try {
            const v = await fetch('https://hcaptcha.com/siteverify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `response=${token}&secret=${sec.hcaptcha_secret}`,
            });
            const j = await v.json();
            if (!j.success) {
                return res.status(403).send('Captcha failed. <a href="' +
                    decodeURIComponent(r || '/') + '">Retry</a>');
            }
        } catch {
            return res.status(502).send('Captcha verification error');
        }
    }

    const cookie = makeVerifyCookieSec(clientIP(req), sec);
    res.cookie(COOKIE_NAME, cookie, {
        maxAge: (sec.challenge.duration_h || 24) * 3600_000,
        httpOnly: true, sameSite: 'Lax', path: '/',
    });
    stats.challenged++;
    res.redirect(302, decodeURIComponent(r || '/'));
});

// ─── Admin ───
app.get('/health', (req, res) => {
    res.json({
        ok: true, configLoaded, stats,
        sites: [...domainMap.entries()].map(([d, e]) => ({
            domain: d,
            challenge: e.sec.challenge.mode,
            waf: e.sec.waf,
            rateLimit: e.sec.rate_limit.max,
            attack: isAttackMode(d),
        })),
        cache: cache.size,
        cacheMB: (cacheBytes / 1048576).toFixed(1),
        rateSessions: rateMap.size,
        memMB: +(process.memoryUsage.rss() / 1048576).toFixed(1),
    });
});

app.get('/reload', async (req, res) => {
    if (req.query.token !== ADMIN_TOKEN) return res.sendStatus(403);
    await loadConfig();
    res.json({ ok: true, sites: [...domainMap.keys()] });
});

app.get('/attack', (req, res) => {
    if (req.query.token !== ADMIN_TOKEN) return res.sendStatus(403);
    const domain = req.query.domain;
    const on = req.query.on !== 'false';

    if (domain) {
        attackModes.set(domain, on);
        return res.json({ domain, attackMode: on });
    }

    // All domains
    for (const d of domainMap.keys()) attackModes.set(d, on);
    res.json({ all: true, attackMode: on });
});

// ─── Security middleware ───
app.use((req, res, next) => {
    // Skip internal paths
    if (req.path.startsWith('/__') || req.path === '/health'
        || req.path === '/reload' || req.path === '/attack') {
        return next();
    }

    stats.req++;
    const sec = getSec(req.hostname);
    const ip = clientIP(req);

    // Security headers
    if (sec.security_headers) {
        res.set({
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'SAMEORIGIN',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
        });
    }

    // IP whitelist
    if (sec.allowed_ips.length && sec.allowed_ips.includes(ip)) return next();

    // IP blacklist
    if (sec.blocked_ips.includes(ip) || sec.blocked_cidrs.some(c => cidrMatch(ip, c))) {
        stats.blocked++;
        return res.status(403).send('Access denied');
    }

    // Rate limit
    if (!rateOk(ip, sec)) {
        stats.blocked++;
        return res.status(429)
            .set('Retry-After', String(sec.rate_limit.window_s || 60))
            .send('Too many requests');
    }

    // WAF
    if (!wafOk(req, sec)) {
        stats.waf++;
        return res.status(403).send('Blocked by WAF');
    }

    // Bot block (if challenge mode is not suspicious — block outright)
    if (sec.challenge.mode !== 'suspicious' && isBot(req.get('User-Agent'), sec)) {
        stats.blocked++;
        return res.status(403).send('Access denied');
    }

    // Challenge
    if (shouldChallenge(req, sec)) {
        stats.challenged++;
        return res.status(503).send(challengePage(req, sec));
    }

    next();
});

// ─── Static ───
app.get(/\.(js|css|png|jpe?g|gif|ico|svg|woff2?|ttf|eot|map|webp|avif)$/i, async (req, res) => {
    const target = getTarget(req.hostname);
    if (!target) return res.sendStatus(404);

    const key = req.hostname + req.originalUrl;
    const hit = cacheGet(key);
    if (hit) {
        stats.cached++;
        res.set({ 'Content-Type': hit.type, 'X-Cache': 'HIT', 'Cache-Control': 'public, max-age=86400' });
        return res.send(hit.data);
    }

    try {
        const r = await originFetch(target, req.originalUrl, {
            headers: { 'User-Agent': req.get('User-Agent') || 'Proxy/2.0' },
        });
        if (!r.ok) return res.sendStatus(r.status);

        const type = r.headers.get('content-type') || 'application/octet-stream';
        const len = +(r.headers.get('content-length') || 0);

        if (len > STREAM_THRESHOLD) {
            res.status(r.status).set({ 'Content-Type': type, 'Cache-Control': 'public, max-age=86400' });
            return Readable.fromWeb(r.body).pipe(res);
        }

        const data = Buffer.from(await r.arrayBuffer());
        cacheSet(key, data, type);
        res.set({ 'Content-Type': type, 'X-Cache': 'MISS', 'Cache-Control': 'public, max-age=86400' });
        res.send(data);
    } catch {
        res.status(502).send('Origin error');
    }
});

// ─── Dynamic ───
app.use(async (req, res) => {
    const target = getTarget(req.hostname);
    if (!target) return res.status(404).send('Unknown host: ' + req.hostname);

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

        res.status(r.status).set('Content-Type', ct);

        if (ct.includes('text/html')) {
            let html = await r.text();
            html = html
                .replaceAll(target.origin, `https://${req.hostname}`)
                .replaceAll(`//${target.host}`, `//${req.hostname}`);
            return res.send(html);
        }

        if (r.body) {
            Readable.fromWeb(r.body).pipe(res);
        } else {
            res.end();
        }
    } catch {
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
