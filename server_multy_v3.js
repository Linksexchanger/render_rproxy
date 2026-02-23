// НЕ нужен process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
// Вместо этого — точечное управление через Agent

const express = require('express');
const compression = require('compression');
const { Agent } = require('undici');

const app = express();
const PORT = process.env.PORT || 3000;

const CONFIG_URL = process.env.CONFIG_URL;
const CONFIG_INTERVAL = 5 * 60 * 1000;

// ─── Маппинг доменов ───
let domainMap = new Map();
let configLoaded = false;

// ─── Кэш undici-агентов (один на каждый target.host) ───
const agentCache = new Map();

function getAgent(targetHost) {
    if (agentCache.has(targetHost)) return agentCache.get(targetHost);

    const agent = new Agent({
        connect: {
            rejectUnauthorized: false,   // для wildcard-серта
            servername: targetHost,       // ← КЛЮЧЕВОЙ МОМЕНТ: правильный SNI
        },
        keepAliveTimeout: 30000,
        keepAliveMaxTimeout: 60000,
    });

    agentCache.set(targetHost, agent);
    return agent;
}

// ─── Обёртка fetch с правильным SNI ───
async function fetchOrigin(target, path, options = {}) {
    const url = target.origin + path;
    const agent = getAgent(target.host);

    const defaultHeaders = {
        'Host': target.host,
        'Accept-Encoding': 'identity',
    };

    return fetch(url, {
        ...options,
        dispatcher: agent,
        headers: {
            ...defaultHeaders,
            ...(options.headers || {}),
        },
    });
}

// ─── Загрузка конфига ───
async function loadConfig() {
    try {
        console.log('Loading config from', CONFIG_URL);
        const resp = await fetch(CONFIG_URL);

        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

        const contentType = resp.headers.get('content-type') || '';
        let sites;

        if (contentType.includes('json')) {
            const json = await resp.json();
            sites = json.sites || json;
        } else {
            sites = parseTxtConfig(await resp.text());
        }

        const newMap = new Map();
        for (const site of sites) {
            const origin = site.origin;
            const host = site.host || site.domains[0];
            for (const domain of site.domains) {
                newMap.set(domain, { origin, host });
                console.log(`  ${domain} → ${origin} (SNI: ${host})`);
            }
        }

        domainMap = newMap;
        configLoaded = true;
        console.log(`✅ Loaded ${newMap.size} domains`);
    } catch (e) {
        console.error('❌ Config error:', e.message);
    }
}

function parseTxtConfig(text) {
    const sitesMap = {};
    text.split('\n')
        .map(l => l.trim())
        .filter(l => l && !l.startsWith('#'))
        .forEach(line => {
            const [domain, origin, host] = line.split('|').map(p => p.trim());
            if (!domain || !origin) return;
            const key = origin + '|' + (host || domain);
            if (!sitesMap[key]) {
                sitesMap[key] = { domains: [], origin, host: host || domain };
            }
            sitesMap[key].domains.push(domain);
        });
    return Object.values(sitesMap);
}

function getTarget(hostname) {
    return domainMap.get(hostname) || null;
}

// ─── Кэш статики ───
const cache = new Map();
const CACHE_TTL = 3600_000;
const MAX_CACHE = 500;

function getCached(key) {
    const item = cache.get(key);
    if (!item) return null;
    if (Date.now() - item.time > CACHE_TTL) {
        cache.delete(key);
        return null;
    }
    return item;
}

function setCache(key, data, type) {
    if (cache.size >= MAX_CACHE) {
        cache.delete(cache.keys().next().value);
    }
    cache.set(key, { data, type, time: Date.now() });
}

// ─── Middleware ───
app.use(compression());

app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        configLoaded,
        sites: [...domainMap.keys()],
        cacheSize: cache.size,
    });
});

app.get('/reload', async (req, res) => {
    if (req.query.token !== process.env.ADMIN_TOKEN) {
        return res.status(403).send('Forbidden');
    }
    await loadConfig();
    res.json({ status: 'reloaded', sites: [...domainMap.keys()] });
});

// ─── Статика с кэшем ───
app.get(
    /\.(js|css|png|jpg|jpeg|gif|ico|svg|woff2?|ttf|eot|map)$/i,
    async (req, res) => {
        const target = getTarget(req.hostname);
        if (!target) return res.status(404).send('Unknown host');

        const key = req.hostname + req.originalUrl;
        const cached = getCached(key);

        if (cached) {
            res.set('Content-Type', cached.type);
            res.set('X-Cache', 'HIT');
            res.set('Cache-Control', 'public, max-age=86400');
            return res.send(cached.data);
        }

        try {
            const resp = await fetchOrigin(target, req.originalUrl, {
                headers: {
                    'User-Agent': req.get('User-Agent') || 'WP-Proxy/1.0',
                },
            });

            if (!resp.ok) return res.sendStatus(resp.status);

            const type = resp.headers.get('content-type')
                         || 'application/octet-stream';
            const data = Buffer.from(await resp.arrayBuffer());

            setCache(key, data, type);

            res.set('Content-Type', type);
            res.set('X-Cache', 'MISS');
            res.set('Cache-Control', 'public, max-age=86400');
            res.send(data);
        } catch (e) {
            console.error(`[${req.hostname}] Static error:`,
                          e.message, e.cause?.code || '');
            res.status(502).send('Origin error');
        }
    }
);

// ─── Динамический контент ───
app.use(async (req, res) => {
    const target = getTarget(req.hostname);
    if (!target) {
        return res.status(404).send(
            `Unknown host: ${req.hostname}\n` +
            `Known: ${[...domainMap.keys()].join(', ')}`
        );
    }

    try {
        const headers = {
            'X-Real-IP': req.ip,
            'X-Forwarded-For': req.ip,
            'X-Forwarded-Proto': 'https',
            'X-Forwarded-Port': '443',
            'User-Agent': req.get('User-Agent') || '',
            'Accept': req.get('Accept') || '*/*',
            'Accept-Language': req.get('Accept-Language') || '',
        };

        if (req.get('Cookie')) headers['Cookie'] = req.get('Cookie');
        if (req.get('Content-Type')) {
            headers['Content-Type'] = req.get('Content-Type');
        }

        const fetchOpts = {
            method: req.method,
            headers,
            redirect: 'manual',
        };

        if (!['GET', 'HEAD'].includes(req.method)) {
            const chunks = [];
            for await (const chunk of req) chunks.push(chunk);
            fetchOpts.body = Buffer.concat(chunks);
            // Для undici нужно указать duplex
            fetchOpts.duplex = 'half';
        }

        const resp = await fetchOrigin(target, req.originalUrl, fetchOpts);

        const contentType = resp.headers.get('content-type') || '';
        res.status(resp.status);
        res.set('Content-Type', contentType);

        // Куки
        const cookies = resp.headers.getSetCookie?.() || [];
        cookies.forEach(c => {
            res.append('Set-Cookie',
                c.replace(/domain=[^;]+;?/gi, '')
                 .replace(/;\s*secure/gi, '')
            );
        });

        // Редиректы
        if ([301, 302, 303, 307, 308].includes(resp.status)) {
            let location = resp.headers.get('location') || '';
            location = location
                .replace(target.origin, `https://${req.hostname}`)
                .replace(`//${target.host}`, `//${req.hostname}`);
            return res.redirect(resp.status, location);
        }

        // HTML — подмена URL
        if (contentType.includes('text/html')) {
            let html = await resp.text();
            html = html
                .replaceAll(target.origin, `https://${req.hostname}`)
                .replaceAll(`//${target.host}`, `//${req.hostname}`);
            res.send(html);
        } else {
            res.send(Buffer.from(await resp.arrayBuffer()));
        }

        console.log(`[${req.hostname}] ${req.method} ${req.originalUrl} -> status ${resp.status}`);
        if (cookies.length) {
            console.log(`[${req.hostname}] Set-Cookie:`, cookies);
        }

    } catch (e) {
        console.error(`[${req.hostname}] Proxy error:`,
                      e.message, e.cause?.code || '', e.cause?.message || '');
        res.status(502).send(`Origin unavailable: ${e.cause?.code || e.message}`);
    }
});

// ─── Запуск ───
async function start() {
    await loadConfig();
    setInterval(loadConfig, CONFIG_INTERVAL);

    const SELF = process.env.RENDER_EXTERNAL_URL;
    if (SELF) {
        setInterval(() => fetch(SELF + '/health').catch(() => {}),
                    14 * 60_000);
    }

    app.listen(PORT, () => {
        console.log(`🚀 Proxy on port ${PORT}`);
    });
}

start().catch(console.error);
