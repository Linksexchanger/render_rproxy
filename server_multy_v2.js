const express = require('express');
const compression = require('compression');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Конфигурация ───
const CONFIG_URL = process.env.CONFIG_URL;
// Например: https://185.1.2.3/.proxy-config/sites.json?token=abc123
// Или:      https://site1.com/wp-json/proxy/v1/sites?token=abc123

const CONFIG_INTERVAL = 5 * 60 * 1000; // Обновлять каждые 5 минут
const PROXY_DOMAIN = process.env.RENDER_EXTERNAL_URL || '';

// ─── Хранилище маппинга доменов ───
// domain → { origin, host }
let domainMap = new Map();
let configLoaded = false;

// ─── Загрузка конфига ───
async function loadConfig() {
    try {
        console.log('Loading sites config...');
        const resp = await fetch(CONFIG_URL);

        if (!resp.ok) {
            throw new Error(`Config HTTP ${resp.status}`);
        }

        const contentType = resp.headers.get('content-type') || '';
        let sites;

        if (contentType.includes('json')) {
            const json = await resp.json();
            sites = json.sites || json;
        } else {
            // Построчный TXT формат:
            // site1.com|https://185.1.2.3|site1.com
            // www.site1.com|https://185.1.2.3|site1.com
            const text = await resp.text();
            sites = parseTxtConfig(text);
        }

        const newMap = new Map();

        for (const site of sites) {
            const origin = site.origin;
            const host = site.host || site.domains[0];

            for (const domain of site.domains) {
                newMap.set(domain, { origin, host });
                console.log(`  ${domain} → ${origin} (Host: ${host})`);
            }
        }

        domainMap = newMap;
        configLoaded = true;
        console.log(`✅ Loaded ${newMap.size} domain mappings`);

    } catch (e) {
        console.error('❌ Config load error:', e.message);
        // Не сбрасываем старый конфиг при ошибке
        if (!configLoaded) {
            console.error('No config available, will retry...');
        }
    }
}

// ─── Парсер TXT-формата ───
function parseTxtConfig(text) {
    const sitesMap = {};

    text.split('\n')
        .map(l => l.trim())
        .filter(l => l && !l.startsWith('#'))
        .forEach(line => {
            // Формат: domain|origin|host
            // или:    domain|origin  (host = domain)
            const parts = line.split('|').map(p => p.trim());
            if (parts.length < 2) return;

            const [domain, origin, host] = parts;
            const key = origin + '|' + (host || domain);

            if (!sitesMap[key]) {
                sitesMap[key] = {
                    domains: [],
                    origin,
                    host: host || domain,
                };
            }
            sitesMap[key].domains.push(domain);
        });

    return Object.values(sitesMap);
}

// ─── Получить origin для домена ───
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

// Здоровье и статус
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        configLoaded,
        sites: [...domainMap.keys()],
        cacheSize: cache.size,
    });
});

// Принудительное обновление конфига
app.get('/reload', async (req, res) => {
    if (req.query.token !== process.env.ADMIN_TOKEN) {
        return res.status(403).send('Forbidden');
    }
    await loadConfig();
    res.json({
        status: 'reloaded',
        sites: [...domainMap.keys()],
    });
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
            const resp = await fetch(target.origin + req.originalUrl, {
                headers: {
                    'Host': target.host,
                    'Accept-Encoding': 'identity',
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
            console.error(`[${req.hostname}] Static error:`, e.message);
            res.status(502).send('Origin error');
        }
    }
);

// ─── Динамический контент (HTML, API, wp-admin) ───
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
            'Host': target.host,
            'X-Real-IP': req.ip,
            'X-Forwarded-For': req.ip,
            'X-Forwarded-Proto': 'https',
            'User-Agent': req.get('User-Agent') || '',
            'Accept': req.get('Accept') || '*/*',
            'Accept-Language': req.get('Accept-Language') || '',
        };

        // Проброс куки
        if (req.get('Cookie')) {
            headers['Cookie'] = req.get('Cookie');
        }

        // Content-Type для POST
        if (req.get('Content-Type')) {
            headers['Content-Type'] = req.get('Content-Type');
        }

        const fetchOpts = {
            method: req.method,
            headers,
            redirect: 'manual',
        };

        // Тело запроса для POST/PUT
        if (!['GET', 'HEAD'].includes(req.method)) {
            const chunks = [];
            for await (const chunk of req) chunks.push(chunk);
            fetchOpts.body = Buffer.concat(chunks);
        }

        const resp = await fetch(
            target.origin + req.originalUrl,
            fetchOpts
        );

        // Редиректы — подменяем origin → proxy домен
        if ([301, 302, 303, 307, 308].includes(resp.status)) {
            let location = resp.headers.get('location') || '';
            location = location
                .replace(target.origin, `https://${req.hostname}`)
                .replace(`//${target.host}`, `//${req.hostname}`);
            res.redirect(resp.status, location);
            return;
        }

        const contentType = resp.headers.get('content-type') || '';
        res.status(resp.status);
        res.set('Content-Type', contentType);

        // Куки — убираем привязку к оригинальному домену
        const cookies = resp.headers.getSetCookie?.() || [];
        cookies.forEach(c => {
            res.append('Set-Cookie',
                c.replace(/domain=[^;]+;?/gi, '')
                 .replace(/secure;?\s*/gi, '')
            );
        });

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

    } catch (e) {
        console.error(`[${req.hostname}] Proxy error:`, e.message);
        res.status(502).send('Origin unavailable');
    }
});

// ─── Запуск ───
async function start() {
    // Загружаем конфиг перед стартом
    await loadConfig();

    // Периодическое обновление
    setInterval(loadConfig, CONFIG_INTERVAL);

    // Keep-alive пинг
    const SELF = process.env.RENDER_EXTERNAL_URL;
    if (SELF) {
        setInterval(() => fetch(SELF + '/health').catch(() => {}),
                    14 * 60_000);
    }

    app.listen(PORT, () => {
        console.log(`\n🚀 Multi-proxy running on port ${PORT}`);
        console.log(`   Config: ${CONFIG_URL}`);
        console.log(`   Sites: ${[...domainMap.keys()].join(', ')}\n`);
    });
}

start().catch(console.error);