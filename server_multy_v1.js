const express = require('express');
const compression = require('compression');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Маппинг доменов ───
/*
const SITES = {
    'site1.com':       'https://origin-server1.com',
    'www.site1.com':   'https://origin-server1.com',
    'site2.com':       'https://origin-server2.com',
    'www.site2.com':   'https://origin-server2.com',
    'site3.com':       'https://origin-server3.com',
    'www.site3.com':   'https://origin-server3.com',
};
*/

// Если все WP на одном сервере:
/*
const SITES = {
     'site1.com': 'https://185.x.x.x',
     'site2.com': 'https://185.x.x.x',
     'site3.com': 'https://185.x.x.x',
};
*/

function getTarget(req) {
    const host = req.hostname;
    return SITES[host] || null;
}

app.use(compression());

// ─── Кэш статики ───
const cache = new Map();
const CACHE_TTL = 3600_000;
const MAX_CACHE = 500;

// ─── Статика ───
app.get(/\.(js|css|png|jpg|jpeg|gif|ico|svg|woff2?|ttf|eot|map)$/i,
    async (req, res) => {
        const target = getTarget(req);
        if (!target) return res.status(404).send('Unknown host');

        const key = req.hostname + req.originalUrl;
        const cached = cache.get(key);

        if (cached && Date.now() - cached.time < CACHE_TTL) {
            res.set('Content-Type', cached.type);
            res.set('X-Cache', 'HIT');
            res.set('Cache-Control', 'public, max-age=86400');
            return res.send(cached.data);
        }

        try {
            const resp = await fetch(target + req.originalUrl, {
                headers: {
                    'Host': new URL(target).host,
                    'Accept-Encoding': 'identity'
                }
            });
            if (!resp.ok) return res.sendStatus(resp.status);

            const type = resp.headers.get('content-type');
            const data = Buffer.from(await resp.arrayBuffer());

            if (cache.size >= MAX_CACHE) {
                cache.delete(cache.keys().next().value);
            }
            cache.set(key, { data, type, time: Date.now() });

            res.set('Content-Type', type);
            res.set('X-Cache', 'MISS');
            res.set('Cache-Control', 'public, max-age=86400');
            res.send(data);
        } catch (e) {
            res.status(502).send('Origin error');
        }
    }
);

// ─── HTML / динамика ───
app.use(async (req, res) => {
    const target = getTarget(req);
    if (!target) return res.status(404).send('Unknown host');

    try {
        const resp = await fetch(target + req.originalUrl, {
            method: req.method,
            headers: {
                'Host': new URL(target).host,
                'X-Real-IP': req.ip,
                'X-Forwarded-For': req.ip,
                'Accept': req.get('Accept') || '*/*',
            },
            body: ['GET','HEAD'].includes(req.method) ? undefined : req,
            redirect: 'manual'
        });

        // Редиректы
        if ([301,302,303,307,308].includes(resp.status)) {
            let loc = resp.headers.get('location') || '';
            loc = loc.replace(target, `https://${req.hostname}`);
            return res.redirect(resp.status, loc);
        }

        const contentType = resp.headers.get('content-type') || '';
        res.status(resp.status);
        res.set('Content-Type', contentType);

        // Куки
        const cookies = resp.headers.getSetCookie?.() || [];
        cookies.forEach(c => {
            res.append('Set-Cookie',
                c.replace(/domain=[^;]+;?/gi, '')
            );
        });

        if (contentType.includes('text/html')) {
            let html = await resp.text();
            html = html.replaceAll(target, `https://${req.hostname}`);
            res.send(html);
        } else {
            res.send(Buffer.from(await resp.arrayBuffer()));
        }
    } catch (e) {
        console.error(`[${req.hostname}]`, e.message);
        res.status(502).send('Origin unavailable');
    }
});

// ─── Keep-alive пинг ───
const SELF = process.env.RENDER_EXTERNAL_URL;
if (SELF) {
    setInterval(() => fetch(SELF + '/health').catch(() => {}), 14 * 60_000);
}
app.get('/health', (req, res) => res.send('ok'));

app.listen(PORT, () => console.log(`Multi-proxy on port ${PORT}`));