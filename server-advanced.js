// server-advanced.js
const express = require('express');
const compression = require('compression');
const { Transform } = require('stream');

const app = express();
const TARGET = 'https://your-wordpress-server.com';
const PORT = process.env.PORT || 3000;

// Домен прокси (Render назначит автоматически)
const PROXY_DOMAIN = process.env.RENDER_EXTERNAL_URL 
                     || 'https://your-app.onrender.com';

app.use(compression());

// ─── Кэш статики ───
const staticCache = new Map();
const CACHE_TTL = 3600_000;

// ─── Статика с кэшем ───
app.get(/\.(js|css|png|jpg|jpeg|gif|ico|svg|woff2?|ttf|eot|map)$/i,
    async (req, res) => {
        const key = req.originalUrl;
        const cached = staticCache.get(key);

        if (cached && Date.now() - cached.time < CACHE_TTL) {
            res.set('Content-Type', cached.type);
            res.set('X-Cache', 'HIT');
            res.set('Cache-Control', 'public, max-age=86400');
            return res.send(cached.data);
        }

        try {
            const resp = await fetch(TARGET + req.originalUrl, {
                headers: { 'Accept-Encoding': 'identity' }
            });
            if (!resp.ok) return res.sendStatus(resp.status);

            const type = resp.headers.get('content-type');
            const data = Buffer.from(await resp.arrayBuffer());

            if (staticCache.size > 500) {
                const oldest = staticCache.keys().next().value;
                staticCache.delete(oldest);
            }
            staticCache.set(key, { data, type, time: Date.now() });

            res.set('Content-Type', type);
            res.set('X-Cache', 'MISS');
            res.set('Cache-Control', 'public, max-age=86400');
            res.send(data);
        } catch (e) {
            res.status(502).send('Proxy error');
        }
    }
);

// ─── HTML/динамика — с подменой URL ───
app.use(async (req, res) => {
    try {
        const headers = { ...req.headers };
        headers.host = new URL(TARGET).host;
        delete headers['accept-encoding']; // получаем без сжатия

        const resp = await fetch(TARGET + req.originalUrl, {
            method: req.method,
            headers,
            body: ['GET', 'HEAD'].includes(req.method) ? undefined : req,
            redirect: 'manual'
        });

        // Обработка редиректов
        if ([301, 302, 303, 307, 308].includes(resp.status)) {
            let location = resp.headers.get('location') || '';
            location = location.replace(TARGET, PROXY_DOMAIN);
            res.redirect(resp.status, location);
            return;
        }

        // Копируем заголовки
        const contentType = resp.headers.get('content-type') || '';
        res.status(resp.status);
        res.set('Content-Type', contentType);

        // Куки — убираем привязку к домену
        const cookies = resp.headers.getSetCookie?.() || [];
        cookies.forEach(c => {
            res.append('Set-Cookie',
                c.replace(/domain=[^;]+;?/gi, '')
                 .replace(/secure;?/gi, '')
            );
        });

        // HTML — подменяем URL сервера на URL прокси
        if (contentType.includes('text/html')) {
            let html = await resp.text();
            const originHost = new URL(TARGET).host;

            // Заменяем все ссылки на origin → proxy
            html = html
                .replaceAll(TARGET, PROXY_DOMAIN)
                .replaceAll(`//${originHost}`, 
                            `//${new URL(PROXY_DOMAIN).host}`);

            res.send(html);
        } else {
            // Бинарные данные — отдаём как есть
            const buffer = Buffer.from(await resp.arrayBuffer());
            res.send(buffer);
        }
    } catch (e) {
        console.error('Proxy error:', e.message);
        res.status(502).send('Origin unavailable');
    }
});

app.listen(PORT, () => {
    console.log(`Advanced WP Proxy on port ${PORT}`);
    console.log(`${PROXY_DOMAIN} → ${TARGET}`);
});

// Пинг самого себя каждые 14 минут
const SELF_URL = process.env.RENDER_EXTERNAL_URL;
if (SELF_URL) {
    setInterval(() => {
        fetch(SELF_URL + '/health').catch(() => {});
    }, 14 * 60 * 1000);
}

app.get('/health', (req, res) => res.send('ok'));