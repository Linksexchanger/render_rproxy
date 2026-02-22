const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const compression = require('compression');

const app = express();

// ─── Конфигурация ───
const TARGET = 'https://your-wordpress-server.com'; // ваш WP-сервер
const PORT = process.env.PORT || 3000;

// ─── Сжатие ответов ───
app.use(compression());

// ─── Кэширование статики в памяти ───
const cache = new Map();
const CACHE_TTL = 3600 * 1000;         // 1 час для статики
const MAX_CACHE_SIZE = 200;            // макс. записей в кэше

function getCached(key) {
    const item = cache.get(key);
    if (!item) return null;
    if (Date.now() - item.time > CACHE_TTL) {
        cache.delete(key);
        return null;
    }
    return item;
}

function setCache(key, data, contentType) {
    if (cache.size >= MAX_CACHE_SIZE) {
        // Удаляем самую старую запись
        const firstKey = cache.keys().next().value;
        cache.delete(firstKey);
    }
    cache.set(key, { data, contentType, time: Date.now() });
}

// ─── Обработка статики с кэшированием ───
app.get(/\.(js|css|png|jpg|jpeg|gif|ico|svg|woff2?|ttf|eot|map)$/i,
    async (req, res) => {
        const cacheKey = req.originalUrl;
        const cached = getCached(cacheKey);

        if (cached) {
            res.set('Content-Type', cached.contentType);
            res.set('X-Cache', 'HIT');
            res.set('Cache-Control', 'public, max-age=86400');
            res.set('Access-Control-Allow-Origin', '*');
            return res.send(cached.data);
        }

        try {
            const url = TARGET + req.originalUrl;
            const response = await fetch(url, {
                headers: {
                    'User-Agent': req.get('User-Agent') || 'WP-Proxy/1.0',
                    'Accept': req.get('Accept') || '*/*',
                    'Accept-Encoding': 'identity' // без сжатия от origin
                }
            });

            if (!response.ok) {
                return res.status(response.status).send('Error');
            }

            const contentType = response.headers.get('content-type') 
                                || 'application/octet-stream';
            const buffer = Buffer.from(await response.arrayBuffer());

            // Кэшируем
            setCache(cacheKey, buffer, contentType);

            res.set('Content-Type', contentType);
            res.set('X-Cache', 'MISS');
            res.set('Cache-Control', 'public, max-age=86400');
            res.set('Access-Control-Allow-Origin', '*');
            res.send(buffer);
        } catch (err) {
            console.error('Static fetch error:', err.message);
            res.status(502).send('Proxy error');
        }
    }
);

// ─── Всё остальное (HTML, API, wp-admin) — проксирование ───
app.use('/', createProxyMiddleware({
    target: TARGET,
    changeOrigin: true,
    selfHandleResponse: false,

    // Подмена ссылок в HTML на домен прокси
    onProxyRes(proxyRes, req, res) {
        // Убираем заголовки безопасности origin-сервера
        delete proxyRes.headers['content-security-policy'];
        delete proxyRes.headers['x-frame-options'];
        
        // Для кук — подменяем домен
        const setCookie = proxyRes.headers['set-cookie'];
        if (setCookie) {
            proxyRes.headers['set-cookie'] = setCookie.map(cookie =>
                cookie.replace(/domain=[^;]+/gi, '')
                      .replace(/secure;?/gi, '')
            );
        }
    },

    // Логирование ошибок
    onError(err, req, res) {
        console.error('Proxy error:', err.message);
        res.status(502).json({ error: 'Origin server unavailable' });
    }
}));

app.listen(PORT, () => {
    console.log(`WP Proxy running on port ${PORT}`);
    console.log(`Proxying to: ${TARGET}`);
});

// Пинг самого себя каждые 14 минут
const SELF_URL = process.env.RENDER_EXTERNAL_URL;
if (SELF_URL) {
    setInterval(() => {
        fetch(SELF_URL + '/health').catch(() => {});
    }, 14 * 60 * 1000);
}

app.get('/health', (req, res) => res.send('ok'));