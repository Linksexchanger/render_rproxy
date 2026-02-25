# Render Shield Proxy

Легковесный обратный прокси с защитой (аналог Cloudflare) для бесплатного тарифа [Render.com](https://render.com).

## Возможности

- **Обратный прокси** — проксирование нескольких сайтов через один сервис
- **Автоконфиг** — список сайтов и настройки безопасности загружаются из JSON, обновляются каждые 5 мин
- **Настройки per-domain** — у каждого сайта свои правила безопасности с глобальными значениями по умолчанию
- **Умное кэширование** — кэш статики с лимитом 15МБ в памяти, до 50КБ на элемент
- **Оптимизация памяти** — большие файлы передаются потоком, периодическая очистка, строгие лимиты
- **Защита от ботов** — блокировка по User-Agent (настраивается для каждого домена)
- **Ограничение частоты** — лимит запросов на IP, настраивается для каждого домена
- **WAF** — блокировка SQL-инъекций, XSS, обхода путей, shell-инъекций
- **IP Intelligence** — обнаружение VPN/Tor/Proxy через [ipquery.io](https://ipquery.io) ([GitHub](https://github.com/ipqwery))
- **JS-проверка** — автоматическая проверка браузера (как у Cloudflare, 3 сек)
- **Математическая CAPTCHA** — задача на сложение
- **hCaptcha** — опциональная интеграция
- **Режим атаки** — проверка всех посетителей, включается для каждого домена через API
- **Блокировка IP** — отдельные адреса и CIDR-диапазоны для каждого домена
- **Заголовки безопасности** — X-Frame-Options, X-Content-Type-Options и др.
- **Поддержка SNI** — правильный TLS Server Name Indication для мультидоменных серверов на одном IP

## Быстрый старт

```bash
git clone https://github.com/you/render-shield-proxy.git
cd render-shield-proxy
npm install
```

## Деплой на Render

1. Запушить на GitHub
2. Render Dashboard → New → Web Service
3. Подключить репозиторий
4. Настройки:
   - **Build Command:** `npm install`
   - **Start Command:** `node server.js`
   - **Plan:** Free
5. Переменные окружения:

| Переменная | Обязательна | Описание |
|------------|-------------|----------|
| `CONFIG_URL` | Да | URL к файлу `sites.json` на вашем сервере |
| `ADMIN_TOKEN` | Да | Секретный токен для API управления |
| `SECRET` | Нет | Строка для подписи cookies (генерируется автоматически) |

6. Добавить домены: Settings → Custom Domains

## Формат конфига

Файл `sites.json` размещается на вашем сервере. Прокси загружает его каждые 5 минут.

```json
{
  "sites": [
    {
      "domains": ["example.com", "www.example.com"],
      "origin": "https://origin.example.com",
      "host": "example.com",
      "security": {
        "blocked_ips": ["1.2.3.4", "10.0.0.0/8"],
        "allowed_ips": [],
        "blocked_ua": ["SemrushBot", "AhrefsBot"],
        "rate_limit": { "window_s": 60, "max": 60 },
        "waf": true,
        "challenge": { "mode": "off", "type": "js", "duration_h": 24 },
        "hcaptcha_sitekey": "",
        "hcaptcha_secret": "",
        "security_headers": true,
        "ip_intel": {
          "enabled": true,
          "block_vpn": false,
          "block_tor": true,
          "block_proxy": true,
          "challenge_vpn": true,
          "challenge_tor": false,
          "challenge_proxy": false,
          "block_risk_above": 0.85,
          "challenge_risk_above": 0.5
        }
      }
    },
    {
      "domains": ["admin.example.com"],
      "origin": "https://origin.example.com",
      "host": "admin.example.com",
      "security": {
        "allowed_ips": ["ВАШ_IP"],
        "rate_limit": { "window_s": 60, "max": 30 },
        "challenge": { "mode": "all", "type": "math", "duration_h": 1 },
        "ip_intel": {
          "enabled": true,
          "block_vpn": true,
          "block_tor": true,
          "block_proxy": true,
          "block_risk_above": 0.7
        }
      }
    }
  ],
  "security_defaults": {
    "blocked_ips": [],
    "allowed_ips": [],
    "blocked_ua": [
      "SemrushBot", "AhrefsBot", "MJ12bot", "DotBot",
      "BLEXBot", "PetalBot", "Bytespider", "GPTBot",
      "CCBot", "DataForSeoBot", "ClaudeBot"
    ],
    "rate_limit": { "window_s": 60, "max": 100 },
    "waf": true,
    "challenge": { "mode": "off", "type": "js", "duration_h": 24 },
    "hcaptcha_sitekey": "",
    "hcaptcha_secret": "",
    "security_headers": true,
    "ip_intel": {
      "enabled": false,
      "block_vpn": false,
      "block_tor": true,
      "block_proxy": true,
      "challenge_vpn": true,
      "challenge_tor": false,
      "challenge_proxy": false,
      "block_risk_above": 0.85,
      "challenge_risk_above": 0.5
    }
  }
}
```

### Структура конфига

| Поле | Описание |
|------|----------|
| `sites[].domains` | Список доменов, на которые отвечает сайт |
| `sites[].origin` | URL бэкенд-сервера (домен или IP с протоколом) |
| `sites[].host` | Заголовок Host и SNI-имя, отправляемое на origin |
| `sites[].security` | Настройки безопасности для сайта (необязательно) |
| `security_defaults` | Глобальные значения по умолчанию |

### Настройки безопасности

Каждый параметр может быть задан для домена в `sites[].security` или глобально в `security_defaults`. Настройки домена имеют приоритет.

| Параметр | Тип | По умолчанию | Описание |
|----------|-----|--------------|----------|
| `blocked_ips` | `string[]` | `[]` | IP и CIDR для блокировки |
| `allowed_ips` | `string[]` | `[]` | IP с полным доступом (пропускают все проверки) |
| `blocked_ua` | `string[]` | см. defaults | Подстроки User-Agent для блокировки |
| `rate_limit.window_s` | `number` | `60` | Окно лимита в секундах |
| `rate_limit.max` | `number` | `100` | Макс. запросов с одного IP за окно |
| `waf` | `boolean` | `true` | Включить WAF |
| `challenge.mode` | `string` | `"off"` | Режим проверки |
| `challenge.type` | `string` | `"js"` | Тип проверки |
| `challenge.duration_h` | `number` | `24` | Часов до повторной проверки |
| `hcaptcha_sitekey` | `string` | `""` | Ключ сайта hCaptcha |
| `hcaptcha_secret` | `string` | `""` | Секретный ключ hCaptcha |
| `security_headers` | `boolean` | `true` | Добавлять заголовки безопасности |
| `ip_intel` | `object` | см. ниже | Настройки IP Intelligence |

### Режимы проверки (challenge)

| Режим | Описание |
|-------|----------|
| `off` | Выключено |
| `suspicious` | Проверять только ботов и пустые User-Agent |
| `all` | Проверять всех посетителей (режим «Под атакой») |

### Типы проверки

| Тип | Описание |
|-----|----------|
| `js` | Автоматическая JS-проверка, 3 сек ожидание, прозрачна для пользователей |
| `math` | Пользователь решает пример (например 7 + 3 = ?) |
| `hcaptcha` | Виджет hCaptcha (нужны ключи) |

## IP Intelligence

Работает на основе [ipquery.io](https://ipquery.io) — бесплатный API для анализа IP-адресов ([GitHub](https://github.com/ipqwery)).

Обнаруживает и блокирует или проверяет посетителей, подключающихся через VPN, Tor, публичные прокси и IP дата-центров на основе скоринга рисков.

### Настройки IP Intel

Настраиваются для каждого домена в `security.ip_intel`:

| Параметр | Тип | По умолчанию | Описание |
|----------|-----|--------------|----------|
| `enabled` | `boolean` | `false` | Включить проверку IP |
| `block_vpn` | `boolean` | `false` | Блокировать VPN-соединения |
| `block_tor` | `boolean` | `true` | Блокировать выходные узлы Tor |
| `block_proxy` | `boolean` | `true` | Блокировать известные прокси |
| `challenge_vpn` | `boolean` | `true` | Показывать проверку пользователям VPN |
| `challenge_tor` | `boolean` | `false` | Показывать проверку пользователям Tor (если не заблокированы) |
| `challenge_proxy` | `boolean` | `false` | Показывать проверку пользователям прокси (если не заблокированы) |
| `block_risk_above` | `number` | `0.85` | Блокировать IP с оценкой риска выше (0.0–1.0) |
| `challenge_risk_above` | `number` | `0.5` | Показывать проверку при оценке риска выше |

### Как это работает

```
Новый посетитель → Запрос к ipquery.io → Кэш на 6 часов
                        │
                        ├── Tor + block_tor=true          → 403 Заблокирован
                        ├── VPN + block_vpn=true           → 403 Заблокирован
                        ├── Proxy + block_proxy=true       → 403 Заблокирован
                        ├── Риск > block_risk_above        → 403 Заблокирован
                        │
                        ├── VPN + challenge_vpn=true       → Страница проверки
                        ├── Риск > challenge_risk_above    → Страница проверки
                        │
                        └── Чистый IP                      → Пропустить
```

### Производительность и лимиты

- Результаты кэшируются 6 часов (макс. 3000 записей, ~300КБ)
- Макс. 5 параллельных запросов к API (предотвращает перегрузку)
- Таймаут 3 секунды (при недоступности API — пропускает)
- Статические файлы (JS, CSS, изображения) не проверяются
- Прошедшие проверку посетители не проверяются повторно

### Примеры конфигурации

**Публичный WordPress-сайт** — проверять VPN, блокировать Tor:
```json
"ip_intel": {
  "enabled": true,
  "block_tor": true,
  "challenge_vpn": true,
  "block_risk_above": 0.85
}
```

**Админ-панель** — блокировать все анонимайзеры:
```json
"ip_intel": {
  "enabled": true,
  "block_vpn": true,
  "block_tor": true,
  "block_proxy": true,
  "block_risk_above": 0.7
}
```

**Мягкий режим** — блокировать только высокий риск:
```json
"ip_intel": {
  "enabled": true,
  "block_risk_above": 0.9,
  "challenge_risk_above": 0.6
}
```

## API управления

Все административные endpoint требуют параметр `?token=ADMIN_TOKEN`.

| Endpoint | Метод | Описание |
|----------|-------|----------|
| `/health` | GET | Статус, настройки по доменам, память, статистика |
| `/reload?token=X` | GET | Принудительная перезагрузка конфига |
| `/attack?token=X&on=true` | GET | Включить режим «Под атакой» для всех доменов |
| `/attack?token=X&on=false` | GET | Выключить режим «Под атакой» для всех доменов |
| `/attack?token=X&domain=D&on=true` | GET | Включить режим «Под атакой» для конкретного домена |
| `/attack?token=X&domain=D&on=false` | GET | Выключить режим «Под атакой» для конкретного домена |
| `/ip-check?token=X&ip=1.2.3.4` | GET | Проверить данные IP Intelligence |

### Пример ответа /health

```json
{
  "ok": true,
  "configLoaded": true,
  "stats": {
    "req": 1523,
    "blocked": 47,
    "challenged": 12,
    "cached": 890,
    "waf": 3,
    "intel_hits": 340,
    "intel_misses": 28,
    "intel_blocks": 5,
    "intel_challenges": 8
  },
  "sites": [
    {
      "domain": "example.com",
      "challenge": "off",
      "waf": true,
      "rateLimit": 60,
      "ipIntel": true,
      "attack": false
    }
  ],
  "cache": 42,
  "cacheMB": "3.2",
  "rateSessions": 15,
  "intelCache": 156,
  "intelActive": 1,
  "memMB": 72.4
}
```

### Пример ответа /ip-check

```json
{
  "ip": "1.2.3.4",
  "info": {
    "vpn": true,
    "tor": false,
    "proxy": false,
    "datacenter": true,
    "risk": 0.72,
    "country": "NL",
    "isp": "DataCamp Limited",
    "ts": 1708678800000
  }
}
```

## Архитектура

```
Пользователь           Render.com                    Сервер-источник
┌──────────┐        ┌─────────────────┐            ┌──────────────┐
│ Браузер  │──────▶│  Shield Proxy   │──────────▶│ nginx / WP   │
│          │◀──────│                 │◀──────────│              │
└──────────┘        │ ✓ WAF           │            └──────────────┘
                    │ ✓ Rate Limit    │
                    │ ✓ Блок ботов    │            ┌──────────────┐
                    │ ✓ IP Intel ─────┼──────────▶│ ipquery.io   │
                    │ ✓ Challenge     │◀──────────│ (проверка IP)│
                    │ ✓ Кэш           │            └──────────────┘
                    └─────────────────┘
```

## Потребление памяти

Оптимизировано для бесплатного тарифа Render.com (512МБ RAM):

| Компонент | Лимит |
|-----------|-------|
| Кэш статики | 15МБ суммарно, 50КБ на элемент |
| Большие файлы | Потоковая передача (>512КБ) без буферизации |
| Таблица rate-limit | Очищается каждые 30 сек, макс. 5000 записей |
| Кэш IP Intel | Макс. 3000 записей (~300КБ), TTL 6 часов |
| Типичное потребление | 60–130МБ |

## Правила WAF

Встроенный WAF блокирует:

- SQL-инъекции (`UNION SELECT`, `DROP TABLE`, `OR 1=1` и т.д.)
- XSS (`<script>`, `javascript:`, `onerror=` и т.д.)
- Обход путей (`../`, `%2e%2e/`)
- Shell-инъекции (`; cat /etc/passwd`, `| wget` и т.д.)

## Советы

- **Добавление сайта:** отредактируйте `sites.json` на сервере, подождите 5 мин или вызовите `/reload`
- **Экстренная ситуация:** вызовите `/attack?on=true` для мгновенной проверки всех посетителей
- **PMA / админ-панели:** используйте `"challenge": {"mode": "all", "type": "math"}` с IP Intel блокировкой и ограничением `allowed_ips`
- **Keep-alive:** прокси пингует себя каждые 14 мин для предотвращения засыпания Render
- **Несколько сайтов:** один сервис Render обслуживает все домены, укладывается в 750 бесплатных часов/месяц
- **IP Intelligence:** включайте только для доменов, которым это необходимо, чтобы минимизировать обращения к API

## Сторонние сервисы

| Сервис | Использование | Лицензия / Условия |
|--------|---------------|---------------------|
| [ipquery.io](https://ipquery.io) ([GitHub](https://github.com/ipqwery)) | IP Intelligence — обнаружение VPN, Tor, прокси, оценка рисков | Бесплатный API, условия на [ipquery.io](https://ipquery.io) |
| [hCaptcha](https://www.hcaptcha.com) | Опциональная CAPTCHA-проверка | Бесплатный тариф, условия на [hcaptcha.com](https://www.hcaptcha.com/terms) |

## Лицензия

MIT — см. [LICENSE](LICENSE)
