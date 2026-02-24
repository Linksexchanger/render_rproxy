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
        "security_headers": true
      }
    },
    {
      "domains": ["admin.example.com"],
      "origin": "https://origin.example.com",
      "host": "admin.example.com",
      "security": {
        "allowed_ips": ["ВАШ_IP"],
        "rate_limit": { "window_s": 60, "max": 30 },
        "challenge": { "mode": "all", "type": "math", "duration_h": 1 }
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
    "security_headers": true
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
    "waf": 3
  },
  "sites": [
    {
      "domain": "example.com",
      "challenge": "off",
      "waf": true,
      "rateLimit": 60,
      "attack": false
    },
    {
      "domain": "admin.example.com",
      "challenge": "all",
      "waf": true,
      "rateLimit": 30,
      "attack": false
    }
  ],
  "cache": 42,
  "cacheMB": "3.2",
  "rateSessions": 15,
  "memMB": 67.3
}
```

## Архитектура

```
Пользователь (РФ)      Render.com              Сервер-источник
┌──────────┐        ┌──────────────┐        ┌──────────────┐
│ Браузер  │───────▶│ Shield Proxy │───────▶│ nginx / WP   │
│          │◀───────│              │◀───────│              │
└──────────┘        │ ✓ WAF        │        └──────────────┘
                    │ ✓ Rate Limit │
                    │ ✓ Блок ботов │
                    │ ✓ Challenge  │
                    │ ✓ Кэш       │
                    └──────────────┘
```

## Потребление памяти

Оптимизировано для бесплатного тарифа Render.com (512МБ RAM):

| Компонент | Лимит |
|-----------|-------|
| Кэш статики | 15МБ суммарно, 50КБ на элемент |
| Большие файлы | Потоковая передача (>512КБ) без буферизации |
| Таблица rate-limit | Очищается каждые 30 сек, макс. 5000 записей |
| Типичное потребление | 60–120МБ |

## Правила WAF

Встроенный WAF блокирует:

- SQL-инъекции (`UNION SELECT`, `DROP TABLE`, `OR 1=1` и т.д.)
- XSS (`<script>`, `javascript:`, `onerror=` и т.д.)
- Обход путей (`../`, `%2e%2e/`)
- Shell-инъекции (`; cat /etc/passwd`, `| wget` и т.д.)

## Советы

- **Добавление сайта:** отредактируйте `sites.json` на сервере, подождите 5 мин или вызовите `/reload`
- **Экстренная ситуация:** вызовите `/attack?on=true` для мгновенной проверки всех посетителей
- **PMA / админ-панели:** используйте `"challenge": {"mode": "all", "type": "math"}` и ограничьте `allowed_ips`
- **Keep-alive:** прокси пингует себя каждые 14 мин для предотвращения засыпания Render
- **Несколько сайтов:** один сервис Render обслуживает все домены, укладывается в 750 бесплатных часов/месяц

## Лицензия

MIT
