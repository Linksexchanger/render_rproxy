# Render Shield Proxy

Lightweight Cloudflare-like reverse proxy for [Render.com](https://render.com) free tier.

## Features

- **Reverse Proxy** — proxy multiple sites through one service
- **Auto-config** — sites and security settings loaded from remote JSON, auto-updates every 5 min
- **Per-domain Security** — each site has its own security rules with global defaults fallback
- **Smart Caching** — byte-limited in-memory cache for static assets (15MB cap, 50KB per item)
- **Memory Optimized** — large files streamed without buffering, periodic cleanup, strict limits
- **Bot Protection** — blocks known bad bots by User-Agent (configurable per domain)
- **Rate Limiting** — per-IP request limits, configurable per domain
- **WAF** — blocks SQL injection, XSS, path traversal, shell injection
- **JS Challenge** — automatic browser verification (Cloudflare-style, 3 sec)
- **Math CAPTCHA** — human-readable math challenge
- **hCaptcha** — optional hCaptcha integration
- **Under Attack Mode** — challenge all visitors, toggleable per domain via API
- **IP Allow/Block** — individual IPs and CIDR ranges per domain
- **Security Headers** — X-Frame-Options, X-Content-Type-Options, etc.
- **SNI Support** — correct TLS Server Name Indication for multi-domain origins on shared IP

## Quick Start

```bash
git clone https://github.com/you/render-shield-proxy.git
cd render-shield-proxy
npm install
```

## Deploy to Render

1. Push to GitHub
2. Render Dashboard → New → Web Service
3. Connect repository
4. Settings:
   - **Build Command:** `npm install`
   - **Start Command:** `node server.js`
   - **Plan:** Free
5. Environment Variables:

| Variable | Required | Description |
|----------|----------|-------------|
| `CONFIG_URL` | Yes | URL to your `sites.json` on origin server |
| `ADMIN_TOKEN` | Yes | Secret token for admin API endpoints |
| `SECRET` | No | Random string for cookie signing (auto-generated if empty) |

6. Add custom domains: Settings → Custom Domains

## Config Format

Host `sites.json` on your origin server. The proxy fetches it every 5 minutes.

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
        "allowed_ips": ["YOUR_IP"],
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

### Config Structure

| Field | Description |
|-------|-------------|
| `sites[].domains` | List of domains this site responds to |
| `sites[].origin` | Backend server URL (domain or IP with protocol) |
| `sites[].host` | Host header and SNI name sent to origin |
| `sites[].security` | Per-site security overrides (optional) |
| `security_defaults` | Global defaults, used when per-site setting is missing |

### Security Settings

Each setting can be specified per domain in `sites[].security` or globally in `security_defaults`. Per-domain settings take priority.

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `blocked_ips` | `string[]` | `[]` | IPs and CIDRs to block |
| `allowed_ips` | `string[]` | `[]` | IPs to always allow (bypass all checks) |
| `blocked_ua` | `string[]` | see defaults | User-Agent substrings to block |
| `rate_limit.window_s` | `number` | `60` | Rate limit window in seconds |
| `rate_limit.max` | `number` | `100` | Max requests per IP per window |
| `waf` | `boolean` | `true` | Enable WAF (SQLi, XSS, path traversal) |
| `challenge.mode` | `string` | `"off"` | Challenge mode |
| `challenge.type` | `string` | `"js"` | Challenge type |
| `challenge.duration_h` | `number` | `24` | Hours before re-challenge |
| `hcaptcha_sitekey` | `string` | `""` | hCaptcha site key |
| `hcaptcha_secret` | `string` | `""` | hCaptcha secret key |
| `security_headers` | `boolean` | `true` | Add security response headers |

### Challenge Modes

| Mode | Description |
|------|-------------|
| `off` | No challenge |
| `suspicious` | Challenge bots and empty User-Agents only |
| `all` | Challenge every visitor (Under Attack Mode) |

### Challenge Types

| Type | Description |
|------|-------------|
| `js` | Automatic JS check, 3 second wait, transparent to users |
| `math` | User solves a simple math problem (e.g. 7 + 3 = ?) |
| `hcaptcha` | hCaptcha widget (requires sitekey and secret) |

## API

All admin endpoints require `?token=ADMIN_TOKEN` query parameter.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Service status, per-domain settings, memory usage, stats |
| `/reload?token=X` | GET | Force config reload from CONFIG_URL |
| `/attack?token=X&on=true` | GET | Enable Under Attack Mode for all domains |
| `/attack?token=X&on=false` | GET | Disable Under Attack Mode for all domains |
| `/attack?token=X&domain=D&on=true` | GET | Enable Under Attack Mode for specific domain |
| `/attack?token=X&domain=D&on=false` | GET | Disable Under Attack Mode for specific domain |

### Health Response Example

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

## Architecture

```
User (Russia)          Render.com              Origin Server
┌──────────┐       ┌──────────────┐        ┌──────────────┐
│ Browser  │──────▶│ Shield Proxy │───────▶│ nginx / WP   │
│          │◀──────│              │◀───────│              │
└──────────┘       │ ✓ WAF        │        └──────────────┘
                   │ ✓ Rate Limit │
                   │ ✓ Bot Block  │
                   │ ✓ Challenge  │
                   │ ✓ Cache      │
                   └──────────────┘
```

## Memory Usage

Designed for Render.com free tier (512MB RAM):

| Component | Limit |
|-----------|-------|
| Static cache | 15MB total, 50KB per item |
| Large files | Streamed (>512KB), not buffered |
| Rate limit map | Auto-cleaned every 30s, max 5000 entries |
| Typical total | 60–120MB |

## WAF Rules

The built-in WAF blocks:

- SQL injection (`UNION SELECT`, `DROP TABLE`, `OR 1=1`, etc.)
- XSS (`<script>`, `javascript:`, `onerror=`, etc.)
- Path traversal (`../`, `%2e%2e/`)
- Shell injection (`; cat /etc/passwd`, `| wget`, etc.)

## Tips

- **Adding a new site:** edit `sites.json` on origin, wait 5 min or call `/reload`
- **Emergency:** call `/attack?on=true` to challenge all visitors immediately
- **PMA / admin panels:** use `"challenge": {"mode": "all", "type": "math"}` and restrict `allowed_ips`
- **Keep-alive:** the proxy pings itself every 14 min to prevent Render free tier sleep
- **Multiple sites:** one Render service handles all domains, fits within 750 free hours/month

## License

MIT
