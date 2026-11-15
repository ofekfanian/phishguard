# PhishGuard

Real-time detection of phishing domains that impersonate protected brands.

Every HTTPS certificate issued anywhere in the world is recorded in public
[Certificate Transparency](https://certificate.transparency.dev/) logs. PhishGuard
listens to that stream, scores each new domain for brand impersonation, and exposes
the results through a REST API and a live dashboard.

Example: `leumi.co.il.verify-account.top` scores 100/100 because it embeds the
bank's real domain as a subdomain of an unrelated one, uses phishing keywords, and
sits on a TLD that is common in phishing campaigns.

## How it works

```
Certificate Transparency logs    ──►  Scorer  ──►  Database  ──►  REST API  ──►  Dashboard
   (or the built-in demo feed)      (0-100 + reasons)  (SQLite)     (FastAPI)
```

| File | Role |
| --- | --- |
| `phishguard/ct.py` | Live feed: follows public CT logs and parses each new certificate |
| `phishguard/sources.py` | Other feeds: a simulated demo feed and a CertStream client |
| `phishguard/scorer.py` | The detection engine. Every point in the score has a written reason |
| `phishguard/enrich.py` | Looks up each candidate's registration date over RDAP |
| `phishguard/pipeline.py` | De-duplicates domains, scores them, saves one detection per registered domain |
| `phishguard/store.py` | Database layer (SQLAlchemy) |
| `phishguard/api.py` | REST API and dashboard |
| `phishguard/config.py` | Protected brands and settings |

### What the scorer looks for

| Signal | Example | Points |
| --- | --- | --- |
| Lookalike characters (digits, Cyrillic/Greek letters, `rn` for `m`) | `paypa1.com`, `rnicrosoft.com` | 55 |
| Typosquatting (edit distance) | `paypol.com` | 50 |
| Brand name in a domain the brand does not own | `leumi-login.com` | 40 |
| Brand name hidden inside a longer word | `myleumionline.com` | 35 |
| Real domain embedded as a subdomain | `leumi.co.il.evil.top` | +20 |
| Phishing keywords (`login`, `verify`, `secure`...) | | +15 to +25 |
| TLD common in phishing | `.xyz`, `.top` | +15 |
| Punycode | `xn--pypal-4ve.com` | +10 |
| Domain registered in the last 30 days | | +15 |
| Domain registered more than 1 / 2 years ago | | -10 / -20 |

A domain is saved as a detection at 50 points or more. A brand name alone (40) is
deliberately below that, which keeps `mizrahi-family.com` out of the results.

### Domain age

Phishing domains are usually days old. For every domain that scores 35 or more,
PhishGuard asks the domain registry (over RDAP) when it was registered, and adjusts
the score. This is what separates `out1ooks.com` (registered months ago, kept) from
`playpal.uk` (registered in 2023, dropped). The lookup is skipped for TLDs that have
no RDAP server, such as `.il` and `.de`.

## Run it

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m phishguard
```

Open http://localhost:8000 for the dashboard and http://localhost:8000/docs for the
interactive API documentation. By default this runs on a simulated feed.

Run the tests:

```bash
.venv/bin/python -m pytest
```

### Live mode

```bash
PHISHGUARD_SOURCE=ct .venv/bin/python -m phishguard
```

PhishGuard downloads the public list of CT logs, picks the ones in use today, and
follows each of them directly. No account or API key is needed. Both generations of
logs are supported: the RFC 6962 JSON API and the newer tiled logs (static-ct-api),
which is where Let's Encrypt certificates are recorded.

Some logs rate-limit clients (HTTP 429). PhishGuard backs off and retries on its own.

A CertStream WebSocket server is also supported (`PHISHGUARD_SOURCE=certstream`),
but that mode has not been tested against a real server.

### Settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `PHISHGUARD_SOURCE` | `demo` | `demo`, `ct`, `certstream` or `none` |
| `PHISHGUARD_CT_LOGS` | discovered automatically | Comma-separated RFC 6962 log URLs to follow |
| `PHISHGUARD_CT_TILED_LOGS` | discovered automatically | Comma-separated tiled log URLs to follow |
| `PHISHGUARD_CERTSTREAM_URL` | `ws://localhost:8080/domains-only` | CertStream WebSocket URL |
| `PHISHGUARD_DB` | `sqlite:///phishguard.db` | Any SQLAlchemy database URL |
| `PHISHGUARD_THRESHOLD` | `50` | Minimum score to save a detection |
| `PHISHGUARD_ENRICH` | `1` in live mode, `0` in demo | Look up domain age over RDAP |

## API

| Endpoint | Description |
| --- | --- |
| `GET /api/detections?min_score=&brand=&limit=` | Latest suspicious domains |
| `GET /api/check?domain=` | Score any domain on demand |
| `GET /api/stats` | Throughput and detection counts |
| `GET /api/brands` | Protected brands |

## Security notes

- Domain names are attacker-controlled input. The dashboard inserts them as text
  only, never as HTML and never as clickable links.
- PhishGuard is passive: it reads public logs and registry records, and never connects
  to a suspicious site.

## Roadmap

- [x] Scoring engine, pipeline, API, dashboard, tests
- [x] Live mode: read CT logs directly
- [x] Read the newer tiled CT logs (static-ct-api), where Let's Encrypt certificates are logged
- [ ] Tune the scores and the list of official domains on real data
- [x] Enrichment: domain age (RDAP)
- [ ] Enrichment: DNS records, hosting provider
- [ ] Cross-check detections with URLhaus and Google Safe Browsing
- [ ] Alerts (Telegram or email) for high-severity detections
- [ ] PostgreSQL, Docker Compose, GitHub Actions CI
- [ ] Deploy to a public URL
