# Redis-Backed Domain Signal Engine

**Date:** 2026-04-10
**Status:** Draft
**Approach:** Redis-backed signal lookups with opt-in activation

## Overview

Add a domain signal enrichment engine backed by Redis. When enabled via `--signals`, each queried domain is checked against multiple threat intelligence and reputation lists stored in Redis. Results appear as a `signals` object in the output alongside existing fields.

The feature is fully opt-in — when disabled (default), no Redis connection is made and output is unchanged.

## Motivation

dnsgeeo currently has domain intelligence scattered across multiple systems:
- LOLFSaaS matching in Go (file-based, per-request parsing)
- Afraid public domain detection in Python WHOIS tool (gated behind `--whois`)
- DDNS provider detection hardcoded in Python WHOIS tool
- PSL private suffix detection in Python WHOIS tool
- No URL shortener detection
- No suspicious TLD flagging
- No domain popularity ranking

Unifying these behind Redis provides: O(1) lookups, shared state across replicas, hot-reloadable data, and access to signals without requiring WHOIS to be enabled.

## Data Sources

### External Lists (downloaded by data_refresh.py)

| Source | URL | Format |
|---|---|---|
| Sublime: free_subdomain_hosts | `https://raw.githubusercontent.com/sublime-security/static-files/main/free_subdomain_hosts.txt` | One domain per line |
| Sublime: url_shorteners | `https://raw.githubusercontent.com/sublime-security/static-files/main/url_shorteners.txt` | One domain per line |
| Sublime: suspicious_tlds | `https://raw.githubusercontent.com/sublime-security/static-files/main/suspicious_tlds.txt` | One TLD per line |
| Sublime: free_file_hosts | `https://raw.githubusercontent.com/sublime-security/static-files/main/free_file_hosts.txt` | One domain per line |
| Sublime: free_email_providers | `https://raw.githubusercontent.com/sublime-security/static-files/main/free_email_providers.txt` | One domain per line |
| Sublime: disposable_email_providers | `https://raw.githubusercontent.com/sublime-security/static-files/main/disposable_email_providers.txt` | One domain per line |
| Sublime: parked_domain_nameservers | `https://raw.githubusercontent.com/sublime-security/static-files/main/parked_domain_nameservers.txt` | One NS domain per line |
| Sublime: tranco | `https://raw.githubusercontent.com/sublime-security/static-files/main/tranco_top_10k.csv` or `tranco_top_50k.csv` or `tranco.csv` | `rank,domain` CSV |
| PeterDaveHello: url-shorteners | `https://raw.githubusercontent.com/PeterDaveHello/url-shorteners/master/list` | One domain per line (comment lines start with `#`) |

### Local Data (already in repo/generated)

| Source | Path | Format |
|---|---|---|
| LOLFSaaS | `data/lolfsaas.json` | JSON array of service entries with domains, categories, abuse scores |
| Afraid public domains | `data/afraid_public_domains.txt` | One domain per line (generated weekly by GitHub Action) |
| Public Suffix List | `data/public_suffix_list.dat` | Standard PSL format (already refreshed by data_refresh.py) |

## Redis Schema

All keys are prefixed with `signals:` to namespace them within the shared Redis instance.

### Boolean Lookup Sets (SISMEMBER)

| Redis Key | Contents | Match Strategy |
|---|---|---|
| `signals:url_shorteners` | Merged Sublime + PeterDaveHello shortener domains | Exact match on registrable domain |
| `signals:free_subdomain_hosts` | Sublime free subdomain host domains | Suffix match: extract registrable domain from query, check membership |
| `signals:free_file_hosts` | Sublime free file host domains | Suffix match on registrable domain |
| `signals:free_email_providers` | Sublime free email provider domains | Exact match |
| `signals:disposable_email_providers` | Sublime disposable email provider domains | Exact match |
| `signals:suspicious_tlds` | Sublime suspicious TLDs (without leading dot) | Extract TLD from query domain, check membership |
| `signals:afraid_public_reg` | Afraid.org public registration domains | Suffix match: check if query domain is under a public reg domain |
| `signals:parked_nameservers` | Sublime parked domain nameserver domains | Match against WHOIS nameserver data when available |

### Ranked Sorted Set (ZSCORE)

| Redis Key | Contents | Lookup |
|---|---|---|
| `signals:tranco` | Domain → rank (score = rank number) | `ZSCORE signals:tranco <domain>` returns rank or nil |

Tranco tier controlled by `DNSGEEO_TRANCO_TIER` env var: `10k` (default), `50k`, or `1m`.

### LOLFSaaS Hash (HGET)

| Redis Key | Contents | Lookup |
|---|---|---|
| `signals:lolfsaas` | Domain/suffix → JSON blob with name, category, abuse scores | Exact domain check, then suffix decomposition for wildcard patterns |

LOLFSaaS entries with wildcard patterns (e.g. `*.workers.dev`) are stored with the suffix as key (e.g. `workers.dev`). The Go binary decomposes the query domain into suffix candidates and checks each.

Example entry value:
```json
{"name": "Cloudflare Workers", "category": "Cloud", "abuse": {"phishing": 1, "c2": 1, "exfil": 0, "payload": 0, "creds": 0}, "matched_pattern": "*.workers.dev"}
```

### PSL Private Suffixes Hash (HGET)

| Redis Key | Contents | Lookup |
|---|---|---|
| `signals:psl_private` | Private suffix → owner name | `HGET signals:psl_private <suffix>` returns owner or nil |

Parsed from `public_suffix_list.dat`. Example: `github.io` → `GitHub, Inc.`

### DDNS Providers Hash (HGET)

| Redis Key | Contents | Lookup |
|---|---|---|
| `signals:ddns_suffixes` | Domain suffix → provider name | Suffix match on query domain |

Loaded from the existing hardcoded data in `whois_rdap.py` (duckdns.org → duckdns, ddns.net → noip, etc.) plus any future additions.

## Data Ingestion

All data ingestion happens in `data_refresh.py`. No signal data is loaded from files by the Go binary when `--signals` is enabled.

### Ingestion Flow

1. Download all external lists to `data/sublime/` directory
2. Read local files (`lolfsaas.json`, `afraid_public_domains.txt`, `public_suffix_list.dat`)
3. Connect to Redis
4. For each data set, atomically replace the key: `DEL` + `SADD`/`ZADD`/`HSET` in a pipeline
5. Set a metadata key `signals:last_refresh` with timestamp

### URL Shortener Merging

Both Sublime and PeterDaveHello shortener lists are merged into one `signals:url_shorteners` set. The PeterDaveHello list has comment lines (starting with `#`) that are skipped during parsing. Duplicates are naturally handled by `SADD`.

### Refresh Cycle

Uses the existing `DNSGEEO_DATA_REFRESH_HOURS` (default 96h). The `refresh_signals()` function is called alongside the existing `refresh_lolfsaas()`, `refresh_psl()`, and `refresh_geoip()` calls.

### Startup Behavior

On container start, `data_refresh.py` runs with `DNSGEEO_DATA_FORCE_REFRESH=1` (existing behavior). This populates Redis with all signal data before the API/MCP servers start accepting requests.

## Go Binary Integration

### New Files

| File | Responsibility |
|---|---|
| `internal/dnsgeeo/signals.go` | `SignalEngine` struct, Redis connection, pipelined lookups, result types |
| `internal/dnsgeeo/signals_test.go` | Unit tests with mock Redis or miniredis |

### New Dependency

`github.com/redis/go-redis/v9` — the standard Go Redis client.

### SignalEngine

```go
type SignalEngine struct {
    client *redis.Client
}

type SignalResult struct {
    URLShortener           bool        `json:"url_shortener"`
    FreeSubdomainHost      bool        `json:"free_subdomain_host"`
    FreeFileHost           bool        `json:"free_file_host"`
    FreeEmailProvider      bool        `json:"free_email_provider"`
    DisposableEmailProvider bool       `json:"disposable_email_provider"`
    SuspiciousTLD          bool        `json:"suspicious_tld"`
    AfraidPublicReg        bool        `json:"afraid_public_reg"`
    ParkedNameservers      bool        `json:"parked_nameservers"`
    TrancoRank             *int        `json:"tranco_rank"`
    PSLIsPrivate           bool        `json:"psl_is_private"`
    PSLPrivateSuffix       string      `json:"psl_private_suffix,omitempty"`

    PSLPublicSuffix        string      `json:"psl_public_suffix,omitempty"`
    DDNSProvider           string      `json:"ddns_provider,omitempty"`
    LOLFSaaS               *LOLFSaaSMatch `json:"lolfsaas,omitempty"`
}
```

### Lookup Strategy

For each domain, the engine:

1. Extracts the TLD (e.g. `com`, `xyz`)
2. Decomposes domain into suffix candidates (e.g. `evil.workers.dev` → `workers.dev`, `dev`)
3. Builds a Redis pipeline with all lookups:
   - `SISMEMBER` for each boolean set
   - `ZSCORE` for Tranco
   - `HGET` for LOLFSaaS (exact + suffix candidates)
   - `HGET` for PSL private (suffix candidates)
   - `HGET` for DDNS suffixes (suffix candidates)
4. Executes pipeline (single Redis round-trip)
5. Assembles `SignalResult` from responses

For suffix matching (free_subdomain_hosts, free_file_hosts, afraid_public_reg, LOLFSaaS, PSL, DDNS): the domain is decomposed into progressively shorter suffixes. For `foo.bar.github.io`, check: `bar.github.io`, `github.io`, `io`. The first match wins (longest suffix).

For parked nameservers: if WHOIS data is available and contains nameservers, each NS domain is checked against `signals:parked_nameservers`. This lookup is only performed when WHOIS data is present in the result.

### Integration with ResolveAndEnrichBatch

The `SignalEngine` is constructed in `main.go` when `--signals` is enabled and passed to `ResolveAndEnrichBatch`. Inside the goroutine for each domain, after DNS resolution and enrichment, `engine.Lookup(domain)` is called. The result is stored in a new `Signals *SignalResult` field on `HostResult`. If the lookup fails, `Signals` is `nil` and `SignalsError` is set with the error string.

## Configuration

### CLI Flags

| Flag | Default | Env Var | Config Key | Description |
|---|---|---|---|---|
| `--signals` | `false` | `DNSGEEO_SIGNALS` | `signals` | Enable Redis-backed signal lookups |
| `--signals-redis` | (falls back to `DNSGEEO_WHOIS_REDIS_URL`) | `DNSGEEO_SIGNALS_REDIS` | `signals-redis` | Redis URL for signals |
| `--tranco-tier` | `10k` | `DNSGEEO_TRANCO_TIER` | `tranco-tier` | Tranco dataset size: `10k`, `50k`, `1m` |

### Redis URL Resolution

When `--signals` is enabled, the Redis URL is resolved in this order:
1. `--signals-redis` CLI flag
2. `DNSGEEO_SIGNALS_REDIS` env var
3. `DNSGEEO_WHOIS_REDIS_URL` env var (reuse WHOIS Redis)
4. `redis://localhost:6379/0` (fallback)

## Server Integration

### Python Servers

`server_common.py`:
- Add `signals: Optional[bool] = None` parameter to `run_dnsgeeo()`
- When `True`, append `--signals` to subprocess args
- When `None`, check `DNSGEEO_SIGNALS` env var

`api_server.py`:
- Add `signals: Optional[bool] = None` to `ResolveRequest`
- Pass through to `run_dnsgeeo()`

`mcp_server.py`:
- Add `signals: Optional[bool] = None` to `dnsgeeo_resolve()`
- Pass through to `run_dnsgeeo()`

### Docker Compose

Both `docker-compose.yml` and `docker-compose.lb.yml`:
```yaml
environment:
  DNSGEEO_SIGNALS: "true"
  DNSGEEO_TRANCO_TIER: "50k"
  # DNSGEEO_WHOIS_REDIS_URL already set — signals reuses it
```

### data_refresh.py

New `refresh_signals(redis_url, tranco_tier, data_dir, refresh_hours)` function:
1. Download external lists (Sublime, PeterDaveHello) to `data_dir/sublime/`
2. Read local files (LOLFSaaS, afraid, PSL)
3. Parse DDNS suffix providers
4. Connect to Redis and push all data atomically

Called from `main()` alongside existing refresh functions. Only runs when `DNSGEEO_SIGNALS=true` (no point downloading/loading if signals are disabled).

## Output Format

### HostResult with signals enabled

```json
{
  "domain": "evil.duckdns.org",
  "resolved": true,
  "dns_server": "8.8.8.8:53",
  "malicious": true,
  "ips": [...],
  "signals": {
    "url_shortener": false,
    "free_subdomain_host": true,
    "free_file_host": false,
    "free_email_provider": false,
    "disposable_email_provider": false,
    "suspicious_tld": false,
    "afraid_public_reg": false,
    "parked_nameservers": false,
    "tranco_rank": null,
    "psl_is_private": false,
    "psl_public_suffix": "org",
    "ddns_provider": "duckdns",
    "lolfsaas": {
      "name": "DuckDNS",
      "category": "C2 Channel",
      "abuse": {"phishing": 1, "c2": 1, "exfil": 0, "payload": 0, "creds": 0},
      "matched_pattern": "*.duckdns.org"
    }
  },
  "whois": {...}
}
```

### HostResult with signals disabled (default)

Output is identical to today. No `signals` field. LOLFSaaS continues to work via `--lolfsaas-db` file path with top-level `lolfsaas` field on HostResult.

## Backward Compatibility

- **`--signals` disabled (default):** Zero behavior change. No Redis connection. LOLFSaaS via `--lolfsaas-db` still works. WHOIS output unchanged.
- **`--signals` enabled without `--whois`:** `signals` object populated from Redis. WHOIS fields absent. `parked_nameservers` is always `false` (no NS data available without WHOIS).
- **`--signals` enabled with `--whois`:** `signals` object populated. WHOIS output retains existing fields (`psl_is_private`, `is_afraid_public_reg`, `ddns_providers`, etc.) for backward compat. Both are independently populated.
- **`--signals` enabled without `--lolfsaas-db`:** LOLFSaaS data comes from Redis. Top-level `lolfsaas` field is omitted; LOLFSaaS match appears inside `signals.lolfsaas`.
- **`--signals` enabled with `--lolfsaas-db`:** Both paths produce data. Top-level `lolfsaas` from file, `signals.lolfsaas` from Redis. Same data, two locations. Users should migrate to signals-only over time.

## Files Changed

| File | Change |
|---|---|
| `internal/dnsgeeo/signals.go` (new) | `SignalEngine`, `SignalResult`, Redis lookups |
| `internal/dnsgeeo/signals_test.go` (new) | Unit tests |
| `internal/dnsgeeo/dnsgeo.go` | Add `Signals *SignalResult` and `SignalsError string` to `HostResult`, thread engine through batch |
| `cmd/dnsgeeo/main.go` | Add `--signals`, `--signals-redis`, `--tranco-tier` flags, construct engine |
| `cmd/dnsgeeo/config_loader.go` | Add signal config keys |
| `cmd/dnsgeeo/config_loader_test.go` | Test signal config parsing |
| `tools/data_refresh.py` | Add `refresh_signals()` for downloading lists and loading into Redis |
| `tools/server_common.py` | Add `signals` parameter |
| `tools/api_server.py` | Expose `signals` parameter |
| `tools/mcp_server.py` | Expose `signals` parameter |
| `docker-compose.yml` | Add `DNSGEEO_SIGNALS` env var |
| `docker-compose.lb.yml` | Add `DNSGEEO_SIGNALS` env var |
| `go.mod` / `go.sum` | Add `github.com/redis/go-redis/v9` |

## Error Handling

**Redis unreachable at startup:** If `--signals` is enabled and Redis cannot be reached, the tool exits with an error. Signals are explicitly requested, so failing silently would be misleading.

**Redis unreachable during lookup:** If a signal lookup fails mid-batch (Redis goes down), the `signals` field is set to `null` and `signals_error` is set with the error message (e.g. `"redis connection refused"`). This mirrors the existing `whois`/`whois_error` pattern. Other enrichment (DNS, GeoIP, WHOIS) continues unaffected.

**Missing Redis keys:** If a signal set/hash doesn't exist in Redis (e.g. `data_refresh.py` hasn't run yet), `SISMEMBER` returns `false` and `ZSCORE`/`HGET` return nil. This produces a `signals` object with all booleans `false` and ranks/matches `null` — safe defaults.

## What Is NOT Changing

- Default behavior when `--signals` is not set
- WHOIS output format and fields
- LOLFSaaS file-based path when `--lolfsaas-db` is used without `--signals`
- GeoIP enrichment, DNS resolution, DoH transport
- Quad9 malicious domain check
- Concurrency model
