# DNS-GEE-O

A dumb tool with an awesome theme song: https://suno.com/s/8hFKpK0zAaSaqEQ9

![DNS-GEE-O logo](dnsgeeologo.png)

DNS-GEE-O is a high-performance concurrent DNS resolver and GeoIP enrichment CLI tool written in Go. Resolve hostnames (A/AAAA records) or process raw IPs and enrich them with geographic location and ASN information using local MaxMind GeoLite2 or DB-IP MMDB databases.

## Features
- **Concurrent DNS Resolution**: Resolve multiple domains in parallel with configurable concurrency (default: 64)
- **Round-Robin DNS**: Distribute queries across multiple DNS servers (default: 8.8.8.8:53, 8.8.4.4:53)
- **GeoIP Enrichment**: Add geographic location data (country, region, city, coordinates) to IP addresses
- **ASN Lookup**: Identify Autonomous System Numbers and organizations
- **Malicious Domain Detection**: Integrate with Quad9's threat intelligence to flag known malicious domains
- **Optional WHOIS/RDAP**: External Python helper for WHOIS/RDAP metadata and domain age
- **IPv4 and IPv6 Support**: Query both A and AAAA records
- **IP Caching**: LRU cache (10,000 entries, 10-minute TTL) to avoid repeated GeoIP lookups
- **File Output**: Save results to JSON files
- **Pretty Printing**: Human-readable JSON output
- **No Database Required**: DNS resolution works without GeoIP databases (enrichment is optional)

## Quick install
Use the installer (requires `curl`, `tar`, `go>=1.23`):

```bash
# For MaxMind GeoLite2 (requires free license key env var)
export MAXMIND_LICENSE_KEY=YOUR_KEY_HERE
bash install.sh
# Binary will be in ./bin/dnsgeeo and DBs in ./data/
# A default config will be written to ~/.config/dnsgeeo/dnsgeeo.conf
```

If you don't have a MaxMind key, you can still run the installer to **build the CLI**; it will skip DB download and tell you how to provide your own `.mmdb` paths (e.g., DB-IP Lite).

Installer options:
- `./install.sh --user-bin` installs to `~/.local/bin` and `~/.local/share/dnsgeeo`
- `./install.sh --global-bin` installs to `/usr/local/bin` and `/usr/local/share/dnsgeeo`
- `./install.sh --bin-dir /path --data-dir /path --config-path /path`
- `./install.sh --no-config` skips writing the default config
- `./install.sh --skip-whois` skips Python WHOIS helper setup
- `WHOIS_VENV_DIR=/path ./install.sh` overrides where the WHOIS venv is created (global install defaults to `/usr/local/share/dnsgeeo/venv`)
- `DNSGEEO_TMP_DIR=/tmp/dnsgeeo ./install.sh` overrides the temporary build directory if `./.tmp` isn't writable

### Setup Scripts

Local setup (CLI + WHOIS helper):

```bash
tools/setup_local.sh
```

Docker setup (API + MCP + Redis):

```bash
tools/setup_docker.sh
```

Flags:
- `tools/setup_local.sh --skip-whois --skip-db --python-bin python3.12 --venv-dir /tmp/dnsgeeo-venv`
- `tools/setup_docker.sh --no-build --pull`
- `tools/setup_docker.sh --down`

## Usage

Defaults (when the installer writes a config): Google public DNS for resolution (8.8.8.8/8.8.4.4), Quad9 for malicious checks, WHOIS/RDAP enabled, and GeoIP paths set to the installed databases.

### Output Format

Each result is a JSON object with a stable shape for LLM parsing. Example (fields omitted for brevity):

```json
{
  "domain": "site.duckdns.org",
  "resolved": true,
  "dns_server": "8.8.8.8:53",
  "malicious": false,
  "ips": [
    {
      "ip": "1.2.3.4",
      "family": "v4",
      "geo": {"country_iso": "US", "country_name": "United States"},
      "asn": {"number": 12345, "organization": "Example ASN"}
    }
  ],
  "whois": {
    "domain": "site.duckdns.org",
    "root_domain": "duckdns.org",
    "is_afraid_hosted": false,
    "psl_is_private": true,
    "psl_public_registrable_domain": "duckdns.org",
    "psl_public_suffix": "org",
    "psl_registrable_domain": "site.duckdns.org",
    "psl_private_suffix": "duckdns.org",
    "psl_private_owner": "DuckDNS",
    "ddns_provider_by_suffix": "duckdns",
    "ddns_providers_by_ns": [],
    "ddns_providers": ["duckdns"]
  }
}
```

Notes:
- Booleans are always present.
- Arrays default to `[]` when unknown.
- `error` values are normalized: `nxdomain`, `timeout`, `servfail`, `refused`, `no_records`, `lookup_failed`.

### Basic DNS Resolution

```bash
# Resolve a single domain
./bin/dnsgeeo google.com

# Resolve multiple domains
./bin/dnsgeeo --list "google.com,github.com,cloudflare.com"

# Mix domains and IPs
./bin/dnsgeeo --list "google.com,8.8.8.8,github.com"
```

### With GeoIP Enrichment

```bash
# Use GeoIP databases
./bin/dnsgeeo google.com \
  --city-db ./data/GeoLite2-City.mmdb \
  --asn-db ./data/GeoLite2-ASN.mmdb \
  --pretty
```

### Malicious Domain Detection

```bash
# Check domains against Quad9 threat intelligence
./bin/dnsgeeo --list "google.com,isitblocked.org" \
  --check-malicious \
  --pretty
```

Enabled by default; use `--check-malicious=false` to disable.

### WHOIS / RDAP (External Helper)

The installer configures the WHOIS/RDAP helper by default. You can still install it manually (creates a venv under `~/.cache`):

```bash
tools/install_whois_tool.sh
```

Run DNS + WHOIS/RDAP in one shot (enabled by default; pass `--whois=false` to disable):

```bash
./bin/dnsgeeo --list "example.com" \
  --whois \
  --whois-tool ./tools/whois_rdap.py \
  --whois-python ~/.cache/dnsgeeo-whois-venv/bin/python \
  --pretty
```

The helper caches results by registrable (root) domain to avoid repeated WHOIS/RDAP lookups across subdomains. Cache defaults to `~/.cache/dnsgeeo-whois-cache.json` with a 24-hour TTL (Docker compose in this repo sets 48 hours via env).
Only successful WHOIS/RDAP results are cached. Cached responses include `whois.cache_hit=true`.
WHOIS/RDAP output includes `is_afraid_hosted` (always present; `true` when nameservers end with `.afraid.org`).
WHOIS/RDAP output includes `psl_is_private` (always present) when the hostname is under a PSL PRIVATE suffix (often multi-tenant or user-controlled subdomains), plus `psl_private_suffix` / `psl_public_suffix` for context. When available, `psl_private_owner` is populated from PSL private section comments. For private suffixes, WHOIS/RDAP queries use the private suffix apex (e.g., `duckdns.org`) rather than the full subdomain.
WHOIS/RDAP output includes DDNS provider hints based on suffix/NS matches: `ddns_provider_by_suffix`, `ddns_providers_by_ns`, and combined `ddns_providers` (always present; arrays are `[]` when unknown).

WHOIS/RDAP result fields are stable for LLM parsing (booleans always present; arrays default to `[]`).

You can also dump the PSL private suffix list (with owner comments) for programmatic use:

```bash
tools/whois_rdap.py --psl-private-list --pretty
```

Or via the Go CLI:

```bash
dnsgeeo --psl-private-list --pretty
```

### Custom DNS Servers

```bash
# Use specific DNS servers
./bin/dnsgeeo --list "example.com,google.com" \
  --dns "8.8.8.8:53,8.8.4.4:53"
```

### Performance Tuning

```bash
# Adjust concurrency for bulk lookups
./bin/dnsgeeo --list "$(cat domains.txt | tr '\n' ',')" \
  --parallel 100 \
  --timeout-ms 3000
```

### Output to File

```bash
# Save results to a file
./bin/dnsgeeo --list "google.com,github.com" \
  --output results.json \
  --pretty
```

### IPv4 Only

```bash
# Disable IPv6 lookups
./bin/dnsgeeo google.com --prefer-ipv6=false
```

## CLI Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--list` | string | | Comma-separated list of hostnames or IPs |
| `--dns` | string | `8.8.8.8:53,8.8.4.4:53` | Comma-separated DNS servers (host:port) |
| `--timeout-ms` | int | `2000` | Per-host lookup timeout in milliseconds |
| `--parallel` | int | `64` | Max concurrent lookups |
| `--prefer-ipv6` | bool | `true` | Also query AAAA (IPv6) addresses |
| `--city-db` | string | `$GEOLITE2_CITY_DB` | Path to GeoLite2-City.mmdb |
| `--asn-db` | string | `$GEOLITE2_ASN_DB` | Path to GeoLite2-ASN.mmdb |
| `--check-malicious` | bool | `true` | Check domains against Quad9 threat intelligence |
| `--whois` | bool | `true` | Include WHOIS/RDAP data via external tool |
| `--whois-tool` | string | | Path to `whois_rdap.py` |
| `--whois-python` | string | `python3` | Python executable for `whois_rdap.py` |
| `--whois-timeout-ms` | int | `20000` | Timeout for `whois_rdap.py` in milliseconds |
| `--psl-private-list` | bool | `false` | Output PSL private suffix list and exit |
| `--output` | string | | Output file path (default: stdout) |
| `--pretty` | bool | `false` | Pretty-print JSON output |
| `--config` | string | | Optional key=value config file (see below) |
| `--maxmind-license-key` | string | `$MAXMIND_LICENSE_KEY` | MaxMind license key used for GeoLite2 auto-downloads |
| `--db-update-hours` | int | `0` | Refresh GeoLite2 DBs if older than this many hours (0 disables) |

### Configuration Files

`dnsgeeo` accepts simple `key=value` config files (comments start with `#` or `;`). CLI flags always take precedence over config entries. Place configs anywhere and pass them via `--config /path/to/dnsgeeo.conf`, or drop a file into `~/.config/dnsgeeo/dnsgeeo.conf`, `/usr/local/etc/dnsgeeo.conf`, or `/etc/dnsgeeo.conf` to have it loaded automatically.

Example config:

```ini
# examples/dnsgeeo.conf
check-malicious=true
pretty=true
parallel=64
timeout-ms=2000
whois=true
whois-timeout-ms=20000
city-db=./data/GeoLite2-City.mmdb
asn-db=./data/GeoLite2-ASN.mmdb
```

## API + MCP

This repo includes a Python REST API and MCP server that wrap the CLI.

### Docker (API + MCP + Redis)

```bash
docker compose up --build
```

Environment variables:
- `DNSGEEO_WHOIS_REDIS_URL` (optional) - Redis cache for WHOIS/RDAP
- `DNSGEEO_WHOIS_CACHE_TTL_HOURS` (default: 24; docker-compose sets 48)
- `DNSGEEO_CITY_DB` / `DNSGEEO_ASN_DB` (override DB paths in container)
- `DNSGEEO_WHOIS_TOOL` / `DNSGEEO_WHOIS_PYTHON` (override WHOIS helper paths)

**Security Note:** Tool paths (`--whois-tool`, `--whois-python`) are **NOT exposed via API/MCP** for security. They can only be configured via CLI flags or environment variables on the server. API clients cannot inject custom tool paths. Python executables are validated against an allowlist or must be absolute paths, and tool paths must be `.py` files.

### REST API (FastAPI)

Start locally:

```bash
python -m tools.api_server
```

Example request:

```bash
curl -s http://localhost:8080/resolve \\
  -H 'content-type: application/json' \\
  -d '{\"domains\":[\"microsoft.com\"],\"check_malicious\":true,\"whois\":true}'
```

PSL private list:

```bash
curl -s http://localhost:8080/psl-private-list
```

With WHOIS timeout override:

```bash
curl -s http://localhost:8080/resolve \\
  -H 'content-type: application/json' \\
  -d '{\"domains\":[\"microsoft.com\"],\"check_malicious\":true,\"whois\":true,\"whois_timeout_ms\":20000}'
```

### MCP Server (fastmcp)

Start locally:

```bash
python -m tools.mcp_server
```

Start both in one process (API + MCP):

```bash
tools/serve_all.sh
```

Tool name:
- `dnsgeeo_resolve` with the same parameters as `/resolve`
- `dnsgeeo_psl_private_list` to fetch PSL private suffixes

Example MCP session (HTTP transport on port `9091` when using `docker compose`):

```bash
SESSION=$(curl -s -D - -o /dev/null -H 'Accept: application/json, text/event-stream' http://localhost:9091/mcp \\
  | awk 'tolower($1)==\"mcp-session-id:\"{print $2}' | tr -d '\\r')

curl -N -s -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' \\
  -H \"mcp-session-id: $SESSION\" \\
  -d '{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"clientInfo\":{\"name\":\"curl\",\"version\":\"0\"}}}' \\
  http://localhost:9091/mcp

curl -N -s -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' \\
  -H \"mcp-session-id: $SESSION\" \\
  -d '{\"jsonrpc\":\"2.0\",\"id\":\"2\",\"method\":\"tools/list\"}' \\
  http://localhost:9091/mcp

curl -N -s -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' \\
  -H \"mcp-session-id: $SESSION\" \\
  -d '{\"jsonrpc\":\"2.0\",\"id\":\"3\",\"method\":\"tools/call\",\"params\":{\"name\":\"dnsgeeo_resolve\",\"arguments\":{\"domains\":[\"microsoft.com\"],\"check_malicious\":true,\"whois\":true}}}' \\
  http://localhost:9091/mcp
```

## Makefile

Common targets:
- `make build`
- `make test`
- `make docker-build`
- `make docker-up`
- `make docker-down`
- `make api`
- `make mcp`
- `make install-whois`

See `examples/dnsgeeo.conf` for a reusable baseline and `examples/mon-colispickup.conf` for a working sample that mirrors:

```bash
./bin/dnsgeeo --check-malicious --pretty \
  --city-db ./data/GeoLite2-City.mmdb \
  --asn-db ./data/GeoLite2-ASN.mmdb \
  mon-colispickup.com
```

It also demonstrates enabling automatic GeoLite2 refreshes every 24 hours by setting `maxmind-license-key` and `db-update-hours`. Hosts (from `--list` or positional args) must still be supplied on the CLI so configs can be shared safely.

## Output Format

### Basic DNS Resolution

```json
[
  {
    "domain": "google.com",
    "resolved": true,
    "ips": [
      {
        "ip": "142.250.113.139",
        "family": "v4"
      },
      {
        "ip": "2607:f8b0:4023:1006::71",
        "family": "v6"
      }
    ]
  }
]
```

### With GeoIP Enrichment

```json
[
  {
    "domain": "example.com",
    "resolved": true,
    "ips": [
      {
        "ip": "93.184.216.34",
        "family": "v4",
        "geo": {
          "country_iso": "US",
          "country_name": "United States",
          "region": "California",
          "city": "Los Angeles",
          "latitude": 34.05,
          "longitude": -118.24
        },
        "asn": {
          "number": 15133,
          "organization": "EDGECAST"
        }
      }
    ]
  }
]
```

### With Malicious Detection

```json
[
  {
    "domain": "isitblocked.org",
    "resolved": true,
    "malicious": true,
    "ips": [
      {
        "ip": "74.208.236.124",
        "family": "v4"
      }
    ]
  }
]
```

### Failed Resolution

```json
[
  {
    "domain": "nonexistent-domain-12345.com",
    "resolved": false,
    "error": "nxdomain"
  }
]
```

## Performance

The tool is optimized for bulk DNS resolution with minimal overhead:

### Architecture Highlights

- **Concurrent Processing**: Up to 64 parallel lookups by default (configurable via `--parallel`)
- **Round-Robin DNS**: Load balancing across multiple DNS servers
- **Connection Reuse**: Single resolver instance reused across all lookups
- **IP Caching**: LRU cache (10,000 entries, 10-minute TTL) for GeoIP lookups
- **Memory Efficient**: Semaphore-based goroutine pooling prevents memory explosion
- **Proper DNS Library**: Uses `miekg/dns` with automatic UDP→TCP fallback

### Benchmarks

```bash
# 150 domains in ~120ms
time ./bin/dnsgeeo --list "$(cat large-list.txt)" --parallel 64

# Results:
# real    0m0.123s
# user    0m0.011s
# sys     0m0.013s
```

### Scalability

The `--parallel` flag controls **concurrency**, not **capacity**:
- Can process unlimited domains with any parallelism setting
- Only N goroutines run concurrently at any time
- Remaining domains queue and wait for available slots
- Example: 1000 domains with `--parallel 64` = max 64 concurrent, all 1000 processed

## Architecture

### Code Structure

```
cmd/dnsgeeo/main.go          # CLI entrypoint, flag parsing
internal/dnsgeeo/dnsgeeo.go   # Core resolution & enrichment logic
```

### Key Components

**Round-Robin DNS Resolver (`RRResolver`)**
- Custom `net.Resolver` that rotates through configured DNS servers
- Thread-safe atomic counter for server selection
- Single resolver instance reused for all lookups

**Batch Processing (`ResolveAndEnrichBatch`)**
- Spawns goroutines with configurable parallelism (semaphore pattern)
- Processes both hostnames (DNS lookup) and raw IPs (direct enrichment)
- Pre-allocated results array for lock-free writes

**IP Enrichment (`EnrichIP`)**
- Uses LRU cache to avoid repeated GeoIP lookups
- Queries both City and ASN databases
- Thread-safe caching

**Malicious Domain Detection (`CheckMaliciousDomain`)**
- Uses Quad9's threat intelligence DNS (9.9.9.9)
- Detects blocked domains via NXDOMAIN with RA flag = 0
- Checks **all domains** regardless of primary DNS resolution status (important for detecting malicious domains that may be blocked or unreachable)
- Uses `miekg/dns` library for proper DNS message parsing

## Examples Directory

See the [examples](examples/) directory for detailed use cases:

- **Basic DNS Resolution** - Simple domain lookups
- **Bulk Domain Processing** - Processing large lists from files
- **GeoIP Enrichment** - Adding geographic data to IPs
- **Malicious Domain Detection** - Security analysis workflows
- **Security Analysis** - Combining features for threat hunting

## Dependencies

- [github.com/oschwald/geoip2-golang](https://github.com/oschwald/geoip2-golang) - MaxMind GeoIP2 database reader
- [github.com/hashicorp/golang-lru/v2](https://github.com/hashicorp/golang-lru) - Thread-safe expiring LRU cache
- [github.com/miekg/dns](https://github.com/miekg/dns) - DNS library for raw DNS queries and flag parsing

## Notes on GeoIP Databases

- **MaxMind GeoLite2** (free): City & ASN — requires a free account and **license key** to download. Attribution is required.
- **DB-IP Lite** (free): City — monthly MMDB, **CC-BY 4.0** (attribution required). If you use DB-IP, pass its City `.mmdb` via `--city-db`.

### Attribution

If you ship this in a product, add attribution per your chosen dataset's license:
- **MaxMind**: "This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com."
- **DB-IP**: "IP Geolocation by DB-IP, https://db-ip.com"
