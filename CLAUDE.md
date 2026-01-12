# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`dnsgeeo` is a concurrent DNS resolver and GeoIP enrichment CLI tool written in Go. It resolves hostnames (A/AAAA records) or accepts raw IPs and enriches them with geographic and ASN information using local MaxMind GeoLite2 or DB-IP MMDB databases.

## Build & Development

### Building
```bash
# Clean build
./install.sh

# Manual build (requires Go 1.21+)
go mod tidy
go build -o ./bin/dnsgeeo ./cmd/dnsgeeo
```

### Testing the CLI
```bash
# Requires GeoIP databases (see setup below)
./bin/dnsgeeo example.com --city-db ./data/GeoLite2-City.mmdb --asn-db ./data/GeoLite2-ASN.mmdb --pretty

# Test with multiple hosts
./bin/dnsgeeo --list "example.com,google.com,8.8.8.8" --city-db ./data/GeoLite2-City.mmdb
```

### Database Setup
The CLI requires at least one MMDB file (City or ASN). To download MaxMind GeoLite2 databases:
```bash
export MAXMIND_LICENSE_KEY=your_key_here
./install.sh
```

Without a license key, the installer builds the CLI but skips database downloads. You can manually provide DB-IP Lite or other compatible MMDB files via `--city-db` and `--asn-db` flags.

## Architecture

### Code Structure
```
cmd/dnsgeeo/main.go          # CLI entrypoint, flag parsing, orchestration
internal/dnsgeeo/dnsgeeo.go   # Core resolution & enrichment logic
```

### Key Components

**Round-Robin DNS Resolver (`RRResolver`)**
- Custom `net.Resolver` that rotates through configured DNS servers using atomic counter
- Default servers: `1.1.1.1:53`, `8.8.8.8:53`
- Thread-safe for concurrent use

**Batch Processing (`ResolveAndEnrichBatch`)**
- Opens GeoIP databases once per batch (via `openReadersFromEnv`)
- Spawns goroutines with configurable parallelism (default 64)
- Uses semaphore pattern (`chan struct{}`) to limit concurrency
- Processes both hostnames (DNS lookup) and raw IPs (direct enrichment)

**IP Enrichment (`EnrichIP`)**
- Uses LRU cache (`expirable.LRU`) to avoid repeated GeoIP lookups
- Queries both City (geo coordinates, region, city) and ASN (number, org) databases
- Database readers are passed as parameters to avoid race conditions

**Concurrency Model**
- Database readers must be opened BEFORE spawning goroutines (variables captured in closure)
- Results slice is pre-allocated; goroutines write to their assigned index (no locking needed)
- IP cache is thread-safe (LRU handles internal synchronization)

## Important Implementation Details

### Database Reader Lifecycle
Database readers (`*geoip2.Reader`) must be opened before goroutine spawning. The earlier implementation had a bug where `cityDB` and `asnDB` were referenced in goroutines before being initialized, causing undefined variable errors. Always follow this pattern:

```go
// CORRECT: Open DBs first
cityDB, asnDB := openReadersFromEnv(cfg)
defer closeDBs(cityDB, asnDB)

// Then spawn goroutines that capture these variables
for i, input := range inputs {
    go func(idx int, data string) {
        // Now cityDB and asnDB are in scope
        EnrichIP(ip, cityDB, asnDB)
    }(i, input)
}
```

### Boolean Literals
Go uses lowercase `true`/`false`, not `True`/`False` (common Python mistake).

### Configuration
The tool accepts configuration via:
1. CLI flags (parsed in `main.go`)
2. Environment variables: `GEOLITE2_CITY_DB`, `GEOLITE2_ASN_DB`

## Dependencies

- `github.com/oschwald/geoip2-golang` - MaxMind GeoIP2 database reader
- `github.com/hashicorp/golang-lru/v2` - Thread-safe expiring LRU cache

## Output Format

JSON array of `HostResult` objects:
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

## Common Flags

- `--list` - Comma-separated list of hosts/IPs
- `--dns` - Custom DNS servers (default: `1.1.1.1:53,8.8.8.8:53`)
- `--timeout-ms` - Per-host timeout in milliseconds (default: 2000)
- `--parallel` - Max concurrent lookups (default: 64)
- `--prefer-ipv6` - Include AAAA records (default: true)
- `--city-db` - Path to GeoLite2-City.mmdb
- `--asn-db` - Path to GeoLite2-ASN.mmdb
- `--pretty` - Pretty-print JSON output
