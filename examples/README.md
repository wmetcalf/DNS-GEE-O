# DNS-GEE-O Examples

This directory contains practical examples demonstrating various use cases for `dnsgeeo`.

## Prerequisites

Make sure you have built the tool:
```bash
cd ..
./install.sh
```

For GeoIP enrichment examples, you'll need the GeoLite2 databases. Set your MaxMind license key:
```bash
export MAXMIND_LICENSE_KEY=your_key_here
./install.sh
```

## Available Examples

### 1. Basic DNS Resolution (`basic-dns.sh`)

Simple DNS resolution examples without GeoIP enrichment.

**What you'll learn:**
- Resolving single and multiple domains
- Mixing domains and IP addresses
- IPv4-only lookups
- Using custom DNS servers

**Run it:**
```bash
chmod +x examples/basic-dns.sh
./examples/basic-dns.sh
```

### 2. Bulk Domain Processing (`bulk-domains.sh`)

Processing large lists of domains efficiently.

**What you'll learn:**
- Reading domains from files
- High-concurrency processing
- Performance tuning with `--parallel`
- Output to files
- Performance benchmarking

**Run it:**
```bash
chmod +x examples/bulk-domains.sh
./examples/bulk-domains.sh
```

### 3. GeoIP Enrichment (`geoip-enrichment.sh`)

Adding geographic and ASN information to IP addresses.

**What you'll learn:**
- Basic GeoIP lookups
- Enriching raw IP addresses
- Extracting country and city information
- ASN analysis
- Working with geographic data

**Prerequisites:** Requires GeoLite2 databases

**Run it:**
```bash
chmod +x examples/geoip-enrichment.sh
./examples/geoip-enrichment.sh
```

### 4. Malicious Domain Detection (`malware-detection.sh`)

Using Quad9's threat intelligence to identify malicious domains.

**What you'll learn:**
- Checking domains against Quad9 threat intelligence
- Filtering malicious domains from results
- Bulk security scanning
- Generating security reports

**Run it:**
```bash
chmod +x examples/malware-detection.sh
./examples/malware-detection.sh
```

### 5. Advanced Security Analysis (`security-analysis.sh`)

Comprehensive security analysis combining all features.

**What you'll learn:**
- Full security profiling (DNS + GeoIP + Threat Intel)
- Geographic risk assessment
- ASN-based threat correlation
- Exporting security data to CSV
- Advanced threat intelligence reporting

**Prerequisites:** Requires GeoLite2 databases

**Run it:**
```bash
chmod +x examples/security-analysis.sh
./examples/security-analysis.sh
```

### 6. WHOIS/RDAP + Domain Age (Python Helper)

The WHOIS/RDAP helper lives under `tools/` and can be used alongside `dnsgeeo`.

**Run it:**
```bash
tools/install_whois_tool.sh
~/.cache/dnsgeeo-whois-venv/bin/python tools/whois_rdap.py --list "example.com" --pretty
```

## Quick Reference

### Common Patterns

**Process domains from a file:**
```bash
./bin/dnsgeeo --list "$(cat domains.txt | tr '\n' ',')"
```

**Filter malicious domains:**
```bash
./bin/dnsgeeo --list "domain1.com,domain2.com" --check-malicious | \
  jq '.[] | select(.malicious == true)'
```

**Extract only IPs:**
```bash
./bin/dnsgeeo google.com | jq -r '.[].ips[].ip'
```

**Count resolved vs failed:**
```bash
./bin/dnsgeeo --list "$(cat domains.txt | tr '\n' ',')" | \
  jq '[.[] | .resolved] | [group_by(.)[] | {(.[0] | tostring): length}] | add'
```

**Get unique countries:**
```bash
./bin/dnsgeeo --list "domain1,domain2,domain3" \
  --city-db ./data/GeoLite2-City.mmdb | \
  jq -r '.[].ips[].geo.country_name' | sort -u
```

## Tips

1. **Performance**: Start with lower `--parallel` values (e.g., 10-20) and increase if needed
2. **Timeout**: Increase `--timeout-ms` for slow/unreliable networks
3. **Large Lists**: Use `--output` to save results to a file
4. **Pretty Print**: Use `--pretty` during development, omit for production (smaller output)
5. **Piping**: Use `jq` or `python` for advanced JSON processing

## Troubleshooting

**"No such host" errors:**
- Check your internet connection
- Verify DNS servers are reachable
- Try different DNS servers with `--dns`

**GeoIP database not found:**
- Run `./install.sh` with `MAXMIND_LICENSE_KEY` set
- Or manually download databases and specify paths with `--city-db` and `--asn-db`

**Slow performance:**
- Increase `--parallel` value
- Reduce `--timeout-ms` if appropriate
- Check network latency

## Additional Resources

- [Main README](../README.md) - Full documentation
- [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) - Free GeoIP databases
- [Quad9](https://www.quad9.net/) - Threat intelligence DNS service
