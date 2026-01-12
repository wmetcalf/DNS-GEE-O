#!/bin/bash
# Advanced Security Analysis Examples
# Combines DNS resolution, GeoIP enrichment, and threat detection

CITY_DB="./data/GeoLite2-City.mmdb"
ASN_DB="./data/GeoLite2-ASN.mmdb"

echo "=== Example 1: Full Security Profile ==="
./bin/dnsgeeo --list "google.com,github.com" \
  --check-malicious \
  --city-db "$CITY_DB" \
  --asn-db "$ASN_DB" \
  --pretty

echo -e "\n=== Example 2: Analyze Suspicious Domains ==="
cat > /tmp/suspicious-domains.txt << 'EOF'
google.com
isitblocked.org
cloudflare.com
EOF

./bin/dnsgeeo --list "$(cat /tmp/suspicious-domains.txt | tr '\n' ',')" \
  --check-malicious \
  --city-db "$CITY_DB" \
  --asn-db "$ASN_DB" | \
  python3 -c "
import json, sys

data = json.load(sys.stdin)

print('Threat Intelligence Report')
print('=' * 70)

for result in data:
    domain = result['domain']
    is_malicious = result.get('malicious', False)
    resolved = result['resolved']

    threat_level = '🔴 MALICIOUS' if is_malicious else '🟢 CLEAN'

    print(f'\nDomain: {domain}')
    print(f'Status: {threat_level}')
    print(f'Resolved: {resolved}')

    if resolved and result.get('ips'):
        for ip_data in result['ips']:
            print(f'\n  IP: {ip_data[\"ip\"]} ({ip_data[\"family\"]})')

            if 'geo' in ip_data:
                geo = ip_data['geo']
                country = geo.get('country_name', 'Unknown')
                city = geo.get('city', 'Unknown')
                print(f'  Location: {city}, {country}')

            if 'asn' in ip_data:
                asn = ip_data['asn']
                print(f'  ASN: AS{asn.get(\"number\", \"N/A\")} - {asn.get(\"organization\", \"Unknown\")}')

    if not resolved:
        print(f'  Error: {result.get(\"error\", \"Unknown error\")}')

    print('-' * 70)
"

echo -e "\n=== Example 3: Geographic Risk Assessment ==="
./bin/dnsgeeo --list "google.com,github.com,cloudflare.com" \
  --city-db "$CITY_DB" \
  --asn-db "$ASN_DB" | \
  python3 -c "
import json, sys
from collections import Counter

data = json.load(sys.stdin)

countries = []
for result in data:
    if result['resolved'] and result.get('ips'):
        for ip_data in result['ips']:
            if 'geo' in ip_data:
                country = ip_data['geo'].get('country_iso', 'Unknown')
                countries.append(country)

print('Geographic Distribution:')
for country, count in Counter(countries).most_common():
    print(f'  {country}: {count} IP(s)')
"

echo -e "\n=== Example 4: ASN-Based Threat Correlation ==="
./bin/dnsgeeo --list "google.com,github.com,microsoft.com" \
  --check-malicious \
  --city-db "$CITY_DB" \
  --asn-db "$ASN_DB" | \
  python3 -c "
import json, sys
from collections import defaultdict

data = json.load(sys.stdin)

asn_domains = defaultdict(list)

for result in data:
    domain = result['domain']
    is_malicious = result.get('malicious', False)

    if result['resolved'] and result.get('ips'):
        for ip_data in result['ips']:
            if 'asn' in ip_data:
                asn_num = ip_data['asn'].get('number')
                asn_org = ip_data['asn'].get('organization', 'Unknown')
                asn_domains[(asn_num, asn_org)].append({
                    'domain': domain,
                    'ip': ip_data['ip'],
                    'malicious': is_malicious
                })

print('ASN Analysis:')
print('=' * 70)
for (asn_num, asn_org), domains in asn_domains.items():
    print(f'\nAS{asn_num}: {asn_org}')
    for d in domains:
        status = '⚠️' if d['malicious'] else '✓'
        print(f'  {status} {d[\"domain\"]} -> {d[\"ip\"]}')
"

echo -e "\n=== Example 5: Export Security Data to CSV ==="
./bin/dnsgeeo --list "google.com,github.com,cloudflare.com" \
  --check-malicious \
  --city-db "$CITY_DB" \
  --asn-db "$ASN_DB" | \
  python3 -c "
import json, sys, csv

data = json.load(sys.stdin)

# Write to CSV
with open('/tmp/security-report.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['Domain', 'IP', 'Malicious', 'Country', 'City', 'ASN', 'Organization'])

    for result in data:
        domain = result['domain']
        is_malicious = 'Yes' if result.get('malicious') else 'No'

        if result['resolved'] and result.get('ips'):
            for ip_data in result['ips']:
                ip = ip_data['ip']
                country = ip_data.get('geo', {}).get('country_name', '')
                city = ip_data.get('geo', {}).get('city', '')
                asn_num = ip_data.get('asn', {}).get('number', '')
                asn_org = ip_data.get('asn', {}).get('organization', '')

                writer.writerow([domain, ip, is_malicious, country, city, asn_num, asn_org])

print('Security report exported to /tmp/security-report.csv')
" && cat /tmp/security-report.csv
