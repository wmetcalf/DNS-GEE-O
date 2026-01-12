#!/bin/bash
# GeoIP Enrichment Examples
# Note: Requires GeoLite2-City.mmdb and GeoLite2-ASN.mmdb databases

CITY_DB="./data/GeoLite2-City.mmdb"
ASN_DB="./data/GeoLite2-ASN.mmdb"

# Check if databases exist
if [ ! -f "$CITY_DB" ]; then
    echo "Warning: $CITY_DB not found. Run ./install.sh with MAXMIND_LICENSE_KEY set."
    echo "Or download databases manually and update paths."
    exit 1
fi

echo "=== Example 1: Basic GeoIP Lookup ==="
./bin/dnsgeeo google.com \
  --city-db "$CITY_DB" \
  --asn-db "$ASN_DB" \
  --pretty

echo -e "\n=== Example 2: Enrich Raw IP Addresses ==="
./bin/dnsgeeo --list "8.8.8.8,8.8.4.4,208.67.222.222" \
  --city-db "$CITY_DB" \
  --asn-db "$ASN_DB" \
  --pretty

echo -e "\n=== Example 3: Domain with Geographic Data ==="
./bin/dnsgeeo --list "github.com,netflix.com,amazon.com" \
  --city-db "$CITY_DB" \
  --asn-db "$ASN_DB" \
  --output /tmp/geo-results.json \
  --pretty

echo "Geographic data saved to /tmp/geo-results.json"

echo -e "\n=== Example 4: Extract Country Information ==="
./bin/dnsgeeo --list "google.com,baidu.com,yandex.ru" \
  --city-db "$CITY_DB" \
  --asn-db "$ASN_DB" | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
for result in data:
    domain = result['domain']
    if result['resolved'] and result['ips']:
        for ip_data in result['ips']:
            if 'geo' in ip_data:
                country = ip_data['geo'].get('country_name', 'Unknown')
                city = ip_data['geo'].get('city', 'Unknown')
                print(f'{domain}: {ip_data[\"ip\"]} -> {city}, {country}')
"

echo -e "\n=== Example 5: ASN Analysis ==="
./bin/dnsgeeo --list "google.com,cloudflare.com,aws.amazon.com" \
  --city-db "$CITY_DB" \
  --asn-db "$ASN_DB" | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
for result in data:
    domain = result['domain']
    if result['resolved'] and result['ips']:
        for ip_data in result['ips']:
            if 'asn' in ip_data:
                asn_num = ip_data['asn'].get('number', 'N/A')
                asn_org = ip_data['asn'].get('organization', 'Unknown')
                print(f'{domain}: AS{asn_num} ({asn_org})')
"
