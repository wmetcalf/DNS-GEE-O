#!/bin/bash
# Basic DNS Resolution Examples

echo "=== Example 1: Single Domain Lookup ==="
./bin/dnsgeeo --pretty google.com

echo -e "\n=== Example 2: Multiple Domains ==="
./bin/dnsgeeo --list "google.com,github.com,cloudflare.com" --pretty

echo -e "\n=== Example 3: Mix Domains and IPs ==="
./bin/dnsgeeo --list "google.com,8.8.8.8,8.8.4.4" --pretty

echo -e "\n=== Example 4: IPv4 Only ==="
./bin/dnsgeeo --prefer-ipv6=false --pretty google.com

echo -e "\n=== Example 5: Using Custom DNS Servers ==="
./bin/dnsgeeo --list "example.com,github.com" \
  --dns "8.8.8.8:53,8.8.4.4:53" \
  --pretty
