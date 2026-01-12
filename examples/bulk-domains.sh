#!/bin/bash
# Bulk Domain Processing Examples

echo "=== Example 1: Processing from a File ==="
# Create a sample domains file
cat > /tmp/domains.txt << 'EOF'
google.com
github.com
cloudflare.com
amazon.com
microsoft.com
apple.com
facebook.com
twitter.com
netflix.com
reddit.com
EOF

# Process all domains
./bin/dnsgeeo --list "$(cat /tmp/domains.txt | tr '\n' ',')" \
  --parallel 10 \
  --output /tmp/results.json \
  --pretty

echo "Results saved to /tmp/results.json"
cat /tmp/results.json | head -50

echo -e "\n=== Example 2: High Concurrency for Large Lists ==="
# Generate 50 domains
python3 << 'EOF' > /tmp/large-list.txt
domains = ["google.com", "github.com", "cloudflare.com"] * 17
for i, domain in enumerate(domains):
    print(f"{domain}")
EOF

time ./bin/dnsgeeo --list "$(cat /tmp/large-list.txt | tr '\n' ',')" \
  --parallel 100 \
  --timeout-ms 3000 | \
  python3 -c "import json,sys; data=json.load(sys.stdin); print(f'Processed {len(data)} domains')"

echo -e "\n=== Example 3: Performance Comparison ==="
echo "Low concurrency (--parallel 5):"
time ./bin/dnsgeeo --list "$(head -20 /tmp/large-list.txt | tr '\n' ',')" \
  --parallel 5 > /dev/null

echo -e "\nHigh concurrency (--parallel 50):"
time ./bin/dnsgeeo --list "$(head -20 /tmp/large-list.txt | tr '\n' ',')" \
  --parallel 50 > /dev/null
