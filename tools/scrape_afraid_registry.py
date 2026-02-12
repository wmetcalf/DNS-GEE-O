#!/usr/bin/env python3
"""Scrape public registration domains from freedns.afraid.org domain registry.

Walks through paginated registry pages (sorted so public domains appear first),
extracts domain names, and stops once non-public domains are encountered.

Output: one domain per line written to the specified output file.
"""

import argparse
import sys
import time
import urllib.error
import urllib.request

from bs4 import BeautifulSoup

BASE_URL = "https://freedns.afraid.org/domain/registry/"
DEFAULT_DELAY = 2.0
MAX_RETRIES = 3
RETRY_BACKOFF = 30  # seconds to wait on rate-limit before retrying

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "identity",
}


def fetch_page(page_num, delay, timeout=15):
    """Fetch a single registry page, with retry on rate-limit."""
    url = f"{BASE_URL}?page={page_num}&sort=2&q="
    for attempt in range(MAX_RETRIES):
        req = urllib.request.Request(url, headers=HEADERS)
        try:
            resp = urllib.request.urlopen(req, timeout=timeout)
            body = resp.read().decode("utf-8", errors="replace")
        except urllib.error.URLError as exc:
            print(f"  [page {page_num}] network error: {exc}", file=sys.stderr)
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_BACKOFF)
                continue
            return None

        if len(body) < 100:
            # Rate-limited: server returns bare "200 OK"
            print(
                f"  [page {page_num}] rate-limited, waiting {RETRY_BACKOFF}s (attempt {attempt + 1}/{MAX_RETRIES})",
                file=sys.stderr,
            )
            time.sleep(RETRY_BACKOFF)
            continue
        return body

    print(f"  [page {page_num}] failed after {MAX_RETRIES} retries", file=sys.stderr)
    return None


def parse_page(html):
    """Extract (domain, type) pairs from a registry page.

    Returns:
        list of (domain_name, domain_type) tuples
        total_pages (int or None)
    """
    soup = BeautifulSoup(html, "html.parser")

    # Extract total page count from title: "Domain Registry : Page X of Y"
    total_pages = None
    title = soup.find("title")
    if title:
        text = title.get_text()
        parts = text.split(" of ")
        if len(parts) == 2:
            try:
                total_pages = int(parts[1].strip())
            except ValueError:
                pass

    domains = []
    rows = soup.find_all("tr", class_=["trd", "trl"])
    for row in rows:
        tds = row.find_all("td")
        if len(tds) < 2:
            continue
        link = tds[0].find("a")
        if not link:
            continue
        domain_name = link.get_text(strip=True)
        domain_type = tds[1].get_text(strip=True)
        domains.append((domain_name, domain_type))

    return domains, total_pages


def scrape_all(delay=DEFAULT_DELAY, max_pages=None):
    """Scrape all public registration domains.

    Stops when a non-public domain is encountered or pages are exhausted.
    """
    all_domains = []
    page = 1
    total_pages = None

    while True:
        if max_pages and page > max_pages:
            print(f"Reached max pages limit ({max_pages})", file=sys.stderr)
            break

        label = f"Page {page}" + (f"/{total_pages}" if total_pages else "")
        print(f"Fetching {label}...", file=sys.stderr, end=" ", flush=True)

        html = fetch_page(page, delay)
        if html is None:
            print("FAILED", file=sys.stderr)
            break

        domains, tp = parse_page(html)
        if tp and total_pages is None:
            total_pages = tp

        if not domains:
            print("no domains found, stopping", file=sys.stderr)
            break

        public_count = 0
        hit_non_public = False
        for domain_name, domain_type in domains:
            if domain_type.lower() != "public":
                hit_non_public = True
                break
            all_domains.append(domain_name)
            public_count += 1

        print(f"{public_count} public domains", file=sys.stderr)

        if hit_non_public:
            print(
                f"Hit non-public domain type on page {page}, stopping.",
                file=sys.stderr,
            )
            break

        if total_pages and page >= total_pages:
            print("Reached last page.", file=sys.stderr)
            break

        page += 1
        time.sleep(delay)

    return all_domains


def main():
    parser = argparse.ArgumentParser(
        description="Scrape public registration domains from freedns.afraid.org"
    )
    parser.add_argument(
        "-o",
        "--output",
        default="data/afraid_public_domains.txt",
        help="Output file path (default: data/afraid_public_domains.txt)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=DEFAULT_DELAY,
        help=f"Delay between requests in seconds (default: {DEFAULT_DELAY})",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=None,
        help="Maximum number of pages to fetch (default: unlimited)",
    )
    parser.add_argument(
        "--min-domains",
        type=int,
        default=1000,
        help="Minimum domains required to accept the scrape (default: 1000)",
    )
    parser.add_argument(
        "--max-shrink-pct",
        type=float,
        default=50.0,
        help="Max allowed percentage shrink vs existing file (default: 50)",
    )
    args = parser.parse_args()

    domains = scrape_all(delay=args.delay, max_pages=args.max_pages)

    if not domains:
        print("ERROR: No domains scraped.", file=sys.stderr)
        return 1

    if len(domains) < args.min_domains:
        print(
            f"ERROR: Only scraped {len(domains)} domains, minimum is {args.min_domains}. "
            "Site may be down or rate-limiting. Refusing to write.",
            file=sys.stderr,
        )
        return 1

    import os

    # Check for excessive shrinkage vs existing file
    if os.path.isfile(args.output):
        with open(args.output, "r", encoding="utf-8") as f:
            existing_count = sum(1 for line in f if line.strip())
        if existing_count > 0:
            shrink_pct = (1 - len(domains) / existing_count) * 100
            if shrink_pct > args.max_shrink_pct:
                print(
                    f"ERROR: New list ({len(domains)}) is {shrink_pct:.1f}% smaller than "
                    f"existing ({existing_count}). Max allowed shrink is {args.max_shrink_pct}%. "
                    "Refusing to overwrite.",
                    file=sys.stderr,
                )
                return 1

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        for domain in domains:
            f.write(domain + "\n")

    print(
        f"\nDone: {len(domains)} public domains saved to {args.output}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
