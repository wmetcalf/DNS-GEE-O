#!/usr/bin/env python3
"""Refresh all dnsgeeo data sources if stale."""
import os
import sys
import time
import urllib.request


def log(msg):
    sys.stderr.write(msg + "\n")


def needs_refresh(path, refresh_hours):
    if refresh_hours <= 0:
        return False
    if not os.path.exists(path):
        return True
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return True
    age_hours = (time.time() - mtime) / 3600.0
    return age_hours >= refresh_hours


def download_url(url, dest_path):
    """Download a URL to a file atomically."""
    tmp_path = dest_path + ".tmp"
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as response, open(tmp_path, "wb") as out:
            out.write(response.read())
        os.replace(tmp_path, dest_path)
        return True
    except Exception as exc:
        log(f"Download failed ({url}): {exc}")
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        return False


def refresh_lolfsaas(dest_path, refresh_hours):
    if not needs_refresh(dest_path, refresh_hours):
        return
    log("Refreshing LOLFSaaS data...")
    url = "https://raw.githubusercontent.com/lolfsaas/lolfsaas.github.io/main/data.json"
    if download_url(url, dest_path):
        log(f"Updated {dest_path}")


def refresh_psl(dest_path, refresh_hours):
    if not needs_refresh(dest_path, refresh_hours):
        return
    log("Refreshing Public Suffix List...")
    url = "https://publicsuffix.org/list/public_suffix_list.dat"
    if download_url(url, dest_path):
        log(f"Updated {dest_path}")


def refresh_signals(redis_url, tranco_tier, data_dir, refresh_hours):
    """Download signal lists and load into Redis."""
    sublime_dir = os.path.join(data_dir, "sublime")
    os.makedirs(sublime_dir, exist_ok=True)

    # External list sources
    SUBLIME_BASE = "https://raw.githubusercontent.com/sublime-security/static-files/main"
    SUBLIME_LISTS = {
        "free_subdomain_hosts.txt": "signals:free_subdomain_hosts",
        "url_shorteners.txt": None,  # merged with PeterDaveHello
        "suspicious_tlds.txt": "signals:suspicious_tlds",
        "free_file_hosts.txt": "signals:free_file_hosts",
        "free_email_providers.txt": "signals:free_email_providers",
        "disposable_email_providers.txt": "signals:disposable_email_providers",
        "parked_domain_nameservers.txt": "signals:parked_nameservers",
    }
    TRANCO_FILES = {
        "10k": "tranco_top_10k.csv",
        "50k": "tranco_top_50k.csv",
        "1m": "tranco.csv",
    }
    PETERDAVEHELLO_URL = "https://raw.githubusercontent.com/PeterDaveHello/url-shorteners/master/list"

    # Download external lists
    for filename in SUBLIME_LISTS:
        dest = os.path.join(sublime_dir, filename)
        if needs_refresh(dest, refresh_hours):
            log(f"Downloading {filename}...")
            download_url(f"{SUBLIME_BASE}/{filename}", dest)

    # Download PeterDaveHello shorteners
    pdh_dest = os.path.join(sublime_dir, "peterdavehello_shorteners.txt")
    if needs_refresh(pdh_dest, refresh_hours):
        log("Downloading PeterDaveHello url-shorteners...")
        download_url(PETERDAVEHELLO_URL, pdh_dest)

    # Download alexandrosmagos/dyn-dns-list
    DYNDSN_URL = "https://raw.githubusercontent.com/alexandrosmagos/dyn-dns-list/master/links.csv"
    dyndns_dest = os.path.join(sublime_dir, "dyn_dns_list.csv")
    if needs_refresh(dyndns_dest, refresh_hours):
        log("Downloading dyn-dns-list...")
        download_url(DYNDSN_URL, dyndns_dest)

    # Download Tranco
    tranco_file = TRANCO_FILES.get(tranco_tier, "tranco_top_10k.csv")
    tranco_dest = os.path.join(sublime_dir, tranco_file)
    if needs_refresh(tranco_dest, refresh_hours):
        log(f"Downloading Tranco ({tranco_tier})...")
        download_url(f"{SUBLIME_BASE}/{tranco_file}", tranco_dest)

    # Now load everything into Redis
    try:
        import redis as redispy
    except ImportError:
        log("WARNING: redis package not installed; skipping signal loading")
        return

    try:
        r = redispy.from_url(redis_url)
        r.ping()
    except Exception as exc:
        log(f"Redis connection failed: {exc}")
        return

    pipe = r.pipeline()

    # Helper to load a text file into a Redis set
    def load_set(filepath, redis_key):
        if not os.path.exists(filepath):
            return
        pipe.delete(redis_key)
        with open(filepath) as f:
            entries = [line.strip().lower() for line in f
                       if line.strip() and not line.startswith("#")]
        if entries:
            pipe.sadd(redis_key, *entries)

    # Load Sublime sets
    for filename, redis_key in SUBLIME_LISTS.items():
        if redis_key is not None:
            load_set(os.path.join(sublime_dir, filename), redis_key)

    # Load merged URL shorteners (Sublime + PeterDaveHello)
    shortener_entries = set()
    for path in [os.path.join(sublime_dir, "url_shorteners.txt"), pdh_dest]:
        if os.path.exists(path):
            with open(path) as f:
                for line in f:
                    line = line.strip().lower()
                    if line and not line.startswith("#"):
                        shortener_entries.add(line)
    if shortener_entries:
        pipe.delete("signals:url_shorteners")
        pipe.sadd("signals:url_shorteners", *shortener_entries)

    # Load afraid public registration domains
    afraid_path = os.path.join(data_dir, "afraid_public_domains.txt")
    load_set(afraid_path, "signals:afraid_public_reg")

    # Load Tranco as sorted set
    if os.path.exists(tranco_dest):
        pipe.delete("signals:tranco")
        with open(tranco_dest) as f:
            mapping = {}
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(",", 1)
                if len(parts) == 2:
                    try:
                        rank = int(parts[0])
                        domain = parts[1].strip().lower()
                        mapping[domain] = rank
                    except ValueError:
                        continue
            if mapping:
                pipe.zadd("signals:tranco", mapping)

    # Load LOLFSaaS as hash
    lolfsaas_path = os.path.join(data_dir, "lolfsaas.json")
    if os.path.exists(lolfsaas_path):
        import json as jsonmod
        pipe.delete("signals:lolfsaas")
        with open(lolfsaas_path) as f:
            entries = jsonmod.load(f)
        for entry in entries:
            for domain in entry.get("domains", []):
                domain = domain.strip().lower()
                if not domain:
                    continue
                if domain.startswith("*."):
                    key = domain[2:]  # "*.workers.dev" → "workers.dev"
                    blob = jsonmod.dumps({
                        "name": entry.get("name", ""),
                        "category": entry.get("category", ""),
                        "abuse": entry.get("abuse", {}),
                        "matched_pattern": domain,
                    })
                    pipe.hset("signals:lolfsaas", key, blob)
                else:
                    blob = jsonmod.dumps({
                        "name": entry.get("name", ""),
                        "category": entry.get("category", ""),
                        "abuse": entry.get("abuse", {}),
                        "matched_pattern": domain,
                    })
                    pipe.hset("signals:lolfsaas", domain, blob)

    # Load PSL private suffixes — just track which suffixes are private (boolean)
    psl_path = os.path.join(data_dir, "public_suffix_list.dat")
    if os.path.exists(psl_path):
        pipe.delete("signals:psl_private")
        in_private = False
        with open(psl_path) as f:
            for line in f:
                line = line.strip()
                if line == "// ===BEGIN PRIVATE DOMAINS===":
                    in_private = True
                    continue
                if not in_private or not line or line.startswith("//"):
                    continue
                suffix = line.lstrip("*.!").lower()
                if suffix:
                    pipe.hset("signals:psl_private", suffix, "1")

    # Load DDNS suffix providers as hash
    ddns_suffixes = {
        "duckdns.org": "duckdns",
        "dedyn.io": "desec_dedyn",
        "ddns.net": "noip",
        "dynv6.net": "dynv6",
        "dynu.net": "dynu",
        "changeip.com": "changeip",
        "dnsexit.com": "dnsexit",
    }
    pipe.delete("signals:ddns_suffixes")
    for suffix, provider in ddns_suffixes.items():
        pipe.hset("signals:ddns_suffixes", suffix, provider)

    # Load dyn-dns-list as hash (domain → provider)
    if os.path.exists(dyndns_dest):
        pipe.delete("signals:ddns_domains")
        with open(dyndns_dest) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("Domain,"):
                    continue
                parts = line.split(",", 3)
                if len(parts) >= 3:
                    domain = parts[0].strip().lower()
                    provider = parts[2].strip().lower()
                    if domain and provider:
                        pipe.hset("signals:ddns_domains", domain, provider)

    # Set refresh timestamp
    import time as timemod
    pipe.set("signals:last_refresh", str(int(timemod.time())))

    try:
        pipe.execute()
        log("Signal data loaded into Redis")
    except Exception as exc:
        log(f"Redis pipeline failed: {exc}")


def refresh_geoip(refresh_hours):
    """Delegate to existing geoip_fetch.py which has its own staleness logic."""
    try:
        # Import the existing geoip_fetch module
        script_dir = os.path.dirname(os.path.abspath(__file__))
        geoip_script = os.path.join(script_dir, "geoip_fetch.py")
        if os.path.exists(geoip_script):
            import subprocess
            env = os.environ.copy()
            env["DNSGEEO_GEOIP_REFRESH_HOURS"] = str(refresh_hours)
            subprocess.run([sys.executable, geoip_script], env=env)
    except Exception as exc:
        log(f"GeoIP refresh failed: {exc}")


def main():
    refresh_hours = int(os.environ.get("DNSGEEO_DATA_REFRESH_HOURS", "96") or "96")
    force = os.environ.get("DNSGEEO_DATA_FORCE_REFRESH", "0") == "1"

    lolfsaas_path = os.environ.get("DNSGEEO_LOLFSAAS_DB", "/app/data/lolfsaas.json")
    psl_path = os.environ.get("DNSGEEO_PSL_PATH", "/app/data/public_suffix_list.dat")

    effective_hours = 0 if force else refresh_hours

    refresh_geoip(effective_hours)
    refresh_lolfsaas(lolfsaas_path, effective_hours)
    refresh_psl(psl_path, effective_hours)

    # Signal data refresh (only when signals are enabled)
    if os.environ.get("DNSGEEO_SIGNALS") == "true":
        redis_url = os.environ.get("DNSGEEO_SIGNALS_REDIS")
        if not redis_url:
            redis_url = os.environ.get("DNSGEEO_WHOIS_REDIS_URL", "redis://localhost:6379/0")
        tranco_tier = os.environ.get("DNSGEEO_TRANCO_TIER", "10k")
        data_dir = os.path.dirname(lolfsaas_path) or "/app/data"
        refresh_signals(redis_url, tranco_tier, data_dir, effective_hours)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
