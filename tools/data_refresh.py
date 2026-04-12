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

    # Download cenk/nrd (newly registered domains, 30-day rolling window)
    NRD_URL = "https://dl.cenk.app/nrd/nrd-last-30-days.txt"
    nrd_dest = os.path.join(sublime_dir, "nrd-last-30-days.txt")
    if needs_refresh(nrd_dest, refresh_hours):
        log("Downloading newly registered domains (30-day)...")
        download_url(NRD_URL, nrd_dest)

    # Download brianhama/bad-asn-list
    BAD_ASN_URL = "https://raw.githubusercontent.com/brianhama/bad-asn-list/master/bad-asn-list.csv"
    bad_asn_dest = os.path.join(sublime_dir, "bad-asn-list.csv")
    if needs_refresh(bad_asn_dest, refresh_hours):
        log("Downloading bad ASN list...")
        download_url(BAD_ASN_URL, bad_asn_dest)

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

    import json as jsonmod
    import time as timemod

    # Write all data to staging keys, then atomically RENAME to live keys.
    # This ensures queries never see empty/partial data during refresh.
    S = ":staging"  # suffix for staging keys
    pipe = r.pipeline()
    rename_pairs = []  # (staging_key, live_key) to RENAME after pipeline

    # Helper to load a text file into a staging Redis set
    def load_set(filepath, live_key):
        if not os.path.exists(filepath):
            return
        staging = live_key + S
        pipe.delete(staging)
        with open(filepath) as f:
            entries = [line.strip().lower() for line in f
                       if line.strip() and not line.startswith("#")]
        if entries:
            pipe.sadd(staging, *entries)
            rename_pairs.append((staging, live_key))

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
        staging = "signals:url_shorteners" + S
        pipe.delete(staging)
        pipe.sadd(staging, *shortener_entries)
        rename_pairs.append((staging, "signals:url_shorteners"))

    # Load afraid public registration domains
    afraid_path = os.path.join(data_dir, "afraid_public_domains.txt")
    load_set(afraid_path, "signals:afraid_public_reg")

    # Load Tranco as sorted set
    if os.path.exists(tranco_dest):
        staging = "signals:tranco" + S
        pipe.delete(staging)
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
                pipe.zadd(staging, mapping)
                rename_pairs.append((staging, "signals:tranco"))

    # Load LOLFSaaS as hash
    lolfsaas_path = os.path.join(data_dir, "lolfsaas.json")
    if os.path.exists(lolfsaas_path):
        staging = "signals:lolfsaas" + S
        pipe.delete(staging)
        with open(lolfsaas_path) as f:
            lol_entries = jsonmod.load(f)
        for entry in lol_entries:
            for domain in entry.get("domains", []):
                domain = domain.strip().lower()
                if not domain:
                    continue
                blob = jsonmod.dumps({
                    "name": entry.get("name", ""),
                    "category": entry.get("category", ""),
                    "abuse": entry.get("abuse", {}),
                    "matched_pattern": domain,
                })
                if domain.startswith("*."):
                    pipe.hset(staging, domain[2:], blob)
                else:
                    pipe.hset(staging, domain, blob)
        rename_pairs.append((staging, "signals:lolfsaas"))

    # Load PSL private suffixes
    psl_path = os.path.join(data_dir, "public_suffix_list.dat")
    if os.path.exists(psl_path):
        staging = "signals:psl_private" + S
        pipe.delete(staging)
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
                    pipe.hset(staging, suffix, "1")
        rename_pairs.append((staging, "signals:psl_private"))

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
    staging = "signals:ddns_suffixes" + S
    pipe.delete(staging)
    for suffix, provider in ddns_suffixes.items():
        pipe.hset(staging, suffix, provider)
    rename_pairs.append((staging, "signals:ddns_suffixes"))

    # Load dyn-dns-list as hash (domain → provider)
    if os.path.exists(dyndns_dest):
        staging = "signals:ddns_domains" + S
        pipe.delete(staging)
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
                        pipe.hset(staging, domain, provider)
        rename_pairs.append((staging, "signals:ddns_domains"))

    # Load newly registered domains as set
    if os.path.exists(nrd_dest):
        staging = "signals:nrd" + S
        pipe.delete(staging)
        with open(nrd_dest) as f:
            nrd_entries = [line.strip().lower() for line in f
                          if line.strip() and not line.startswith("#")]
        if nrd_entries:
            pipe.sadd(staging, *nrd_entries)
            rename_pairs.append((staging, "signals:nrd"))
            log(f"NRD: {len(nrd_entries)} domains loaded")

    # Load bad ASNs as set + names hash
    if os.path.exists(bad_asn_dest):
        staging_set = "signals:bad_asns" + S
        staging_names = "signals:bad_asn_names" + S
        pipe.delete(staging_set)
        pipe.delete(staging_names)
        with open(bad_asn_dest) as f:
            asn_map = {}
            for line in f:
                line = line.strip()
                if not line or line.startswith("ASN,"):
                    continue
                parts = line.split(",", 1)
                if len(parts) >= 1:
                    try:
                        asn_num = str(int(parts[0].strip()))
                        entity = parts[1].strip().strip('"') if len(parts) > 1 else ""
                        asn_map[asn_num] = entity
                    except ValueError:
                        continue
            if asn_map:
                for asn_num, entity in asn_map.items():
                    pipe.sadd(staging_set, asn_num)
                    if entity:
                        pipe.hset(staging_names, asn_num, entity)
                rename_pairs.append((staging_set, "signals:bad_asns"))
                rename_pairs.append((staging_names, "signals:bad_asn_names"))
                log(f"Bad ASNs: {len(asn_map)} loaded")

    try:
        pipe.execute()
        # Atomic swap: RENAME staging keys to live keys in a transaction
        rename_pipe = r.pipeline(transaction=True)
        for staging_key, live_key in rename_pairs:
            rename_pipe.rename(staging_key, live_key)
        rename_pipe.execute()
        # Update timestamp after successful swap
        r.set("signals:last_refresh", str(int(timemod.time())))
        log("Signal data loaded into Redis")
    except Exception as exc:
        log(f"Redis pipeline failed: {exc}")
        # Clean up staging keys on failure
        for staging_key, _ in rename_pairs:
            r.delete(staging_key)


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
    refresh_hours = int(os.environ.get("DNSGEEO_DATA_REFRESH_HOURS", "24") or "24")
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
