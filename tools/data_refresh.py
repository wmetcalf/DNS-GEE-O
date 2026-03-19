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

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
