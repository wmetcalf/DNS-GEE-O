#!/usr/bin/env python3
import os
import sys
import tarfile
import tempfile
import time
import urllib.request


CITY_EDITION = "GeoLite2-City"
ASN_EDITION = "GeoLite2-ASN"


def log(msg):
    sys.stderr.write(msg + "\n")


def download_and_extract(edition_id, license_key, dest_path):
    url = (
        "https://download.maxmind.com/app/geoip_download"
        f"?edition_id={edition_id}&license_key={license_key}&suffix=tar.gz"
    )
    with tempfile.TemporaryDirectory() as tmpdir:
        archive_path = os.path.join(tmpdir, f"{edition_id}.tar.gz")
        log(f"Downloading {edition_id}...")
        urllib.request.urlretrieve(url, archive_path)
        with tarfile.open(archive_path, "r:gz") as tar:
            tar.extractall(tmpdir)
        mmdb_path = None
        for root, _, files in os.walk(tmpdir):
            for name in files:
                if name.endswith(".mmdb") and edition_id in name:
                    mmdb_path = os.path.join(root, name)
                    break
            if mmdb_path:
                break
        if not mmdb_path:
            raise RuntimeError(f"{edition_id} mmdb not found in archive")
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        tmp_out = dest_path + ".tmp"
        with open(mmdb_path, "rb") as src, open(tmp_out, "wb") as dst:
            dst.write(src.read())
        os.replace(tmp_out, dest_path)
        log(f"Wrote {dest_path}")


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


def main():
    license_key = os.environ.get("MAXMIND_LICENSE_KEY", "").strip()
    if not license_key:
        log("MAXMIND_LICENSE_KEY not set; skipping GeoLite2 download.")
        return 0

    city_db = os.environ.get("DNSGEEO_CITY_DB", "/app/data/GeoLite2-City.mmdb")
    asn_db = os.environ.get("DNSGEEO_ASN_DB", "/app/data/GeoLite2-ASN.mmdb")
    refresh_hours = int(os.environ.get("DNSGEEO_GEOIP_REFRESH_HOURS", "96") or "96")
    force_refresh = os.environ.get("DNSGEEO_GEOIP_FORCE_DOWNLOAD", "0") == "1"

    needs_city = force_refresh or needs_refresh(city_db, refresh_hours)
    needs_asn = force_refresh or needs_refresh(asn_db, refresh_hours)
    if not needs_city and not needs_asn:
        log("GeoLite2 DBs are fresh; skipping download.")
        return 0

    try:
        if needs_city:
            download_and_extract(CITY_EDITION, license_key, city_db)
        if needs_asn:
            download_and_extract(ASN_EDITION, license_key, asn_db)
    except Exception as exc:
        log(f"GeoLite2 download failed: {exc}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
