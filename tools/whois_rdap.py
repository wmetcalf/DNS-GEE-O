#!/usr/bin/env python3
import argparse
import copy
import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.request

import whois
from publicsuffixlist import PublicSuffixList

DDNS_SUFFIX_PROVIDERS = {
    "duckdns": {"duckdns.org"},
    "desec_dedyn": {"dedyn.io"},
    "noip": {"ddns.net"},
    "dynv6": {"dynv6.net"},
    "dynu": {"dynu.net"},
    "changeip": {"changeip.com"},
    "dnsexit": {"dnsexit.com"},
}

DDNS_NS_PATTERNS = {
    "afraid_freedns": [r"^ns[1-4]\.afraid\.org$"],
    "duckdns": [r"^ns[1-9]\.duckdns\.org$"],
    "noip": [r"^ns[1-5]\.no-ip\.com$", r"^nf[1-5]\.no-ip\.com$"],
    "dynu": [r"^ns[0-9]+\.dynu\.com$"],
    "changeip": [r"^ns[1-7]\.changeip\.com$"],
    "desec_dedyn": [r"^ns1\.desec\.io$", r"^ns2\.desec\.org$"],
    "dnsexit": [r"^ns[1-4]\.dnsexit\.com$", r"^pm[12]\.dnsexit\.com$"],
}

_PSL_PRIVATE_OWNER_BY_SUFFIX = None
_PSL_PRIVATE_RULES = None
_PSL = None  # Cached PublicSuffixList instance

def _get_psl():
    """Get or create cached PublicSuffixList instance."""
    global _PSL
    if _PSL is None:
        _PSL = PublicSuffixList()
    return _PSL


def parse_args():
    parser = argparse.ArgumentParser(
        description="WHOIS/RDAP lookup tool with domain age calculation."
    )
    parser.add_argument(
        "--list",
        default="",
        help="Comma-separated list of domains",
    )
    parser.add_argument(
        "--no-whois",
        action="store_true",
        help="Disable WHOIS lookup",
    )
    parser.add_argument(
        "--no-rdap",
        action="store_true",
        help="Disable RDAP lookup",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=8.0,
        help="Timeout in seconds for RDAP HTTP requests",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON",
    )
    parser.add_argument(
        "--cache-path",
        default=None,
        help="Path to cache file",
    )
    parser.add_argument(
        "--cache-ttl-hours",
        type=int,
        default=None,
        help="Cache TTL in hours",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable cache usage",
    )
    parser.add_argument(
        "--psl-private-list",
        action="store_true",
        help="Output PSL private suffix list with owners as JSON and exit",
    )
    parser.add_argument("domains", nargs="*")
    return parser.parse_args()


def normalize_datetime(value):
    if value is None:
        return None
    if isinstance(value, list):
        candidates = [normalize_datetime(v) for v in value if v is not None]
        candidates = [v for v in candidates if v is not None]
        if not candidates:
            return None
        return min(candidates)
    if isinstance(value, dt.datetime):
        return ensure_aware(value)
    if isinstance(value, str):
        return parse_iso_datetime(value)
    return None


def parse_iso_datetime(value):
    value = value.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(value)
        return ensure_aware(parsed)
    except ValueError:
        return None


def ensure_aware(value):
    if value.tzinfo is not None:
        return value
    return value.replace(tzinfo=dt.timezone.utc)


def load_psl_private_rules():
    global _PSL_PRIVATE_OWNER_BY_SUFFIX, _PSL_PRIVATE_RULES
    if _PSL_PRIVATE_RULES is not None and _PSL_PRIVATE_OWNER_BY_SUFFIX is not None:
        return _PSL_PRIVATE_RULES, _PSL_PRIVATE_OWNER_BY_SUFFIX

    owners = {}
    rules = []
    # publicsuffixlist stores the PSL data in its package
    import publicsuffixlist
    psl_path = os.path.join(os.path.dirname(publicsuffixlist.__file__), "public_suffix_list.dat")
    try:
        with open(psl_path, "r", encoding="utf-8") as handle:
            in_private = False
            current_owner = ""
            for raw_line in handle:
                line = raw_line.strip()
                if line == "// ===BEGIN PRIVATE DOMAINS===":
                    in_private = True
                    continue
                if line == "// ===END PRIVATE DOMAINS===":
                    break
                if not in_private:
                    continue
                if not line:
                    continue
                if line.startswith("//"):
                    comment = line[2:].strip()
                    if "Submitted by" in comment:
                        continue
                    if ":" in comment:
                        current_owner = comment.split(":", 1)[0].strip()
                    continue
                rule_raw = line.split()[0]
                is_exception = rule_raw.startswith("!")
                rule_body = rule_raw[1:] if is_exception else rule_raw
                is_wildcard = rule_body.startswith("*.")
                base = rule_body[2:] if is_wildcard else rule_body
                base = base.lstrip(".")
                labels = [p for p in base.split(".") if p]
                if not labels:
                    continue
                if current_owner:
                    owners[base.lower()] = current_owner
                rules.append(
                    {
                        "labels": labels,
                        "wildcard": is_wildcard,
                        "exception": is_exception,
                        "base": base,
                    }
                )
    except OSError:
        owners = {}
        rules = []

    _PSL_PRIVATE_OWNER_BY_SUFFIX = owners
    _PSL_PRIVATE_RULES = rules
    return rules, owners


def private_suffix_info(domain):
    rules, owners = load_psl_private_rules()
    if not rules:
        return "", "", "", False
    labels = [p for p in normalize_hostname(domain).split(".") if p]
    if not labels:
        return "", "", "", False

    best_rule = None
    best_len = 0
    for rule in rules:
        rule_labels = rule["labels"]
        if rule["wildcard"]:
            if len(labels) < len(rule_labels) + 1:
                continue
            if labels[-len(rule_labels) :] != rule_labels:
                continue
            match_len = len(rule_labels) + 1
        else:
            if len(labels) < len(rule_labels):
                continue
            if labels[-len(rule_labels) :] != rule_labels:
                continue
            match_len = len(rule_labels)

        if match_len > best_len:
            best_len = match_len
            best_rule = rule
        elif match_len == best_len and best_rule is not None:
            if rule["exception"] and not best_rule["exception"]:
                best_rule = rule

    if not best_rule:
        return "", "", "", True

    suffix_labels = best_len
    if best_rule["exception"]:
        suffix_labels = max(0, suffix_labels - 1)
    if suffix_labels <= 0:
        return "", "", "", True

    private_suffix = ".".join(labels[-suffix_labels:])
    registrable_labels = suffix_labels + 1
    if len(labels) >= registrable_labels:
        private_sld = ".".join(labels[-registrable_labels:])
    else:
        private_sld = ".".join(labels)
    owner = owners.get(best_rule["base"].lower(), "")
    return private_suffix, private_sld, owner, True


def psl_private_info(domain):
    domain = domain.strip().strip(".")
    if not domain:
        return "", "", "", "", False
    psl = _get_psl()
    public_sld = psl.privatesuffix(domain) or ""
    public_sld = public_sld.strip(".")
    private_suffix, private_sld, private_owner, supported = private_suffix_info(domain)
    is_private = bool(private_suffix)
    return public_sld, private_sld, private_suffix, private_owner, is_private, supported


def load_psl_private_owners():
    _, owners = load_psl_private_rules()
    return owners


def registrable_suffix(registrable_domain):
    if not registrable_domain or "." not in registrable_domain:
        return ""
    return registrable_domain.split(".", 1)[1]


def normalize_hostname(value):
    if not value:
        return ""
    value = value.strip().lower()
    if value.endswith("."):
        value = value[:-1]
    return value


def hostname_endswith_suffix(hostname, suffix):
    host = normalize_hostname(hostname)
    suf = normalize_hostname(suffix)
    return host == suf or host.endswith("." + suf)


def ddns_provider_by_suffix(hostname):
    host = normalize_hostname(hostname)
    for provider, suffixes in DDNS_SUFFIX_PROVIDERS.items():
        for suffix in suffixes:
            if hostname_endswith_suffix(host, suffix):
                return provider
    return None


def ddns_providers_by_ns(name_servers):
    if not name_servers:
        return []
    hits = []
    for provider, patterns in DDNS_NS_PATTERNS.items():
        for pattern in patterns:
            for ns in name_servers:
                if not isinstance(ns, str):
                    continue
                if re.match(pattern, normalize_hostname(ns)):
                    hits.append(provider)
                    break
            else:
                continue
            break
    return sorted(set(hits))


def rdap_lookup(domain, timeout):
    url = f"https://rdap.org/domain/{domain}"
    req = urllib.request.Request(url, headers={"Accept": "application/rdap+json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", errors="replace")
    data = json.loads(body)
    return url, data


def rdap_created_at(rdap_data):
    for event in rdap_data.get("events", []):
        action = str(event.get("eventAction", "")).strip().lower()
        if action in {"registration", "registered", "created"}:
            event_date = event.get("eventDate")
            if not event_date:
                continue
            parsed = parse_iso_datetime(str(event_date))
            if parsed is not None:
                return parsed
    return None


def rdap_events(rdap_data):
    events = []
    for event in rdap_data.get("events", []):
        action = str(event.get("eventAction", "")).strip()
        date_value = event.get("eventDate")
        parsed = parse_iso_datetime(str(date_value)) if date_value else None
        events.append(
            {
                "action": action,
                "date": parsed.isoformat() if parsed else str(date_value) if date_value else None,
            }
        )
    return events


def rdap_nameservers(rdap_data):
    results = []
    for ns in rdap_data.get("nameservers", []):
        name = ns.get("ldhName") or ns.get("unicodeName")
        if name:
            results.append(name)
    return results


def rdap_registrar_info(rdap_data):
    for entity in rdap_data.get("entities", []):
        roles = [str(role).lower() for role in entity.get("roles", [])]
        if "registrar" not in roles:
            continue
        vcard = entity.get("vcardArray")
        registrar_name = None
        registrar_country = None
        if isinstance(vcard, list) and len(vcard) == 2:
            for entry in vcard[1]:
                if not isinstance(entry, list) or len(entry) < 4:
                    continue
                key = entry[0]
                value = entry[3]
                if key == "fn" and isinstance(value, str):
                    registrar_name = value
                if key == "adr" and isinstance(value, list) and len(value) >= 7:
                    country = value[6]
                    if isinstance(country, str) and country.strip():
                        registrar_country = country.strip()
        return registrar_name, registrar_country
    return None, None


def whois_lookup(domain):
    res = whois.whois(domain)
    created = normalize_datetime(res.creation_date)
    registrant_org = getattr(res, "org", None)
    registrant_address_parts = []
    for key in ("address", "city", "state", "zipcode", "country"):
        value = getattr(res, key, None)
        if not value:
            continue
        if isinstance(value, (list, tuple)):
            registrant_address_parts.extend([str(v) for v in value if v])
        else:
            registrant_address_parts.append(str(value))
    registrant_address = ", ".join(dict.fromkeys(registrant_address_parts)) if registrant_address_parts else None
    return {
        "created_at": created.isoformat() if created else None,
        "expiration_date": normalize_datetime(res.expiration_date).isoformat()
        if res.expiration_date
        else None,
        "updated_date": normalize_datetime(res.updated_date).isoformat()
        if res.updated_date
        else None,
        "registrar": res.registrar,
        "name_servers": list(res.name_servers) if res.name_servers else None,
        "registrant_org": registrant_org,
        "registrant_address": registrant_address,
    }, created


def root_domain(domain):
    domain = domain.strip().strip(".")
    if not domain:
        return ""
    private_suffix, _, _, _ = private_suffix_info(domain)
    if private_suffix:
        return private_suffix
    psl = _get_psl()
    sld = psl.privatesuffix(domain)
    return sld or domain


def load_cache(path):
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def save_cache(path, data):
    if not path:
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle)


def cache_entry_is_fresh(entry, ttl_hours):
    if not entry or ttl_hours <= 0:
        return False
    fetched_at = entry.get("fetched_at")
    if not fetched_at:
        return False
    parsed = parse_iso_datetime(fetched_at)
    if parsed is None:
        return False
    now = dt.datetime.now(dt.timezone.utc)
    return now - parsed <= dt.timedelta(hours=ttl_hours)


def main():
    args = parse_args()
    if args.psl_private_list:
        _, owners = load_psl_private_rules()
        entries = []
        for suffix, owner in sorted(owners.items()):
            entries.append({"suffix": suffix, "owner": owner})
        if args.pretty:
            print(json.dumps(entries, indent=2, sort_keys=False))
        else:
            print(json.dumps(entries))
        return 0

    inputs = []
    if args.list:
        inputs.extend([v.strip() for v in args.list.split(",") if v.strip()])
    inputs.extend(args.domains)

    if not inputs:
        print("No domains provided", file=sys.stderr)
        return 2

    env_cache_path = os.getenv("DNSGEEO_WHOIS_CACHE_PATH")
    cache_path = args.cache_path or env_cache_path or os.path.expanduser(
        "~/.cache/dnsgeeo-whois-cache.json"
    )

    env_ttl = os.getenv("DNSGEEO_WHOIS_CACHE_TTL_HOURS")
    ttl_hours = args.cache_ttl_hours
    if ttl_hours is None:
        ttl_hours = int(env_ttl) if env_ttl else 24

    redis_url = os.getenv("DNSGEEO_WHOIS_REDIS_URL", "")
    redis_client = None
    if redis_url:
        try:
            import redis  # type: ignore
        except ImportError as exc:
            print("error: redis module not installed", file=sys.stderr)
            return 2
        redis_client = redis.Redis.from_url(redis_url)

    cache = {} if args.no_cache else load_cache(cache_path)
    cache_dirty = False

    roots = []
    domain_to_root = {}
    for domain in inputs:
        root = root_domain(domain)
        domain_to_root[domain] = root
        if root and root not in roots:
            roots.append(root)

    root_results = {}

    for root in roots:
        cached = None
        if redis_client is not None:
            try:
                cached_raw = redis_client.get(f"dnsgeeo:whois:{root}")
                if cached_raw:
                    cached = json.loads(cached_raw)
            except Exception:
                cached = None

        if cached is None and cache:
            cached = cache.get(root)

        if cached and cache_entry_is_fresh(cached, ttl_hours):
            root_results[root] = (cached.get("data", {}), True)
            continue

        entry = {"domain": root}
        created = None
        created_source = None
        registrar = None
        registrar_country = None
        name_servers = None

        if not args.no_rdap:
            try:
                url, data = rdap_lookup(root, args.timeout)
                entry["rdap_url"] = url
                entry["rdap_status"] = data.get("status")
                entry["rdap_events"] = rdap_events(data)
                rdap_ns = rdap_nameservers(data)
                if rdap_ns:
                    name_servers = rdap_ns
                rdap_created = rdap_created_at(data)
                if rdap_created:
                    entry["rdap_created_at"] = rdap_created.isoformat()
                    created = rdap_created
                    created_source = "rdap"
                r_name, r_country = rdap_registrar_info(data)
                registrar = r_name or registrar
                registrar_country = r_country or registrar_country
            except (urllib.error.URLError, ValueError) as exc:
                entry["rdap_error"] = str(exc)

        if not args.no_whois:
            try:
                whois_info, whois_created = whois_lookup(root)
                entry.update(
                    {
                        "whois_created_at": whois_info.get("created_at"),
                        "whois_expiration_date": whois_info.get("expiration_date"),
                        "whois_updated_date": whois_info.get("updated_date"),
                        "registrant_org": whois_info.get("registrant_org"),
                        "registrant_address": whois_info.get("registrant_address"),
                    }
                )
                registrar = whois_info.get("registrar") or registrar
                whois_ns = whois_info.get("name_servers")
                if whois_ns:
                    name_servers = whois_ns
                if created is None and whois_created is not None:
                    created = whois_created
                    created_source = "whois"
            except Exception as exc:  # python-whois can raise varied exceptions
                entry["whois_error"] = str(exc)

        if registrar:
            entry["registrar"] = registrar
        if registrar_country:
            entry["registrar_country"] = registrar_country
        if name_servers:
            entry["name_servers"] = name_servers
            entry["is_afraid_hosted"] = any(
                ns.lower().endswith(".afraid.org") for ns in name_servers if isinstance(ns, str)
            )

        if created is not None:
            created_utc = created.astimezone(dt.timezone.utc)
            entry["created_at"] = created_utc.isoformat()
            entry["created_at_source"] = created_source
            now_utc = dt.datetime.now(dt.timezone.utc)
            if now_utc >= created_utc:
                age_days = int((now_utc - created_utc).total_seconds() / 86400)
                entry["age_days"] = age_days

        root_results[root] = (entry, False)
        if not args.no_cache and root:
            if not entry.get("whois_error") and not entry.get("rdap_error"):
                cached_payload = {
                    "fetched_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "data": entry,
                }
                if redis_client is not None:
                    try:
                        redis_client.setex(
                            f"dnsgeeo:whois:{root}",
                            int(ttl_hours * 3600),
                            json.dumps(cached_payload),
                        )
                    except Exception:
                        pass
                cache[root] = cached_payload
                cache_dirty = True

    results = []
    for domain in inputs:
        root = domain_to_root.get(domain, "")
        root_entry, cache_hit = root_results.get(root, ({"domain": root}, False))
        entry = copy.deepcopy(root_entry)
        entry["domain"] = domain
        public_sld, private_sld, private_suffix, private_owner, is_private, private_supported = psl_private_info(domain)
        if private_supported:
            if public_sld:
                entry["psl_public_registrable_domain"] = public_sld
                public_suffix = registrable_suffix(public_sld)
                if public_suffix:
                    entry["psl_public_suffix"] = public_suffix
            if private_sld:
                entry["psl_registrable_domain"] = private_sld
            if private_suffix:
                entry["psl_private_suffix"] = private_suffix
                if private_owner:
                    entry["psl_private_owner"] = private_owner
            entry["psl_is_private"] = is_private
        suffix_provider = ddns_provider_by_suffix(domain)
        if suffix_provider:
            entry["ddns_provider_by_suffix"] = suffix_provider
        ns_providers = ddns_providers_by_ns(entry.get("name_servers"))
        if ns_providers:
            entry["ddns_providers_by_ns"] = ns_providers
        combined = sorted(set([p for p in [suffix_provider] if p] + ns_providers))
        if combined:
            entry["ddns_providers"] = combined
        if root:
            entry["root_domain"] = root
        if cache_hit:
            entry["cache_hit"] = True
        results.append(entry)

    if cache_dirty and not args.no_cache:
        save_cache(cache_path, cache)

    if args.pretty:
        print(json.dumps(results, indent=2, sort_keys=False))
    else:
        print(json.dumps(results))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
