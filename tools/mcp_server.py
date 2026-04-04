import os
from typing import Any, Dict, List, Optional

from fastmcp import FastMCP

try:
    from tools.server_common import run_dnsgeeo, run_dnsgeeo_psl_private_list
except ImportError:
    from server_common import run_dnsgeeo, run_dnsgeeo_psl_private_list


app = FastMCP("DNS-GEE-O MCP")


@app.tool()
def dnsgeeo_resolve(
    domains: List[str],
    dns: Optional[str] = None,
    timeout_ms: Optional[int] = None,
    parallel: Optional[int] = None,
    prefer_ipv6: Optional[bool] = None,
    check_malicious: Optional[bool] = None,
    city_db: Optional[str] = None,
    asn_db: Optional[str] = None,
    whois: Optional[bool] = None,
    whois_timeout_ms: Optional[int] = None,
    doh: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    Resolve domains to IPs with GeoIP and WHOIS enrichment.

    Returns results with IPs, GeoIP data, ASN info, and WHOIS details including:
    - psl_is_private: True if domain uses a private PSL suffix (e.g., github.io, herokuapp.com)
    - psl_private_owner: Owner of the private suffix (e.g., "GitHub Inc.")
    - psl_private_suffix: The private suffix itself (e.g., "github.io")
    - psl_public_suffix: Public TLD suffix (e.g., "com", "org", "io")
    - is_afraid_hosted: True if hosted on afraid.org free DNS
    - is_afraid_public_reg: True if domain is under an afraid.org public registration domain
    - ddns_providers: List of detected dynamic DNS providers
    - ddns_provider_by_suffix: Provider detected by domain suffix
    - ddns_providers_by_ns: Providers detected by nameservers

    Args:
        domains: List of domain names or IP addresses to resolve
        dns: Comma-separated DNS servers (default: "1.1.1.1:53,8.8.8.8:53")
        timeout_ms: Per-host timeout in milliseconds (default: 2000)
        parallel: Max concurrent lookups (default: 64)
        prefer_ipv6: Include AAAA records (default: true)
        check_malicious: Check against Quad9 threat intel (default: false)
        city_db: Path to GeoLite2-City.mmdb (optional)
        asn_db: Path to GeoLite2-ASN.mmdb (optional)
        whois: Enable WHOIS/RDAP lookup (default: false)
        whois_timeout_ms: WHOIS timeout in milliseconds (default: 3000)
        doh: Use DNS over HTTPS for all queries (default: false, or DNSGEEO_DOH env var)

    Returns:
        Dictionary with "results" key containing list of enriched domain data
    """
    results = run_dnsgeeo(
        domains=domains,
        dns=dns,
        timeout_ms=timeout_ms,
        parallel=parallel,
        prefer_ipv6=prefer_ipv6,
        check_malicious=check_malicious,
        city_db=city_db,
        asn_db=asn_db,
        whois=whois,
        whois_timeout_ms=whois_timeout_ms,
        doh=doh,
    )
    return {"results": results}


@app.tool()
def dnsgeeo_psl_private_list() -> Dict[str, Any]:
    """
    Get the list of all private Public Suffix List (PSL) entries.

    Returns all private suffixes from the PSL with their owners. Private suffixes
    are used by hosting providers, dynamic DNS services, and platforms to delegate
    subdomains (e.g., github.io, herokuapp.com, duckdns.org).

    Returns:
        Dictionary with "results" key containing list of {suffix, owner} entries
    """
    entries = run_dnsgeeo_psl_private_list()
    return {"results": entries}


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=os.getenv("DNSGEEO_MCP_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.getenv("DNSGEEO_MCP_PORT", "9090")))
    args = parser.parse_args()
    app.run(transport="http", host=args.host, port=args.port)
