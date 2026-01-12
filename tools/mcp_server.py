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
) -> Dict[str, Any]:
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
    )
    return {"results": results}


@app.tool()
def dnsgeeo_psl_private_list() -> Dict[str, Any]:
    entries = run_dnsgeeo_psl_private_list()
    return {"results": entries}


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=os.getenv("DNSGEEO_MCP_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.getenv("DNSGEEO_MCP_PORT", "9090")))
    args = parser.parse_args()
    app.run(transport="http", host=args.host, port=args.port)
