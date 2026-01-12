import json
import os
import subprocess
from typing import Any, Dict, List, Optional


def _default_city_db() -> str:
    return os.getenv("DNSGEEO_CITY_DB", "")


def _default_asn_db() -> str:
    return os.getenv("DNSGEEO_ASN_DB", "")


def _existing_path(path: Optional[str]) -> str:
    if not path:
        return ""
    return path if os.path.exists(path) else ""


def _default_dnsgeeo_bin() -> str:
    return os.getenv("DNSGEEO_BIN", "./bin/dnsgeeo")


def _default_whois_tool() -> str:
    return os.getenv("DNSGEEO_WHOIS_TOOL", "./tools/whois_rdap.py")


def _default_whois_python() -> str:
    return os.getenv("DNSGEEO_WHOIS_PYTHON", "python3")


def run_dnsgeeo(
    domains: List[str],
    dns: Optional[str] = None,
    timeout_ms: Optional[int] = None,
    parallel: Optional[int] = None,
    prefer_ipv6: Optional[bool] = None,
    check_malicious: Optional[bool] = None,
    city_db: Optional[str] = None,
    asn_db: Optional[str] = None,
    whois: Optional[bool] = None,
    whois_tool: Optional[str] = None,
    whois_python: Optional[str] = None,
    whois_timeout_ms: Optional[int] = None,
    whois_cache_path: Optional[str] = None,
    whois_cache_ttl_hours: Optional[int] = None,
    whois_redis_url: Optional[str] = None,
) -> List[Dict[str, Any]]:
    if not domains:
        raise ValueError("domains list is empty")

    args = [_default_dnsgeeo_bin(), "--list", ",".join(domains)]

    if dns:
        args += ["--dns", dns]
    if timeout_ms is not None:
        args += ["--timeout-ms", str(timeout_ms)]
    if parallel is not None:
        args += ["--parallel", str(parallel)]
    if prefer_ipv6 is True:
        args += ["--prefer-ipv6=true"]
    elif prefer_ipv6 is False:
        args += ["--prefer-ipv6=false"]
    if check_malicious is True:
        args += ["--check-malicious"]
    elif check_malicious is False:
        args += ["--check-malicious=false"]

    city_db = _existing_path(city_db or _default_city_db())
    asn_db = _existing_path(asn_db or _default_asn_db())
    if city_db:
        args += ["--city-db", city_db]
    if asn_db:
        args += ["--asn-db", asn_db]

    if whois is True:
        args += ["--whois"]
        args += ["--whois-tool", whois_tool or _default_whois_tool()]
        args += ["--whois-python", whois_python or _default_whois_python()]
        if whois_timeout_ms is not None:
            args += ["--whois-timeout-ms", str(whois_timeout_ms)]
    elif whois is False:
        args += ["--whois=false"]

    env = os.environ.copy()
    if whois_cache_path:
        env["DNSGEEO_WHOIS_CACHE_PATH"] = whois_cache_path
    if whois_cache_ttl_hours is not None:
        env["DNSGEEO_WHOIS_CACHE_TTL_HOURS"] = str(whois_cache_ttl_hours)
    if whois_redis_url:
        env["DNSGEEO_WHOIS_REDIS_URL"] = whois_redis_url

    try:
        output = subprocess.check_output(args, env=env)
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode("utf-8", errors="replace") if exc.stderr else ""
        raise RuntimeError(f"dnsgeeo failed: {stderr.strip() or exc}") from exc

    try:
        return json.loads(output.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError("dnsgeeo returned invalid JSON") from exc


def run_dnsgeeo_psl_private_list(
    pretty: bool = False,
    whois_tool: Optional[str] = None,
    whois_python: Optional[str] = None,
    whois_timeout_ms: Optional[int] = None,
) -> List[Dict[str, Any]]:
    args = [_default_dnsgeeo_bin(), "--psl-private-list"]
    if pretty:
        args.append("--pretty")
    if whois_tool:
        args += ["--whois-tool", whois_tool]
    if whois_python:
        args += ["--whois-python", whois_python]
    if whois_timeout_ms is not None:
        args += ["--whois-timeout-ms", str(whois_timeout_ms)]

    try:
        output = subprocess.check_output(args, env=os.environ.copy())
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode("utf-8", errors="replace") if exc.stderr else ""
        raise RuntimeError(f"dnsgeeo failed: {stderr.strip() or exc}") from exc

    try:
        return json.loads(output.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError("dnsgeeo returned invalid JSON") from exc
