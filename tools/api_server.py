import os
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

try:
    from tools.server_common import run_dnsgeeo, run_dnsgeeo_psl_private_list
except ImportError:
    from server_common import run_dnsgeeo, run_dnsgeeo_psl_private_list


class ResolveRequest(BaseModel):
    domains: List[str] = Field(..., min_length=1)
    dns: Optional[str] = None
    timeout_ms: Optional[int] = None
    parallel: Optional[int] = None
    prefer_ipv6: Optional[bool] = None
    check_malicious: Optional[bool] = None
    city_db: Optional[str] = None
    asn_db: Optional[str] = None
    whois: Optional[bool] = None
    whois_timeout_ms: Optional[int] = None


app = FastAPI(title="DNS-GEE-O API", version="1.0.0")


@app.get("/health")
def health() -> Dict[str, Any]:
    return {"status": "ok"}


@app.post("/resolve")
def resolve(req: ResolveRequest) -> Dict[str, Any]:
    try:
        results = run_dnsgeeo(
            domains=req.domains,
            dns=req.dns,
            timeout_ms=req.timeout_ms,
            parallel=req.parallel,
            prefer_ipv6=req.prefer_ipv6,
            check_malicious=req.check_malicious,
            city_db=req.city_db,
            asn_db=req.asn_db,
            whois=req.whois,
            whois_timeout_ms=req.whois_timeout_ms,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return {"results": results}


@app.get("/psl-private-list")
def psl_private_list() -> Dict[str, Any]:
    try:
        entries = run_dnsgeeo_psl_private_list()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {"results": entries}


if __name__ == "__main__":
    import uvicorn

    host = os.getenv("DNSGEEO_API_HOST", "0.0.0.0")
    port = int(os.getenv("DNSGEEO_API_PORT", "8080"))
    uvicorn.run("api_server:app", host=host, port=port, reload=False)
