# mitm_jsonl_addon.py — write one JSON line per HTTP exchange for Lab timeline sync.
# Used by: mitmdump -s configs/mitm_jsonl_addon.py
from mitmproxy import http
import json
import os
import time

OUT = os.environ.get("APKCHECK_FLOW_JSONL", "")
_t0 = time.time()


def _out_path(flow: http.HTTPFlow) -> str:
    if OUT:
        return OUT
    conf = getattr(flow, "metadata", {}) or {}
    # fall back beside confdir if set via env
    base = os.environ.get("APKCHECK_PROXY_DIR", ".")
    return os.path.join(base, "flows.jsonl")


def response(flow: http.HTTPFlow) -> None:
    try:
        req = flow.request
        res = flow.response
        host = (req.host or "").lower()
        url = req.pretty_url or req.url or ""
        tags = ["mitm"]
        if "divar" in host or "divar" in url.lower():
            tags.append("divar")
        row = {
            "ts": time.time(),
            "offset_ms": int((time.time() - _t0) * 1000),
            "method": req.method,
            "host": req.host,
            "url": url,
            "path": req.path,
            "status": res.status_code if res else 0,
            "tags": tags,
        }
        path = _out_path(flow)
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    except Exception:
        pass
