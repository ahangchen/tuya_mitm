#!/usr/bin/env python3
"""mitmproxy 抓包脚本（完整版）：同时记录请求 query（含 requestId）与响应体。
用法: mitmdump -s capture_full.py
输出: /home/ubuntu/coding/tuya-mitm/capture.jsonl
每行: {"ts":..., "method":..., "url":..., "query":{...}, "req_body":..., "resp_body":...}
"""
import json, re, time
from mitmproxy import http

LOG = "/home/ubuntu/coding/tuya-mitm/capture.jsonl"

def response(flow: http.HTTPFlow):
    url = flow.request.pretty_url
    if not re.search(r'tuya|tuyacn|smartlife|<YOUR-OEM-BRAND>|api\.json', url, re.I):
        return
    entry = {
        "ts": time.strftime("%H:%M:%S"),
        "method": flow.request.method,
        "url": url,
        "query": dict(flow.request.query),
        "req_headers": {k: v for k, v in flow.request.headers.items()
                        if k.lower() in ("atop", "cookie", "content-type")},
        "req_body": (flow.request.get_text(strict=False) or "")[:20000],
        "resp_body": (flow.response.get_text(strict=False) or "")[:200000],
    }
    with open(LOG, "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    print(f"[captured] {flow.request.method} {url[:150]}", flush=True)
