import json, re, time
from mitmproxy import http

LOG = "/home/ubuntu/coding/tuya-mitm/bodies.log"

def response(flow: http.HTTPFlow):
    url = flow.request.pretty_url
    if not re.search(r'tuya|tuyacn|smartlife|<YOUR-OEM-BRAND>|api.json', url, re.I):
        return
    body = flow.response.get_text(strict=False) or ""
    entry = {"ts": time.strftime("%H:%M:%S"), "url": url, "body": body[:200000]}
    with open(LOG, "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    print(f"[captured] {flow.request.method} {url[:120]}", flush=True)
