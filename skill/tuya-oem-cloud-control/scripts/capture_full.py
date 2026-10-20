# mitmproxy addon: record request+response pairs for offline crypto analysis.
# Usage: mitmdump -s capture_full.py -p 8080 --set block_global=false
import json, time, re
from urllib.parse import parse_qs

OUT = "capture.jsonl"

def response(flow):
    req = flow.request
    url = req.pretty_url
    # capture everything OEM-related; do NOT filter by domain only (OEM apps use custom domains)
    if not re.search(r'tuya|tuyacn|smartlife|<YOUR-OEM-BRAND>|api\.json', url, re.I):
        return
    rec = {
        "ts": time.strftime("%H:%M:%S"),
        "method": req.method,
        "url": url,
        "query": dict(req.query),
        "req_headers": dict(req.headers),
        "req_body": req.get_text(strict=False) or "",
        "resp_body": flow.response.get_text(strict=False) or "",
    }
    with open(OUT, "a") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    if "api.json" in url:
        q = parse_qs(rec["req_body"])
        print(f"[api] {rec['ts']} a={q.get('a', [''])[0]}", flush=True)
