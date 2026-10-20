#!/usr/bin/env python3
import json, hmac, hashlib, urllib.parse

APPID = "<YOUR-APPKEY>"
APPSECRET = "<YOUR-APPSECRET>"
CERT = "<APK-CERT-SHA256>"
CERT_L = CERT.lower()
TOKEN = "<YOUR-TS-BMP-TOKEN>"
ECODE = "<YOUR-ECODE>"

samples = []
with open("/home/ubuntu/coding/tuya-mitm/capture.jsonl") as f:
    for line in f:
        d = json.loads(line)
        p = dict(urllib.parse.parse_qsl(d["req_body"], keep_blank_values=True))
        sign = p.pop("sign", None)
        if sign:
            samples.append((p, sign))
print("samples:", len(samples))

secrets = {
    "S": f"A_{TOKEN}_{APPSECRET}",
    "cert_token_secret": f"{CERT}_{TOKEN}_{APPSECRET}",
    "certL_token_secret": f"{CERT_L}_{TOKEN}_{APPSECRET}",
    "cert_S": f"{CERT}_{APPSECRET}",
    "token_secret": f"{TOKEN}_{APPSECRET}",
    "appid_token_secret": f"{APPID}_{TOKEN}_{APPSECRET}",
    "cert_token_S": f"{CERT}_{TOKEN}_A_{TOKEN}_{APPSECRET}",
    "S_ecode": f"A_{TOKEN}_{APPSECRET}_{ECODE}",
    "cert_token_secret_ecode": f"{CERT}_{TOKEN}_{APPSECRET}_{ECODE}",
}

def build_msgs(p):
    items = list(p.items())
    kv = sorted((k, str(v)) for k, v in items)
    a = p.get("a", ""); v_ = p.get("v", ""); t = p.get("time", p.get("t", ""))
    reqid = p.get("requestId", "")
    m = {}
    m["sorted_kv_pipepipe"] = "||".join(f"{k}={v}" for k, v in kv)
    m["sorted_kv_amp"] = "&".join(f"{k}={v}" for k, v in kv)
    m["sorted_kv_concat"] = "".join(f"{k}={v}" for k, v in kv)
    m["sorted_kv_noeq"] = "".join(f"{k}{v}" for k, v in kv)
    m["orig_kv_concat"] = "".join(f"{k}={v}" for k, v in items)
    m["orig_kv_noeq"] = "".join(f"{k}{v}" for k, v in items)
    m["values_orig"] = "".join(str(v) for k, v in items)
    m["values_sorted"] = "".join(str(v) for k, v in kv)
    m["a_v_empty_t"] = a + v_ + "" + t
    m["a_v_t"] = a + v_ + t
    m["reqid_a_v_t"] = reqid + a + v_ + t
    m["a_pipe_t"] = a + "||" + t
    m["empty"] = ""
    return m

def fns(msg, key):
    yield "hmac_hex", hmac.new(key.encode(), msg.encode(), hashlib.sha256).hexdigest()
    yield "hmac_upper", hmac.new(key.encode(), msg.encode(), hashlib.sha256).hexdigest().upper()
    yield "sha256_keymsg", hashlib.sha256((key + msg).encode()).hexdigest()
    yield "md5_keymsg", hashlib.md5((key + msg).encode()).hexdigest()

subset = samples[:5]
best = []
for sname, secret in secrets.items():
    msgs0 = build_msgs(subset[0][0])
    for mname in msgs0:
        for m1, sig1 in fns(msgs0[mname], secret):
            if sig1 != subset[0][1]:
                continue
            hits = sum(1 for p, s in subset if dict(fns(build_msgs(p)[mname], secret))[m1] == s)
            best.append((hits, sname, mname, m1))
            print("first-hit!", hits, sname, mname, m1)

if not best:
    print("no hit on first sample; trying hash-without-key variants & request-order guesses")
    # brute: md5/sha1/sha256 of message only, message = various
    for mname in build_msgs(subset[0][0]):
        msg = build_msgs(subset[0][0])[mname]
        for hn, hv in [("md5", hashlib.md5(msg.encode()).hexdigest()),
                       ("sha1", hashlib.sha1(msg.encode()).hexdigest()),
                       ("sha256", hashlib.sha256(msg.encode()).hexdigest())]:
            if hv == subset[0][1]:
                print("plain hash hit", hn, mname)
    # try HMAC with key=requestId
    for mname in build_msgs(subset[0][0]):
        reqid = subset[0][0].get("requestId", "")
        for m1, sig1 in fns(build_msgs(subset[0][0])[mname], reqid):
            if sig1 == subset[0][1]:
                print("key=requestId hit", mname, m1)
    print("done probe")
