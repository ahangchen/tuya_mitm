#!/usr/bin/env python3
"""Minimal working Tuya OEM atop client (values redacted - fill your own).
Verified flow: form -> sign -> encrypt postData -> POST api.json -> decrypt response.
Replace HOST/APPID/APPSECRET/TOKEN/ECODE/SID with values recovered from your OEM app.
"""
import json, hmac, hashlib, base64, uuid, time, sys
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

HOST = "https://YOUR-OEM-DOMAIN/api.json"
APPID = "your-appKey"
APPSECRET = "your-appSecret"
TOKEN = "your-t_s.bmp-token"
S = f"A_{TOKEN}_{APPSECRET}"          # secret material for sign + response keys
ECODE = "your-session-ecode"          # from decrypted login response
SID_FULL = "your-full-60-char-sid"    # from decrypted login response
DEV_ID = "6cxxxxxxxxxxxxxxxx"

COMMON = {  # MUST mirror the real app's form exactly, per API - diff against captures
    "appVersion": "2.1.13", "appRnVersion": "5.34", "channel": "oem",
    "deviceId": "your-app-instance-id", "platform": "<YOUR-PHONE-MODEL>", "lang": "zh_CN",
    "clientId": APPID, "osSystem": "16", "os": "Android",
    "timeZoneId": "Asia/Shanghai", "ttid": f"sdk_tuya_chinaOnline@{APPID}",
    "deviceCoreVersion": "4.3.0", "sdkVersion": "4.4.0",
}
SIGN_KEYS = os.environ.get("TUYA_SIGN_KEYS", "<YOUR-SIGN-KEYS>").split()

def swap32(s): return s[8:16] + s[0:8] + s[24:32] + s[16:24]

def sign_msg(params):
    items = []
    for k in sorted(SIGN_KEYS):
        v = params.get(k)
        if not v: continue
        if k == "postData": v = swap32(hashlib.md5(v.encode()).hexdigest())
        items.append(f"{k}={v}")
    return "||".join(items)

def sign(params): return hmac.new(S.encode(), sign_msg(params).encode(), hashlib.sha256).hexdigest()

def key_for(rid, ecode=None):
    msg = S + (f"_{ecode}" if ecode else "")
    return hmac.new(rid.encode(), msg.encode(), hashlib.sha256).hexdigest()[:16].encode()

def gcm_encrypt(key, plain):
    c = AES.new(key, AES.MODE_GCM); ct, tag = c.encrypt_and_digest(plain.encode())
    return base64.b64encode(c.nonce + ct + tag).decode()

def decrypt_result(key, b64):
    raw = base64.b64decode(b64)
    try:
        c = AES.new(key, AES.MODE_GCM, nonce=raw[:12])
        return c.decrypt_and_verify(raw[12:-16], raw[-16:]).decode()
    except Exception:
        return unpad(AES.new(key, AES.MODE_ECB).decrypt(raw), 16).decode()

def call(a, v="1.0", post_obj=None, session=True):
    rid = str(uuid.uuid4())
    p = dict(COMMON)
    p.update({"a": a, "v": v, "et": "3", "requestId": rid, "time": str(int(time.time()))})
    if session: p["sid"] = SID_FULL
    if post_obj is not None:
        plain = json.dumps(post_obj, separators=(",", ":"))
        p["postData"] = gcm_encrypt(key_for(rid, ECODE if session else None), plain)
    p["sign"] = sign(p)
    r = requests.post(HOST, data=p, timeout=15, headers={"Content-Type": "application/x-www-form-urlencoded"})
    resp = r.json()
    out = {"http": r.status_code, "resp": resp}
    if isinstance(resp.get("result"), str):
        out["plain"] = decrypt_result(key_for(rid, ECODE if session else None), resp["result"])
    return out

if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "check":   # anonymous sanity check
        print(call("tuya.p.time.get", session=False)["plain"])
    elif cmd == "whoami":
        print(call("tuya.m.user.info.get")["plain"])
    elif cmd == "on":    # turn on kitchen light example: dps key 1 on the panel device
        dev = sys.argv[2] if len(sys.argv) > 2 else DEV_ID
        dps = sys.argv[3] if len(sys.argv) > 3 else "{\"1\":true}"
        print(call("tuya.m.device.dp.publish", "1.0", {"devId": dev, "dps": dps})["plain"])
    elif cmd == "query":
        dev = sys.argv[2] if len(sys.argv) > 2 else DEV_ID
        print(call("tuya.m.device.dp.get", "1.0", {"devId": dev})["plain"])
