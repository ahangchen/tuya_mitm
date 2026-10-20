#!/usr/bin/env python3
"""Tuya OEM (小海智家) api.json client with cracked request sign."""
import json, hmac, hashlib, base64, uuid, time, sys, os, re, urllib.parse
import requests
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

# 敏感值从本地 credentials.local.md 读取（不入库），环境变量可覆盖
import os as _os

def _load_creds():
    creds = {}
    f = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "credentials.local.md")
    if _os.path.exists(f):
        for line in open(f, encoding="utf-8"):
            line = line.strip()
            if line.startswith("- ") and ":" in line:
                k, _, v = line[2:].partition(":")
                creds[k.strip()] = v.strip()
    return creds

_C = _load_creds()

def _sessval(which):
    for k, v in _C.items():
        if "会话" in k and "调研" not in k:
            for part in v.split(","):
                if part.strip().startswith(which + "="):
                    return part.strip().split("=", 1)[1]
    return "<YOUR-" + which.upper() + ">"

HOST = _os.environ.get("TUYA_HOST", _C.get("API host", "<YOUR-OEM-DOMAIN>").strip())
if not HOST.startswith("http"): HOST = "https://" + HOST
HOST += "/api.json"
APPID = _os.environ.get("TUYA_APPID", _C.get("appKey/clientId", "<YOUR-APPKEY>"))
APPSECRET = _os.environ.get("TUYA_APPSECRET", _C.get("appSecret", "<YOUR-APPSECRET>"))
TOKEN = _os.environ.get("TUYA_TOKEN", _C.get("t_s.bmp token", "<YOUR-TOKEN>"))
ECODE = _os.environ.get("TUYA_ECODE", _sessval("ecode"))
SID_FULL = _os.environ.get("TUYA_SID", _sessval("sid"))
SID = SID_FULL
S = f"A_{TOKEN}_{APPSECRET}"
DEV_ID = _os.environ.get("TUYA_DEV_ID", _C.get("app 实例 deviceId", "<YOUR-DEV-ID>"))
GID = _os.environ.get("TUYA_GID", _C.get("gid", "<YOUR-GID>"))
SIGN_KEYS = _os.environ.get("TUYA_SIGN_KEYS", _C.get("SIGN_KEYS", "<YOUR-SIGN-KEYS>").strip().strip('"')).split()

_PHONE = _C.get("手机型号/设备指纹", "platform=<YOUR-PHONE-MODEL>")
_platform = _PHONE.split(",")[0].split("=")[-1]
_equip = _PHONE.split(",")[1].split("=")[-1] if "," in _PHONE else "<YOUR-EQUIPMENT-ID>"

COMMON = {
    "appVersion": "2.1.13", "appRnVersion": "5.34", "channel": "oem",
    "deviceId": DEV_ID, "platform": _platform, "lang": "zh_CN",
    "clientId": APPID, "osSystem": "16", "os": "Android",
    "timeZoneId": "Asia/Shanghai", "ttid": f"sdk_tuya_chinaOnline@{APPID}",
    "deviceCoreVersion": "4.3.0", "sdkVersion": "4.4.0", "appType": "xhzj", "equipmentId": _equip, "gid": GID,
}

def swap32(s): return s[8:16] + s[0:8] + s[24:32] + s[16:24]

def sign_msg(params: dict) -> str:
    items = []
    for k in sorted(SIGN_KEYS):
        v = params.get(k)
        if v is None or v == "":
            continue
        if k == "postData":
            v = swap32(hashlib.md5(v.encode()).hexdigest())
        items.append(f"{k}={v}")
    return "||".join(items)

def sign(params: dict) -> str:
    return hmac.new(S.encode(), sign_msg(params).encode(), hashlib.sha256).hexdigest()

def key_for(request_id: str, ecode=ECODE) -> bytes:
    msg = S + (f"_{ecode}" if ecode else "")
    return hmac.new(request_id.encode(), msg.encode(), hashlib.sha256).hexdigest()[:16].encode()

def gcm_encrypt(key: bytes, plaintext: str) -> str:
    c = AES.new(key, AES.MODE_GCM, nonce=_os.urandom(12))
    ct, tag = c.encrypt_and_digest(plaintext.encode())
    return base64.b64encode(c.nonce + ct + tag).decode()

def gcm_decrypt(key: bytes, b64: str):
    raw = base64.b64decode(b64)
    c = AES.new(key, AES.MODE_GCM, nonce=raw[:12])
    return c.decrypt_and_verify(raw[12:-16], raw[-16:])

def ecb_decrypt(key: bytes, b64: str):
    from Crypto.Util.Padding import unpad
    raw = base64.b64decode(b64)
    return unpad(AES.new(key, AES.MODE_ECB).decrypt(raw), 16)

def call(a, v="1.0", post_obj=None, session=True, timeout=15):
    rid = str(uuid.uuid4())
    p = dict(COMMON)
    # 关键修复：appType/equipmentId/gid 三个多余字段会导致服务端对 postData 解密失败
    # （DECODE_ERROR / BATCH_API_PARAM_WRONG）——真实 app 请求表单里没有它们
    for k in ("appType", "equipmentId", "gid"):
        p.pop(k, None)
    p.update({"a": a, "v": v, "et": "3", "requestId": rid, "time": str(int(time.time()))})
    if session:
        p["sid"] = SID
    plain_pd = json.dumps(post_obj, separators=(",", ":")) if post_obj is not None else None
    if plain_pd is not None:
        p["postData"] = gcm_encrypt(key_for(rid), plain_pd)
    p["sign"] = sign(p)
    r = requests.post(HOST, data=p, timeout=timeout,
                      headers={"Content-Type": "application/x-www-form-urlencoded"})
    resp = r.json()
    out = {"http": r.status_code, "resp": resp}
    res = resp.get("result")
    k = key_for(rid, ECODE if session else None)
    if isinstance(res, str):
        try:
            out["plain"] = gcm_decrypt(k, res).decode()
        except Exception:
            try:
                out["plain"] = ecb_decrypt(k, res).decode()
            except Exception as e:
                out["plain_err"] = str(e)
    return out

def batch(apis, timeout=15):
    """apis: list of (a, v, post_obj_or_None)"""
    outer_rid = str(uuid.uuid4())
    t = int(time.time())
    entries = []
    for (a, v, post_obj) in apis:
        inner_rid = str(uuid.uuid4())
        body = dict(COMMON)
        body.update({"a": a, "v": v, "et": "3", "requestId": inner_rid, "time": str(t),
                     "sid": SID_FULL, "gid": str(GID)})
        pd = json.dumps(post_obj, separators=(",", ":")) if post_obj is not None else ""
        entry_body = dict(body)
        entry_body["postData"] = pd
        ap = {
            "ET_VERSION": "3", "apiChannel": "", "apiName": a, "apiVersion": v,
            "encryptPostDataString": "", "etVersion": "3", "gid": GID,
            "h5Request": False, "isH5Request": False, "isN4H5Request": False,
            "locationRequire": True, "n4H5Request": False, "postBody": {},
            "postDataString": pd,
            "requestBody": entry_body, "requestSignBody": entry_body,
            "requestTime": 0, "requestUrl": HOST, "responseTime": 0,
            "serverHostUrl": HOST, "session": SID_FULL, "sessionRequire": True,
            "shouldCache": False, "signWhitEncryptedBody": True, "spRequest": False,
            "throwCache": False,
            "urlGETParams": {k: val for k, val in COMMON.items()},
            "urlParams": entry_body,
        }
        entries.append({"a": a, "apiParams": ap, "et": "3", "requestId": inner_rid,
                        "sign": sign(entry_body), "t": t, "v": v})
    post = {"apis": entries}
    return call("tuya.m.api.batch.invoke", "1.0", post, session=True, timeout=timeout)


def _call_raw(a, v, post_obj=None, session=False, proxies=None, verify=True):
    """底层调用，返回解密后的 dict"""
    import requests as _rq
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    rid = str(uuid.uuid4())
    p = dict(COMMON)
    p.update({"a": a, "v": v, "et": "3", "requestId": rid, "time": str(int(time.time()))})
    if session: p["sid"] = SID_FULL
    if post_obj is not None:
        p["postData"] = gcm_encrypt(key_for(rid, ECODE if session else None), json.dumps(post_obj, separators=(",", ":")))
    p["sign"] = sign(p)
    r = _rq.post(HOST, data=p, timeout=15, proxies=proxies, verify=verify,
                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    resp = r.json()
    if not isinstance(resp.get("result"), str):
        raise RuntimeError(json.dumps(resp, ensure_ascii=False)[:200])
    key = key_for(rid, ECODE if session else None)
    raw = base64.b64decode(resp["result"])
    try:
        c = AES.new(key, AES.MODE_GCM, nonce=raw[:12])
        return json.loads(c.decrypt_and_verify(raw[12:-16], raw[-16:]).decode())
    except Exception:
        return json.loads(unpad(AES.new(key, AES.MODE_ECB).decrypt(raw), 16).decode())

def relogin(proxies=None, verify=True):
    """自动重登: username.token.get -> RSA(PKCS1(md5hex)) -> passwd.login -> 更新 credentials.local.md"""
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_v1_5
    mobile = _C.get("username", "")
    password = _os.environ.get("TUYA_PASSWORD", _C.get("password", ""))
    assert mobile and password, "credentials.local.md 需要 username/password 两行"
    tv = _call_raw("tuya.m.user.username.token.get", "2.0",
                   {"countryCode": "86", "isUid": False, "username": mobile},
                   proxies=proxies, verify=verify)["result"]
    key = RSA.construct((int(tv["publicKey"]), int(tv.get("exponent", "65537"))))
    # 密码编码: hex(md5(password))，RSA/NONE/PKCS1Padding 加密后转 hex
    enc = PKCS1_v1_5.new(key).encrypt(hashlib.md5(password.encode()).hexdigest().encode())
    out = _call_raw("tuya.m.user.mobile.passwd.login", "4.0",
                    {"countryCode": "86", "ifencrypt": "1", "mobile": mobile,
                     "options": "{\"group\": 1,\"mfaCode\": \"\"}",
                     "passwd": enc.hex(), "token": tv["token"]},
                    proxies=proxies, verify=verify)
    if not out.get("success"):
        raise RuntimeError(f"passwd.login failed: {out.get('errorCode')} {out.get('errorMsg')}")
    r = out["result"]
    print(f"relogin OK ecode={r['ecode']}")
    cf = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "credentials.local.md")
    lines = open(cf, encoding="utf-8").read()
    lines = re.sub(r"- 会话（[^）]*）:.*", f"- 会话（自动重登）: ecode={r['ecode']}, sid={r['sid']}", lines, count=1)
    open(cf, "w").write(lines)
    return r

DEVICES = {}
for _ln in open(_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "credentials.local.md"), encoding="utf-8"):
    _m = re.match(r"- (.+?) devId: (\w+)", _ln.strip())
    if _m:
        DEVICES[_m.group(1)] = _m.group(2)

def _cmd_session():
    """会话调用统一入口：TUYA_PROXY 环境变量可走代理"""
    return call

def device_status(dev_id: str, dps=None):
    po = {"devId": dev_id}
    if dps: po["dps"] = dps
    out = call("tuya.m.device.dp.get", "1.0", po, session=True)
    return json.loads(out.get("plain") or "{}")

def device_control(dev_id: str, dps: dict):
    """dps 值类型即控制类型：bool=开关, str=枚举(open/close/stop), int=百分比"""
    out = call("tuya.m.device.dp.publish", "1.0",
               {"devId": dev_id, "dps": json.dumps(dps, separators=(",", ":"))}, session=True)
    j = json.loads(out.get("plain") or "{}")
    if not j.get("success"):
        raise RuntimeError(f"dp.publish failed: {j.get('errorCode')} {j.get('errorMsg')}")
    return j

def light(name: str, on: bool):
    """按 credentials.local.md 里的设备别名控制灯（dp1 布尔）"""
    dev_id = DEVICES[name]
    device_control(dev_id, {"1": bool(on)})
    st = device_status(dev_id, ["1"])
    print(f"{name} -> dp1={st['result'].get('1')}")

CURTAINS = {"主卧": "6c7845f4995b9006cebirr", "客厅": "6cf633be4929ddb239mjus"}

def curtain(name: str, action):
    """action: open/close/stop 或 0-100 百分比(int)"""
    dev_id = CURTAINS.get(name) or DEVICES.get(name)
    assert dev_id, f"未知窗帘: {name}，可用: {list(CURTAINS)}"
    dps = {"1": action} if isinstance(action, str) else {"2": int(action)}
    device_control(dev_id, dps)
    time.sleep(2)
    st = device_status(dev_id, ["1", "2", "3"])
    print(f"{name} -> {st['result']}")

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "validate"
    if cmd == "relogin":
        px = _os.environ.get("TUYA_PROXY")
        proxies = {"https": px} if px else None
        relogin(proxies=proxies, verify=not px)
        sys.exit(0)
    if cmd == "validate":
        out = call("tuya.p.time.get", "1.0", None, session=False)
        print("time.get http:", out["http"], "success:", json.loads(out.get("plain", "{}")).get("success") if out.get("plain") else None)
        out2 = call("tuya.m.user.info.get", "1.0", None, session=True)
        print("user.info.get http:", out2["http"])
        if out2.get("plain"):
            j = json.loads(out2["plain"])
            print("user.info success:", j.get("success"), "keys:", list(j.get("result", {}).keys())[:8] if isinstance(j.get("result"), dict) else type(j.get("result")))
        else:
            print("user.info resp:", json.dumps(out2["resp"])[:500], out2.get("plain_err"))
    elif cmd == "control":
        # control <设备别名或devId> <json dps>
        target = sys.argv[2] if len(sys.argv) > 2 else None
        dev = DEVICES.get(target, target)
        dps = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {"1": True}
        device_control(dev, dps)
        print("控制成功:", json.dumps(device_status(dev).get("result"), ensure_ascii=False))
    elif cmd == "query":
        target = sys.argv[2] if len(sys.argv) > 2 else None
        dev = DEVICES.get(target, target)
        out = call("tuya.m.device.dp.get", "1.0", {"devId": dev}, session=True)
        print("http:", out["http"])
        print("plain:", (out.get("plain") or "")[:2000] or json.dumps(out["resp"])[:800])
    elif cmd == "devices":
        for name, dev in DEVICES.items():
            st = device_status(dev)
            print(f"{name} ({dev}):", json.dumps(st.get("result"), ensure_ascii=False))
    elif cmd == "curtain":
        # curtain <主卧|客厅> <open|close|stop|百分比>
        action = sys.argv[3] if len(sys.argv) > 3 else "open"
        curtain(sys.argv[2], int(action) if action.isdigit() else action)
