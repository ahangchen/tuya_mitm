#!/usr/bin/env python3
"""解密 Tuya OEM App (小海智家) api.json 响应 —— 公式已实测验证（见 ANALYSIS.md）。

已确认算法（2026-10-19 native 逆向 + 真实抓包 sign oracle 验证）：
  S      = "A_" + token + "_" + appSecret          # token 从 assets/t_s.bmp 按 appId 提取
  digest = HMAC-SHA256(key=requestId, msg=S 或 S+"_"+ecode)   # 会话接口需登录 ecode
  key16  = hex(digest)[:16] (ASCII)                # AES-128 密钥
  et=3   : AES-GCM，base64(result) 前 12B 为 nonce，末尾 16B 为 tag
  et!=3  : AES-128-ECB-PKCS5
  sign   = md5hex("result=" + result + "||t=" + t + "||" + key16)   # 可用作离线 key 验证

用法: ./decrypt_tuya.py --capture capture.jsonl --out decrypted.jsonl [--ecode <登录ecode>]
"""
import argparse, base64, hashlib, hmac, json, sys
from urllib.parse import parse_qs
from Crypto.Cipher import AES

APP_ID = "<YOUR-APPKEY>"
APP_SECRET = "<YOUR-APPSECRET>"
TOKEN = "<YOUR-TS-BMP-TOKEN>"   # extracted from assets/t_s.bmp via appId
S_SECRET = "A_" + TOKEN + "_" + APP_SECRET   # verified against 10/10 anonymous captures

def derive_key(request_id: str, ecode=None) -> bytes:
    secret = S_SECRET if not ecode else S_SECRET + "_" + ecode
    return hmac.new(request_id.encode(), secret.encode(), hashlib.sha256).hexdigest().encode()[:16]

def sign_of(key16: bytes, result: str, t) -> str:
    return hashlib.md5(("result=" + result + "||t=" + str(t) + "||" + key16.decode()).encode()).hexdigest()

def decrypt_result(result_b64: str, key16: bytes, et="3") -> bytes:
    raw = base64.b64decode(result_b64)
    if et == "3":
        cipher = AES.new(key16, AES.MODE_GCM, nonce=raw[:12])
        return cipher.decrypt_and_verify(raw[12:-16], raw[-16:])
    c = AES.new(key16, AES.MODE_ECB)
    out = c.decrypt(raw)
    pad = out[-1]
    if 1 <= pad <= 16 and out[-pad:] == bytes([pad]) * pad:
        return out[:-pad]
    raise ValueError("bad padding")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--capture", required=True)
    ap.add_argument("--out", default="/home/ubuntu/coding/tuya-mitm/decrypted.jsonl")
    ap.add_argument("--ecode", default=None, help="登录会话 ecode（会话接口必填，否则跳过）")
    a = ap.parse_args()

    n_ok = n_sess = n_fail = 0
    out = open(a.out, "w")
    for line in open(a.capture):
        rec = json.loads(line)
        if "/api.json" not in rec["url"]:
            continue
        q = {k: v[0] for k, v in parse_qs(rec["req_body"]).items()} if rec.get("req_body") else {}
        try:
            body = json.loads(rec["resp_body"])
        except Exception:
            continue
        rid, res, t, sign = q.get("requestId"), body.get("result"), body.get("t"), body.get("sign")
        if not rid or not res:
            continue
        sid = q.get("sid")
        if sid and not a.ecode:
            n_sess += 1
            continue
        key = derive_key(rid, a.ecode if sid else None)
        entry = {"ts": rec["ts"], "api": q.get("a"), "requestId": rid,
                 "key16": key.decode(), "sign_ok": sign_of(key, res, t) == sign}
        try:
            pt = decrypt_result(res, key, q.get("et", "3"))
            try:
                entry["decrypted"] = json.loads(pt)
            except Exception:
                entry["decrypted"] = pt.decode("utf-8", "replace")
            n_ok += 1
        except Exception as e:
            entry["error"] = f"decrypt failed: {e}"
            n_fail += 1
        out.write(json.dumps(entry, ensure_ascii=False) + "\n")
    out.close()
    print(f"decrypted={n_ok} failed={n_fail} session_skipped={n_sess} -> {a.out}")
    if n_sess:
        print(f"!! {n_sess} 条会话接口需要 --ecode（登录时下发的会话密钥，抓登录接口可得）")

if __name__ == "__main__":
    main()
