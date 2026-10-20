---
name: "tuya-oem-cloud-control"
description: "Reverse-engineer a Tuya OEM smart-home app (HTTP atop protocol + control API) to control your own devices from code without root or device migration"
---

# Tuya OEM Cloud Control Skill

Control devices bound to a Tuya OEM smart-home app (小海智家, or any OEM) from your own server code, without root, without migrating devices, without Tuya developer API access.

## When to use
- Your devices are in an OEM Tuya app, and the Tuya IoT platform app-account QR authorization fails (common for OEM apps).
- You want server-side cloud control (works anywhere, no LAN needed).

## Prerequisites
- A Linux server with a public IP (for phone proxy) and outbound internet
- The OEM app's APK file (from any app store)
- An Android phone that trusts user CA certificates (test first: if the app loads its device list through mitmproxy, you're good; if not, use an Android emulator with a non-Google-Play image + `adb root` + system CA)

## Phase 1 — Capture paired traffic
1. Run mitmproxy on the server: `mitmdump -s scripts/capture_full.py -p 8080 --set block_global=false` (the addon records request body + response body per flow; both are REQUIRED).
2. Phone: set Wi-Fi HTTP proxy to server public IP:port; install mitmproxy CA (`http://mitm.it`); open the app; cold-start to refresh the device list; then log out and log back in (captures the login response that contains the session `ecode` and `sid`).
3. Note: cloud firewall must allow the proxy port temporarily; close it afterwards.

## Phase 2 — Recover secrets from the APK
1. Unzip the APK; find in dex: `appKey/clientId` and `APPSECRET` (search `initSdk` / `SmartApplication`).
2. Find the token blob: usually an asset like `t_s.bmp` / `fixed_key.bmp` (fake BMP, key material). The request secret S is often `A_{TOKEN}_{APPSECRET}` but varies by SDK version.
3. Response decryption (verified across Tuya atop SDKs):
   - `key = HMAC-SHA256(key=requestId, message=S [+ "_" + ecode for session APIs]).hex()[:16]` (ASCII)
   - `plain = AES-128-ECB-PKCS5(key, b64decode(result))` or AES-128-GCM when `et=3` (nonce = first 12 bytes of ciphertext, tag = last 16)
4. Brute-force-validate candidate S formulas against real paired samples: decrypt each captured `result` and look for JSON starting with `{`. This is the fastest way to converge — always validate with data, not by reading code alone.

## Phase 3 — Request signing
- `sign = HMAC-SHA256(key=S, msg=join)` where join = `k=v` pairs joined by `||` over a fixed key order (extract from dex, ); when `k=postData`, substitute `swap32(md5hex(postData))` (swap first/last 8 bytes of the 32-hex digest).
- CRITICAL: the forged form fields must match the real request exactly, per API. Extra fields (appType/equipmentId/gid present in list APIs but absent in control APIs) cause `BATCH_API_PARAM_WRONG`.

## Phase 4 — Session
- Login responses (decrypt them!) contain `ecode` (session key material) and `sid` (60 chars, use full, never truncate).
- Session APIs: key message = `S + "_" + ecode`.
- Sessions expire in hours → re-login capture refreshes ecode/sid.

## Phase 5 — Control
- Inner API: `tuya.m.device.dp.publish` v1.0, postData `{"devId":"<id>","dps":"{\"1\":true}"}` (dps is a STRINGIFIED json).
- Read back with `tuya.m.device.dp.get` / device list `dataPointInfo.dps`.
- Device inventory (devId/name/localKey/DpName) comes from the decrypted device-list responses.
- Zigbee sub-devices are controlled the same way via their devId (cloud side).
- Reference implementation: `tuya_client_example.py` in this skill's assets — build form → sign → encrypt postData (GCM) → POST api.json → decrypt response.

## Gotchas (all hit in practice)
- Capture must pair requests with responses; requestId only exists on the request side.
- OEM apps use custom API domains (not tuyacn.com) — don't filter by domain, capture all.
- Android system proxy bypasses Tailscale/VPN addresses; proxy must point to a public IP.
- Control commands do NOT appear in HTTP captures — the app uses a persistent MQTT/TCP channel; don't chase them, just reverse the publish API from dex.
- Sessions die (USER_SESSION_LOSS) — refresh ecode by re-login capture.
- Keep appSecret/ecode/localKey secret; they are equivalent to account control. Never commit them to public repos.
