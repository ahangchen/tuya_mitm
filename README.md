# tuya_mitm — 涂鸦 OEM App（小海智家）云端控制逆向攻关

不 root 手机、不迁移设备、不用涂鸦开发者 API，通过 mitmproxy 抓包 + APK 逆向，破解涂鸦 atop 协议的响应加密与请求签名，最终用自己的代码在云端直接控制 OEM App 绑定的设备。

> ⚠️ 仅限研究自己账号/设备。所有密钥、会话、设备 ID 均已脱敏为占位符。

## 目录结构

| 文件 | 说明 |
|---|---|
| `PLAYBOOK.md` | 全流程 playbook（抓包 → 提密钥 → 破签名 → 控设备），最小修改可复刻 |
| `ANALYSIS.md` | 本次攻关的详细分析记录：加密体系、签名算法、踩坑时间线 |
| `tuya_client.py` | 最终可用客户端：签名 + GCM 加密 + api.json 调用 + 控制开灯（已脱敏） |
| `decrypt_tuya.py` | 批量解密抓包文件（capture.jsonl → decrypted.jsonl） |
| `crack_sign.py` | S 公式暴力验证脚本（用成对样本试候选密钥材料） |
| `extract_bmp_key.py` | 从 assets/t_s.bmp 提取内嵌 token（移植自 nalajcie/tuya-sign-hacking） |
| `extract_devices.py` | 从解密后的设备列表提取 devId/name/localKey/功能点 |
| `dump_resp.py` | 早期响应 dump 脚本 |
| `skill/tuya-oem-cloud-control/` | 沉淀的可复用 skill（含脱敏示例客户端和抓包脚本） |

抓包原始数据（capture.jsonl、decrypted*.jsonl、devices_summary.json 等）含真实账号/设备信息，不入库。

## 核心结论（速览）

- 响应解密：`key = HMAC-SHA256(key=requestId, msg=S [+ "_" + ecode]).hex()[:16]`；`et=3` 走 AES-GCM（nonce 前 12B、tag 尾 16B），否则 AES-128-ECB/PKCS5
- `S = "A_" + t_s.bmp内嵌token + "_" + appSecret`（appSecret 在 dex `SmartApplication.initSdk` 明文可搜）
- 请求签名：参数按固定 key 序 `k=v` 以 `||` 拼接，`postData` 用 `swap32(md5hex(密文))` 替换，`sign = HMAC-SHA256(S, msg)`
- 请求体加密：`key = hex(HMAC-SHA256(requestId, S+"_"+ecode))[:16]` + AES-GCM
- 控制接口：`tuya.m.device.dp.publish`，`dps` 是字符串化的 JSON

详细过程见 `PLAYBOOK.md` 和 `ANALYSIS.md`。

## 依赖

```
pip install requests pycryptodome
```
