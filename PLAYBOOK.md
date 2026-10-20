# 小海智家（涂鸦 OEM App）云端控制完全攻破手册

日期：2026-10-19 ~ 2026-10-20
目标：不迁移设备、不 root 手机，在自有服务器上以代码控制涂鸦 OEM App（小海智家）绑定的智能家居设备。
结果：✅ 完全打通。响应解密、请求签名、会话伪造、设备控制、状态回读全部实现。

---

## 0. 背景与架构认知

- 小海智家是涂鸦智能的 OEM App（clientId=`<YOUR-APPKEY>`，API host `<YOUR-OEM-DOMAIN>`，域名属 <YOUR-OEM-BRAND>/中海）。
- 设备本体是标准涂鸦方案（Wi-Fi 面板/网关 + Zigbee 子设备），云端数据在涂鸦云（数据中心 AY 中国）。
- App 与云的交互分两条通道：
  - **HTTP `api.json`（atop 协议）**：设备列表、状态查询、会话管理 → 响应体 AES 加密
  - **长连接（涂鸦 MQTT/TCP）**：控制指令下发（按开关时 HTTP 抓包看不到任何 publish！）
- OEM App 不支持涂鸦 IoT 平台的「App 账号扫码授权」（实测确认），官方云开发路线走不通，因此自建 atop 客户端。

## 1. 抓包阶段（mitmproxy）

要点：
- 手机连任意 Wi-Fi，代理指到 mitmproxy 服务器（Tailscale 内网 IP 会被 Android 系统代理绕过，需走公网 IP + 云防火墙放行 8080，用完即关）
- Android 7+ App 不信任用户证书——本例中小海智家信任用户证书，直接安装 mitmproxy CA 即可解密 HTTPS（若 App 不信任，需模拟器 AOSP 镜像 adb root 装系统证书）
- 关键脚本：`capture_full.py`——**必须同时记录请求体（含 requestId/sid/sign）和响应体**，只记响应会导致后续无法解密
- 需要抓的关键流量：
  1. 冷启动刷新设备列表（拿密文样本）
  2. **退出登录 → 重新登录**（`validate.code.login` / `passwd.login` 响应里有会话 `ecode`，注意登录可能走密码或短信两个不同接口）
  3. 若要找控制报文：抓不到——控制走 TCP 长连接，不经过 HTTP 代理

## 2. 响应解密逆向（APK 分析）

APK 从应用商店下载即可（无需脱壳，标准 ProGuard 混淆 + 关键逻辑在 native）。

核心算法（还原自 `com.tuya.smart.android.network.Business.decryptResponse`，classes2.dex + lib/arm64-v8a/libjnimain.so）：

```
digest = HMAC-SHA256(key=requestId, message=S)      # requestId 是每个请求的 UUID，在请求表单里
key16  = hex(digest)[:16]                            # 32位十六进制字符串取前16个ASCII字符
plain  = AES-128-ECB-PKCS5(key16, base64decode(result))   # et!=3
        或 AES-128-GCM(key16, nonce=密文前12B, tag=末尾16B)  # et=3
```

其中 `S`（native 全局密钥材料）= `A_{TOKEN}_{APPSECRET}`：
- `APPSECRET` 硬编码在 `SmartApplication.initSdk`（dex 明文可搜）
- `TOKEN` 来自 `assets/t_s.bmp`（又是伪装成 BMP 的密钥 blob）
- 会话接口的 key = HMAC(requestId, S + "_" + ecode)，匿名接口不带 ecode

反向验证方法：拿「请求 requestId + 响应 result」成对样本逐个试候选 S 公式（ECB+GCM 双模式），解出以 `{` 开头的 JSON 即命中。本例耗时最长的坑：S 的组装格式（`A_` 前缀、bmp token）。

工具链：androguard/jadx 反编译 + `strings libjnimain.so` 找 HMAC/AES 常量 + 真实样本暴力验证。

## 3. 请求签名逆向

```
sign = HMAC-SHA256(key=S, message=sorted_params_join)
message = "||".join(f"{k}={v}" for k in 固定顺序键列表 if v 非空)   # v 含 postData 时
postData 参与签名时用 md5(postData) 十六进制做 swap32（前后8字节两两交换）后再代入
```

SIGN_KEYS = 具体字段序列见本地 `credentials.local.md`（按此顺序拼接，非字母序；从 dex 提取）

⚠️ 最大的坑：**伪造请求的表单字段必须和真实请求完全一致**。真实控制请求不带 `appType`/`equipmentId`/`gid`，多带会报 `BATCH_API_PARAM_WRONG`。逐字段对照抓包样本。

## 4. 会话（ecode/sid）

- 登录接口响应（解密后）含 `ecode`（会话密钥标识）和 `sid`（60位会话ID）
- 会话有效期有限（实测数小时内失效），失效报 `USER_SESSION_LOSS`
- 续期方式：重新登录抓包取新 ecode/sid（无 root 无法自动续期；若要无人值守需定期人工或逆向 token 刷新）
- 伪造请求时 `sid` 必须用完整 60 位（截断会失败）

## 5. 设备控制

- 内层 API：`tuya.m.device.dp.publish` v1.0，postData `{"devId":"6cxxx","dps":"{\"1\":true}"}`（dps 是字符串化的 JSON）
- 可通过 `tuya.m.api.batch.invoke` 批量（内层 envelope 结构复杂）或直接单发（推荐单发）
- 状态回读：`tuya.m.device.dp.get` / `tuya.m.device.get`，或从设备列表响应的 `dataPointInfo.dps` 取
- 设备清单/功能点/localKey：从解密后的设备列表提取（`devices_summary.json`）
- Zigbee 子设备（窗帘等）在云控模式下和直连设备无区别，都走 devId

## 6. 完整调用链（tuya_client.py）

1. 生成 requestId(UUID)、time
2. 组装表单（参数与真实请求严格一致）
3. 计算 sign（HMAC-SHA256）
4. postData 用会话 key AES-GCM 加密（et=3）
5. POST 到 api.json
6. 响应 result 用同 key 解密（GCM/ECB 自动尝试）
7. 校验 success 字段

## 7. 踩坑记录

| 坑 | 教训 |
|---|---|
| 抓包只记响应 | requestId 只在请求侧，无配对样本无法解密，全部重抓 |
| 过滤规则漏自定义域名 | OEM 用 `<YOUR-OEM-DOMAIN>`，不是涂鸦官方域名 |
| Android 系统代理绕过 Tailscale | 代理目标要走公网 IP |
| S 公式猜测错误 | native 层 `A_` 前缀 + t_s.bmp token，需暴力验证候选 |
| ecode 过期 | 会话数小时失效，控制报 USER_SESSION_LOSS，重登即解 |
| 多带表单字段 | 控制请求多 appType/equipmentId/gid 会 BATCH_API_PARAM_WRONG |
| sid 截断 | 必须 60 位全量 |
| 找控制报文方向错误 | 控制不走 HTTP，抓包抓不到，只能逆向 SDK 确认 api 名 |

## 8. 文件清单

- `tuya_client.py` —— 完整客户端（签名/加密/解密/控制/回读）
- `ANALYSIS.md` —— 加密算法逆向详情（native 偏移地址备查）
- `capture.jsonl` —— 全量抓包（脱敏后可做回归测试集）
- `decrypted2.jsonl` —— 解密后的响应
- `devices_summary.json` —— 设备清单（devId/name/localKey/DP）
- `decrypt_tuya.py` / `extract_devices.py` —— 批量解密与设备提取工具
- `capture_full.py` —— 抓包脚本（请求+响应成对记录）

## 9. 安全提醒

- appSecret/ecode/localKey 等同于账号控制权，文件注意保管，不要提交公开仓库
- 云防火墙的临时端口用完立即删除
- 本方案仅用于控制自己名下的设备
