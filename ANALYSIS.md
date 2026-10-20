# Tuya OEM App (小海智家) api.json 响应加密逆向分析报告

日期：2026-10-19
APK 解包目录：`/home/ubuntu/coding/tuya-mitm/apk/`（42 个 classes*.dex + lib/arm64-v8a/libjnimain.so）

## 0. 请求 sign 算法 —— 已完全攻破并实测验证 ✓（2026-10-20）

对 capture.jsonl 全部 420 条带 sign 请求离线验证：405 条直接通过（其余 15 条为 capture 截断/另一会话样本，
其中已解密的 3 条 batch.invoke 同样验证通过）。公式：

```
S    = "A_" + t_s.bmp_token + "_" + appSecret        # 与响应侧完全相同！
     = "A_<YOUR-TS-BMP-TOKEN>_<YOUR-APPSECRET>"
     （不需要证书 SHA256、不需要 bmp 请求侧 token、签名阶段不含 ecode）

msg  = 对参与签名的参数（key 列表：a,v,lat,lon,lang,deviceId,appVersion,ttid,isH5,h5Token,
       os,clientId,postData,time,requestId,et,n4h5,sid,chKey,sp）按 key 升序，
       跳过空值，拼成 "k1=v1||k2=v2||..."（无首尾分隔符）
     其中 postData 项的值 = swap32(md5hex(密文 postData))，
       swap32(s)=s[8:16]+s[0:8]+s[24:32]+s[16:24]  (classes39 TuyaApiSignManager.swapSignString)

sign = HMAC-SHA256(key=S, msg=msg) 的 hex
```

请求体加密（postData，et=3）：`key = hex(HMAC-SHA256(key=requestId, msg=S+"_"+ecode))[:16]`（ASCII），
AES-GCM，`base64(nonce12 || ct || tag16)`。已用真实抓包 batch.invoke 请求解密验证 ✓
（会话接口响应解密同样用 S+"_"+ecode，ecode=<YOUR-ECODE> 时全部可解 ✓）。

batch.invoke 内层 apis[] 每项自带独立 requestId/sign（同一公式，sid 用完整 60 位会话），
外层 form 的 sid 是前 40 位截断。外层 form 还带 gid（不参与签名）。

实测：伪造 tuya.p.time.get（匿名）→ 服务器接受 sign 并返回可解密 success=true ✓。
会话已过期：tuya.m.user.info.get → USER_SESSION_LOSS；batch.invoke 控制设备（含对抓包原始请求的
精确重放）→ BATCH_API_PARAM_WRONG。控制需重新登录获取新 ecode。

## 1. 结论（算法）——已实测验证 ✓

2026-10-19 晚补充：用真实抓包（capture.jsonl 215 对）+ 响应 sign oracle 完整验证：
**匿名接口 10/10 全部 sign 校验通过且 GCM 解密成功**（含 tuya.p.time.get 等）。

最终公式：
```
S      = "A_" + token + "_" + appSecret
token  = 从 assets/t_s.bmp 按 appId 提取的内嵌密钥（nalajcie/tuya-sign-hacking 算法）
         = "<YOUR-TS-BMP-TOKEN>"
appSecret = <YOUR-APPSECRET>
→ S    = "A_<YOUR-TS-BMP-TOKEN>_<YOUR-APPSECRET>"

digest = HMAC-SHA256(key=requestId, msg=S)          # 无会话接口
digest = HMAC-SHA256(key=requestId, msg=S_ecode)    # 会话接口，S_ecode = S + "_" + ecode
key16  = hex(digest)[:16] (ASCII 字节)              # AES-128 密钥
et=3   : AES-GCM，base64(result) 前 12B nonce，尾部 16B tag（decryptBytesAppendedNonce2Bytes）
et!=3  : AES-128-ECB/PKCS5
sign   = md5hex("result=" + result + "||t=" + t + "||" + key16)   # MD5Util.md5AsBase64 实际返回 hex
```

S 组装的 native 证据链（doCommandNative cmd==0，libjnimain.so）：
- 0x3bd1c(env, ctx, flag)：GetObjectClass(ctx)→getAssets→读取 **assets/t_s.bmp**（flag=true 时 t_s_daily.bmp）内容
- 0x3f0d0(appId, bmp内容)：按 appId 提取 bmp 内嵌 token → **G1**(0x96590)
- flag(mSecurity|mNTY)==0 时：**G2 = "A"**（.rodata 0x20af0 常量）；否则 G2=G2+G4（daily key）
- S = G2 + "_" + G1 + "_" + appSecret（0x3d4d0-0x3d530，'_' 分隔符 @0x2128a）

会话接口：需要登录时下发的 ecode（TuyaApiParams.ecode，`S+"_"+ecode` 作 HMAC msg）。
当前抓包未含登录流程 → 195 条会话响应待 ecode。**行动：抓一次退出登录→重新登录**，
登录接口是匿名接口（可用 S 解密），解密后从登录响应提取 ecode，即可解密全部。

api.json 响应体 `{"result":"<base64>","sign":"<hex>","t":<ms>}` 的解密流程（还原自
`com.tuya.smart.android.network.Business.decryptResponse`，classes2.dex）：

1. **派生 AES 密钥**（native，`libjnimain.so` `getEncryptoKey(requestId, ecode)` @ 0x3d93c）：
   ```
   secret = S                       # ecode == null 时
   secret = S + "_" + ecode         # ecode 非空时（ecode = 会话 ecode）
   digest = HMAC-SHA256(key = requestId, message = secret)   # 0x407c0 = HMAC(setkey=data1, update=data2)
   key    = hex(digest).encode()[:16]                        # 32 位十六进制字符串取前 16 字节 ASCII
   ```
2. **解密**（`et != "3"` 时，默认路径）：
   ```
   plain = AES-128-ECB-PKCS5Decrypt(key, base64decode(result))   # javax.crypto.Cipher("AES")，无 IV
   ```
   `et == "3"` 时改用 AES-GCM：nonce 取密文前 12 字节，密文其余部分 + 末尾 16 字节 tag
   （`AesGcmUtil.decryptBytesAppendedNonce2Bytes`）。
3. `sign` 为对 key/result 的 HMAC 校验（`Business.verifyResponseResult`）。

## 2. 密钥材料 S 的来源

- `S` 是 libjnimain.so 内的全局 std::string（.bss @ 0x965c0）。
- 初始化：`TuyaSmartNetWork.initialize()` → `TuyaNetworkSecurity.initJNI(ctx)`（classes39.dex）→
  `JNICLibrary.doCommandNative(ctx, 0, mAppSecret.getBytes(), mAppId.getBytes(), mSecurity|mNTY, mD)`。
- 本 App（SmartApplication.initSdk，classes23.dex）的值：
  - **appKey/appId = `<YOUR-APPKEY>`**
  - **appSecret   = `<YOUR-APPSECRET>`**
  - API host: `https://<YOUR-OEM-DOMAIN>/api.json`
- 即 S 由 appSecret/appId（可能混入设备 uuid，见 getConfig 流程）在 native 层组装；
  最可能的候选：`S = appSecret`。`decrypt_tuya.py` 内置多候选拼接，抓到 requestId 后可自动验证。

## 3. 关键缺失：requestId 未被抓包

- `requestId = UUID.randomUUID()`，由 App **每个请求随机生成**，放在请求侧（query/body），用于 HMAC key。
- `bodies.log` 只记录了响应（url 无 query、无请求体），因此**现有 131 条 api.json 密文无法离线解密**——
  不是算法问题，是每次请求的 HMAC key（requestId）没有留下任何副本，数学上不可恢复。
- 另外会话接口还需要登录会话的 `ecode`（会话接口 key = HMAC(requestId, S+"_"+ecode)）。

## 4. 解密路径相关代码位置（备查）

| 内容 | 位置 |
|---|---|
| decryptResponse / AESUtil / AesGcmUtil | classes2.dex `com.tuya.smart.android.network.Business` |
| TuyaNetworkSecurity (Java 封装) | classes2.dex(桩) / classes39.dex(实现) |
| native 注册表 | libjnimain.so `.rela.dyn` @0x96230-0x962f8 |
| getEncryptoKey 实现 | libjnimain.so 0x3d93c |
| HMAC 封装 | libjnimain.so 0x407c0（key=data1, msg=data2, SHA256, 输出 hex %02x @0x2212a） |
| initJNI / doCommandNative | classes39.dex + libjnimain.so 0x3cc8c |

## 5. 公开资料交叉验证（nalajcie/tuya-sign-hacking、tuyapi issue #7）

- **请求签名** secret 格式：`[APK证书SHA256]_[bmp内嵌token]_[appSecret]`，HMAC-SHA256（与本地
  native 分析的 4 段 `G5_G2_G1_X` 拼接吻合，多出的一段应为会话/ecode 或版本差异）。
- **响应 key 格式**：issue #7 示例请求 key `OTM0ZTA4ZDBmZGM3ODg0NQ==` → base64 解码为
  `934e08d0fdc78845`——正是「hex 摘要取前 16 个 ASCII 字符」，与本地逆向结论一致 ✓
- 每请求随机 key（requestId 派生）+ AES/GCM 也被 issue #7 描述 ✓（本地 SDK：ECB 为主，et=3 时 GCM）
- bmp token 提取工具：repo 内 `read-keys-from-bmp/`（appId 字符串 jHash 定位 header，
  系数矩阵高斯消元得 key）。**对本地 OEM fixed_key.bmp 用已知 seed（appId/appSecret/文件名）
  均提取失败，且全文件扫描无任何合法 header 位置 → 新版 SDK 的 bmp 为另一种编码
  （可能为静态 AES 加密 blob，见 issue #7 的 daily_app_secret 描述），待后续处理。**
  已写 python 移植版提取器（本文件同目录 extract_bmp_key.py）可继续调试。

## 5b. fixed_key.bmp 的真实用途

fixed_key.bmp 不直接用于 HTTP 响应解密（响应 key 只依赖 requestId + S），但它内嵌的 token
是**请求签名 secret**（及可能的 S 初始化）的组成部分——即抓包伪造/重放请求时必需。
（此前报告称"与本任务无关"不准确，特此更正。）

`assets/fixed_key.bmp`（22554B）由 `TuyaUtil.getAssetsData(ctx,"fixed_key.bmp","soisiwoejre".getBytes())`
读取后交给 `TuyaNetworkInterface.setSecurityContent()` → **native UDP/TLS 局域网配网加密**（libtuya native），
与 api.json HTTP 响应加密完全无关。HTTP 通道密钥只依赖 requestId + S(+ecode)。

## 6b. 本 APK 已提取的材料

| 材料 | 值 |
|---|---|
| appKey/clientId | `<YOUR-APPKEY>` |
| appSecret | `<YOUR-APPSECRET>` |
| APK 证书 SHA256 (DER) | `<APK-CERT-SHA256>`（冒号大写：`<APK-CERT-SHA256>`） |
| 证书 | Tuya 官方签发（CN=www.tuya.com, 2021-2075），v1+v2 签名 |
| bmp token | **未提取成功**：OEM fixed_key.bmp 不符旧版系数矩阵格式（全文件无合法 header），疑为新版加密 blob |

签名 secret 候选（待 requestId 可用时验证）：
`[certSHA256]_[bmpToken]_[appSecret]` 及 dex 观察到的 4 段 `G5_G2_G1_X` 拼接变体。

## 7. 下一步（如何真正拿到明文/localKey）

1. 重新抓包，**必须记录请求**：使用 `capture_full.py`（本目录），记录
   `flow.request.url`（含 requestId query 参数）+ 响应体。
2. 用 `decrypt_tuya.py` 解密：自动尝试 S 候选（appSecret 及组合）；会话接口需传 ecode
   （登录响应 `result` 解密后可提取，或抓包 Cookie/header）。
3. 解密成功后运行 `extract_devices.py` 生成 `devices_summary.json`（devId/name/localKey/modelId/功能点）。

## §7 会话/控制实测补充（01:00–01:45）
- passwd.login（455 行）响应：匿名 plain-S 密钥即可解（key=hex(HMAC-SHA256(rid,S))[:16]，GCM nonce-first）。得到 ecode=<YOUR-ECODE>。该会话因 00:55:52 logout 失效；当前有效会话=00:56:14 短信登录：ecode=<YOUR-ECODE>，sid=<YOUR-FULL-SID>（user.info.get 验证通过 ✅）
- batch.invoke 内层条目 sign：HMAC(**plain S**, 原24键列表, 无 ecode)（已对真实样本验证）
- batch.invoke 外层表单可原样重放成功（服务端不校验 time 新鲜度）
- 控制指令 API：`tuya.m.device.dp.publish` v=1.0，postData={"devId","dps"}（dex classes38 Lcom/tuya/sdk/device/qqpppdp 确认）
- 遗留问题：我们自己加密的 postData（与 app 密钥/格式完全一致）会间歇性被服务端拒 DECODE_ERROR / BATCH_API_PARAM_WRONG；同 ciphertext 原样重放必成功，新 ciphertext 时好时坏（01:29–01:31 窗口内多次成功），疑似服务端会话级防重放/风控状态。设备控制最终未能下达。
- 复跑命令：`cd /home/ubuntu/coding/tuya-mitm && PYTHONPATH=. /home/ubuntu/coding/tuya-venv/bin/python /tmp/ctrl8.py`（若 DECODE_ERROR 等几分钟再试，或让手机开着代理在 app 里点一次灯抓真实 dp.publish 后原样重放）

## §8 🎉 根因确认 & 厨房灯控制成功（02:45）
**DECODE_ERROR / BATCH_API_PARAM_WRONG 根因**：我们构造的表单里带了 `appType=xhzj`、
`equipmentId=<YOUR-EQUIPMENT-ID>`、`gid=<YOUR-GID>` 三个字段——真实 app 请求（capture.jsonl 全部 1257 条）
在带 postData 的 api.json 表单里**没有这些字段**。带上它们服务端即拒绝解密 postData（DECODE_ERROR）。
之前"间歇性成功"（01:29–01:31）是因为那几次测试脚本恰好 pop 掉了这些字段；并非风控/时间窗。

修复：`tuya_client.call()` 现已自动剔除 appType/equipmentId/gid。

**控制指令实测成功**（02:47）：
- API：`tuya.m.device.dp.publish` v=1.0，postData={"devId":"<YOUR-DEV-ID>","dps":{"1":true}}
  （API/版本来自 dex classes38 `qqpppdp.qddqppb`）
- 响应 `{"result":true,"success":true}`
- 回读 `tuya.m.device.dp.get` v=1.0 postData={"devId"}：dps `{"1":true,"2":true,"3":true,...}`
  → **dp1 厨房灯 = true（已开）**

**MQTT 通道逆向结论**（备用，未采用）：
- mSdk=true → 连接参数来自 `qpqbppd`：clientId=`{partnerIdentity}_{appId}_mb_{sid}{md5b64(md5b64(appId)+ecode)[-16:]}`（partnerIdentity=<YOUR-PARTNER-ID>），username=clientId，password=native(libjnimain JNICLibrary doCommandNative cmd=2, 16位中间hex)——未能本地复现，连接 rc=5。
- 但控制其实走 HTTP dp.publish 即可（app 的 MQTT 主要用于状态推送）。
