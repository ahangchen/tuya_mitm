#!/usr/bin/env python3
"""从 decrypted.jsonl 提取设备汇总 -> devices_summary.json
汇总: devId, name, localKey, modelId, 功能点(dp 名称/权限)。
"""
import json, sys, argparse

def walk(o):
    """递归产出所有 dict，找含 devId 的节点"""
    if isinstance(o, dict):
        if "devId" in o and ("localKey" in o or "name" in o):
            yield o
        for v in o.values():
            yield from walk(v)
    elif isinstance(o, list):
        for v in o:
            yield from walk(v)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--decrypted", default="/home/ubuntu/coding/tuya-mitm/decrypted.jsonl")
    ap.add_argument("--out", default="/home/ubuntu/coding/tuya-mitm/devices_summary.json")
    a = ap.parse_args()
    devs = {}
    for line in open(a.decrypted):
        rec = json.loads(line)
        dec = rec.get("decrypted")
        if not isinstance(dec, (dict, list)):
            continue
        for node in walk(dec):
            did = node.get("devId")
            if not did or did in devs:
                continue
            devs[did] = {
                "devId": did,
                "name": node.get("name"),
                "localKey": node.get("localKey"),
                "modelId": node.get("modelId"),
                "productId": node.get("productId"),
                "productName": node.get("productName"),
                "schema": node.get("schema") or node.get("dps") or node.get("function") or {},
            }
    out = {"device_count": len(devs), "devices": list(devs.values())}
    json.dump(out, open(a.out, "w"), ensure_ascii=False, indent=2)
    print(f"{len(devs)} devices -> {a.out}")

if __name__ == "__main__":
    main()
