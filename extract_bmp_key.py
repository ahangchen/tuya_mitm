#!/usr/bin/env python3
"""Tuya fixed_key.bmp 内嵌 token 提取器（移植自 nalajcie/tuya-sign-hacking read-keys-from-bmp）。

对旧版 SDK 格式（header=[keys_cnt][coeffs_cnt][magic4]，系数矩阵高斯消元）支持穷举 seed / 全位置扫描。
用法:
  python3 extract_bmp_key.py [--bmp apk/assets/fixed_key.bmp] [--seed <字符串>]
不指定 seed 时做全位置扫描，输出可打印的候选 key。
"""
import argparse, struct
from fractions import Fraction

def load(bmp):
    data = open(bmp, 'rb').read()
    off = struct.unpack('<I', data[10:14])[0]
    return data[off:]

def parse(pix, p):
    L = len(pix)
    cnt = pix[(p + 1) % L]
    mul = pix[(p + 2) % L]
    if not (1 <= cnt <= 4 and 1 <= mul <= 8):
        return None
    magic = (pix[(p + 3) % L] << 24) | (pix[(p + 4) % L] << 16) | (pix[(p + 5) % L] << 8) | pix[(p + 6) % L]
    if magic >= 1 << 31:
        magic -= 1 << 32
    offs = p ^ magic
    coeffs = []
    for _ in range(mul):
        v1_off = offs % L
        v1_len = pix[v1_off]
        if not 1 <= v1_len <= 40:
            return None
        s1 = bytes(pix[(v1_off + 1 + i) % L] for i in range(v1_len))
        v2_off = (v1_off + v1_len + 1) % L
        v2_len = pix[v2_off]
        if not 1 <= v2_len <= 40:
            return None
        s2 = bytes(pix[(v2_off + 1 + i) % L] for i in range(v2_len))
        vn_off = (v2_off + v2_len + 1) % L
        vnext = (pix[vn_off] << 24) | (pix[(vn_off + 1) % L] << 16) | (pix[(vn_off + 2) % L] << 8) | pix[(vn_off + 3) % L]
        if vnext >= 1 << 31:
            vnext -= 1 << 32
        offs = v1_off ^ vnext
        coeffs.append((s1.hex(), s2.hex()))
    M = [[Fraction(int(a, 16)) ** (mul - 1 - e) for e in range(mul)] + [Fraction(int(b, 16))] for a, b in coeffs]
    for c in range(mul):
        piv = next((r for r in range(c, mul) if M[r][c] != 0), None)
        if piv is None:
            return None
        M[c], M[piv] = M[piv], M[c]
        inv = M[c][c]
        M[c] = [v / inv for v in M[c]]
        for r in range(mul):
            if r != c and M[r][c] != 0:
                f = M[r][c]
                M[r] = [M[r][k] - f * M[c][k] for k in range(mul + 1)]
    res = M[mul - 1][mul] / M[mul - 1][mul - 1]
    if res.denominator != 1:
        return None
    h = format(res.numerator, 'x')
    for hh in (h, h[1:]):
        try:
            s = bytes.fromhex(hh).decode()
            if s.isprintable():
                return s
        except Exception:
            pass
    return None

def jhash(s):
    acc = 0
    for ch in s.encode():
        acc = ((acc << 5) - acc + ch) & 0xFFFFFFFF
    if acc >= 1 << 31:
        acc -= 1 << 32
    return abs(acc)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--bmp', default='/home/ubuntu/coding/tuya-mitm/apk/assets/fixed_key.bmp')
    ap.add_argument('--seed', default=None, help='定位用种子字符串（旧版为 appId）')
    a = ap.parse_args()
    pix = load(a.bmp)
    L = len(pix)
    if a.seed:
        p = (jhash(a.seed) % L) // 2
        print(a.seed, '-> pos', p, '->', parse(pix, p))
    else:
        n = 0
        for p in range(L):
            if not (1 <= pix[(p + 1) % L] <= 4 and 1 <= pix[(p + 2) % L] <= 8):
                continue
            r = parse(pix, p)
            if r and 8 < len(r) < 64:
                print(f'pos {p} KEY: {r}')
                n += 1
        print(f'{n} candidates; pixels={L}')

if __name__ == '__main__':
    main()
