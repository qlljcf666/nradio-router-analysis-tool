#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================
 NRadio / 蜂易达 DD-5G (Hi6352, OpenWrt) 隐藏安全页
 "密码" (=supass RSA 签名) 计算 / 校验工具
================================================================
逆向对象: /usr/bin/supass  (ARM32, 12814 字节, 2.1.11/2.2.15/mtd27 完全相同)
页面    : http://<网关IP>/cgi-bin/luci/admin/system/security/<fac_key前8位>
调用    : supass -t <校验码ccode> -s <密码hex> -m <MAC>   exit 0 = 通过

【验证算法 (静态逆向 100% 还原)】
  1. H = SHA1( ccode || MAC )          # 两字符串直接拼接, 无任何分隔符
                                        # MAC 用 uci oem.board.id 的原始大小写
  2. EM (256B) = 00 01 | FF * 218 | 00 | DigestInfo_SHA1(15B) | H(20B)
     DigestInfo = 30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14
  3. m = int(EM);  输入密码 s_hex(512 hex 字符 => 256 字节, 大端整数)
     验证: pow(s, 65537, n) == m
  => "密码" 就是用对应 RSA 私钥 d 对 H 做的 PKCS#1 v1.5 签名。

【公钥 (从 supass .data @vaddr 0x2300d 提取, 64 个小端 32 位 limb)】
  e = 65537
  n = 1953686053225375343628222132801162542500336878037128780757002673387134...73329
  Montgomery 参数自洽: n0*n0inv ≡ -1 (mod 2^32), R² = 2^4096 mod n 均成立。
  已排除: 小因子 / Fermat 近素数 / Pollard-rho / ROCA / FactorDB 已有分解。
  固件内只有公钥, 私钥由厂商 NRadio 持有 (客服凭校验码给密码即用私钥签发)。
  => 未获得私钥 d 时, 任何人都无法离线生成可通过的密码; 工具的 gen 模式
     在提供 d (或 n 被分解) 后可立即出密码。

用法:
  python supass_pwd_tool.py info
  python supass_pwd_tool.py hash   --ccode 3Q4q... --mac 44:37:0b:f1:2f:9a
  python supass_pwd_tool.py verify --ccode 3Q4q... --mac 44:37:0b:f1:2f:9a \\
                                   --sig <客服给的512位hex密码>
  python supass_pwd_tool.py gen    --ccode 3Q4q... --mac 44:37:0b:f1:2f:9a \\
                                   --d  <私钥d(十进制或0x十六进制)>
  python supass_pwd_tool.py extract /path/to/supass      # 从二进制提公钥
  python supass_pwd_tool.py selftest                     # 随机密钥回环自测
================================================================
"""
import argparse, hashlib, sys

E = 65537
N = int(
 "19536860532253753436282221328011625425003368780371287807570026733871343065103704723930248200120099306097756295196909898743866220536224458022160212536140974393863419718752210161273295758277312354282350632482515645141845160830437490704347391148158356474374706740685444428968278023219547564634613711047504313625727747145705901173704161701014924053643810821162906508494893733276598356647256491262548868791822860591183138449771506960653738259550362878209251118640279674159861566253497423679750039277963905461609003076600008046568328706740395844254508874732806858964347823434615653740619262441275850434363165725429686873329")

SHA1_DIGESTINFO = bytes.fromhex("3021300906052b0e03021a05000414")
K = (N.bit_length() + 7) // 8     # 256


def message_digest(ccode: str, mac: str) -> bytes:
    # supass: SHA1_Update(ccode) 紧接 SHA1_Update(mac), 无分隔符
    return hashlib.sha1(ccode.encode() + mac.encode()).digest()


def encode_pkcs1(h: bytes) -> int:
    t = SHA1_DIGESTINFO + h
    ps = b"\xff" * (K - len(t) - 3)
    em = b"\x00\x01" + ps + b"\x00" + t
    assert len(em) == K
    return int.from_bytes(em, "big")


def rsa_sign_int(m: int, d: int, n: int = N) -> bytes:
    return pow(m, d, n).to_bytes(K, "big")


def rsa_verify(sig: bytes, h: bytes, n: int = N, e: int = E) -> bool:
    if len(sig) != K:
        return False
    s = int.from_bytes(sig, "big")
    if s >= n:
        return False
    return pow(s, e, n) == encode_pkcs1(h)


def parse_int(x: str) -> int:
    return int(x, 0) if x.lower().startswith(("0x", "0b", "0o")) else int(x)


def cmd_info(a):
    print("supass 公钥 (RSA-2048, PKCS#1 v1.5 + SHA1)")
    print(f"  e = {E}")
    print(f"  n = {N}")
    print(f"  n bits = {N.bit_length()}")
    print("固件版本 2.1.11 / 2.2.15 / mtd27 中 supass 二进制 MD5 完全一致, 公钥相同。")
    print("生成密码必须持有私钥 d; 固件内不存在私钥。")


def cmd_hash(a):
    h = message_digest(a.ccode, a.mac)
    print(f"ccode        = {a.ccode}")
    print(f"mac          = {a.mac}  (注意: 设备用 oem.board.id 原始字符串, 通常小写)")
    print(f"SHA1(c‖m) H  = {h.hex()}")
    print("此 H 即被 RSA 签名的摘要; 密码 = RSA 私钥对 PKCS#1(H) 的签名 (512 hex)。")


def cmd_verify(a):
    sig = bytes.fromhex(a.sig.strip())
    h = message_digest(a.ccode, a.mac)
    ok = rsa_verify(sig, h)
    print("verify:", "PASS  (supass 会返回 0, 密码正确)" if ok
                    else "FAIL  (supass 返回非 0, 密码不正确)")
    print(f"  H = {h.hex()}")
    if len(sig) != K:
        print(f"  长度 {len(sig)} 字节 != 256 (应为 512 个 hex 字符)")
    sys.exit(0 if ok else 1)


def cmd_gen(a):
    if not a.d:
        print("无法生成: 缺少私钥 d。")
        print("RSA-2048 模数 n 不可分解, 固件中只有公钥;")
        print("请向厂商客服提供校验码获取密码 (得到后可用 verify 子命令本地核验),")
        print("或在拿到 d / p,q 后用: gen --d <d>")
        sys.exit(2)
    d = parse_int(a.d)
    h = message_digest(a.ccode, a.mac)
    sig = rsa_sign_int(encode_pkcs1(h), d)
    print("== 在安全页“密码”框粘贴下面 512 位十六进制 ==")
    print(sig.hex())
    # 立即回算自证
    assert rsa_verify(sig, h), "internal error"
    print("\n(已用内嵌公钥本地复核通过)")


def cmd_extract(a):
    b = open(a.supass, "rb").read()
    # 数据段 vaddr 0x22eb8 -> file 0x2eb8; 模数 256B @ vaddr 0x2300d (file 0x300d)
    raw = b[0x300d:0x300d + 256]
    n = int.from_bytes(raw, "little")
    n0inv = int.from_bytes(b[0x3009:0x300d], "little")
    r2 = int.from_bytes(b[0x310d:0x310d + 256], "little")
    assert (int.from_bytes(raw[:4], "little") * n0inv) & 0xffffffff == 0xffffffff
    assert r2 == pow(2, 4096, n)
    print(f"e = {E}")
    print(f"n = {n}")
    print("Montgomery 自洽校验通过 (n0inv, R^2)。")
    if n != N:
        print("注意: 提取到的 n 与本工具内嵌值不同, 请更新 N。")


def cmd_selftest(a):
    # 生成一次性 2048 位 RSA 密钥, 验证 sign/verify 回环与 supass 编码一致
    import random
    def is_prime(x):
        if x < 2: return False
        for p in (3,5,7,11,13,17,19,23,29,31,37):
            if x % p == 0: return x == p
        d, r = x - 1, 0
        while d % 2 == 0: d //= 2; r += 1
        for _ in range(12):
            y = pow(random.randrange(2, x - 1), d, x)
            if y in (1, x - 1): continue
            for _ in range(r - 1):
                y = y * y % x
                if y == x - 1: break
            else: return False
        return True
    def gen_prime():
        while True:
            x = random.getrandbits(1024) | (1 << 1023) | 1
            if is_prime(x): return x
    p, q = gen_prime(), gen_prime()
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(E, -1, phi)
    h = hashlib.sha1(b"selftest-ccode" + b"00:11:22:33:44:55").digest()
    m = encode_pkcs1(h)
    sig = pow(m, d, n).to_bytes(K, "big")
    assert pow(int.from_bytes(sig, "big"), E, n) == m
    print("selftest PASS: PKCS#1 v1.5 SHA1 签名/验证回环正确, 编码与 supass 一致。")


def main():
    ap = argparse.ArgumentParser(description="NRadio supass 安全页密码计算/校验工具")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("info")
    sp = sub.add_parser("hash");   sp.add_argument("--ccode", required=True); sp.add_argument("--mac", required=True)
    sp = sub.add_parser("verify"); sp.add_argument("--ccode", required=True); sp.add_argument("--mac", required=True); sp.add_argument("--sig", required=True)
    sp = sub.add_parser("gen");    sp.add_argument("--ccode", required=True); sp.add_argument("--mac", required=True); sp.add_argument("--d", default="")
    sp = sub.add_parser("extract"); sp.add_argument("supass")
    sub.add_parser("selftest")
    a = ap.parse_args()
    {"info": cmd_info, "hash": cmd_hash, "verify": cmd_verify,
     "gen": cmd_gen, "extract": cmd_extract, "selftest": cmd_selftest}[a.cmd](a)


if __name__ == "__main__":
    main()
