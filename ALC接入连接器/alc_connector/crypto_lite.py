"""
crypto_lite.py -- 纯标准库密码学原语

模块说明:
  - 权利要求10 / 实施例一: 车端采用椭圆曲线加密(ECC)对上传数据加密
  - 权利要求8  / 实施例七: 零知识证明与承诺方案

实现内容(全部为真实可验证的密码学构造, 不依赖第三方库):
  1. secp256r1 (NIST P-256) 椭圆曲线点运算与 ECDH 密钥协商
  2. HKDF-SHA256 密钥派生 (RFC 5869)
  3. SHA256-CTR 流加密 + HMAC-SHA256 认证 (encrypt-then-MAC)
  4. Pedersen 承诺 (RFC 3526 MODP-2048 素数阶子群)
  5. Schnorr 离散对数知识证明 (Fiat-Shamir 非交互化)
  6. Diffie-Hellman 隐私集合求交 (DH-PSI) 所需的群指数运算
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Optional, Tuple

# ---------------------------------------------------------------------------
# 1. secp256r1 (NIST P-256) 椭圆曲线
#    曲线方程: y^2 = x^3 + a*x + b  (mod P)
# ---------------------------------------------------------------------------
P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_A = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

Point = Optional[Tuple[int, int]]  # None 表示无穷远点 O


def _inv(a: int, m: int) -> int:
    """模逆元, 使用 Python 内置扩展欧几里得。"""
    return pow(a, -1, m)


def ec_add(p: Point, q: Point) -> Point:
    """椭圆曲线点加法 (仿射坐标)。"""
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and (y1 + y2) % P256_P == 0:
        return None  # P + (-P) = O
    if p == q:
        # 倍点: lambda = (3*x^2 + a) / (2*y)
        lam = (3 * x1 * x1 + P256_A) * _inv(2 * y1, P256_P) % P256_P
    else:
        # 点加: lambda = (y2 - y1) / (x2 - x1)
        lam = (y2 - y1) * _inv((x2 - x1) % P256_P, P256_P) % P256_P
    x3 = (lam * lam - x1 - x2) % P256_P
    y3 = (lam * (x1 - x3) - y1) % P256_P
    return (x3, y3)


def ec_mul(k: int, p: Point) -> Point:
    """标量乘 k*P, double-and-add。"""
    r: Point = None
    addend = p
    k %= P256_N
    while k:
        if k & 1:
            r = ec_add(r, addend)
        addend = ec_add(addend, addend)
        k >>= 1
    return r


def ec_on_curve(p: Point) -> bool:
    """验证点是否在曲线上, 用于抵御无效曲线攻击。"""
    if p is None:
        return True
    x, y = p
    return (y * y - (x * x * x + P256_A * x + P256_B)) % P256_P == 0


class ECKeyPair:
    """secp256r1 密钥对, 提供 ECDH 共享密钥协商。"""

    G: Point = (P256_GX, P256_GY)

    def __init__(self, priv: Optional[int] = None):
        self.priv = priv if priv is not None else secrets.randbelow(P256_N - 1) + 1
        self.pub = ec_mul(self.priv, ECKeyPair.G)

    def ecdh(self, peer_pub: Point) -> bytes:
        """ECDH: 共享点 = priv * peer_pub, 取 x 坐标作为共享秘密。"""
        if not ec_on_curve(peer_pub):
            raise ValueError("对端公钥不在 secp256r1 曲线上, 拒绝协商")
        shared = ec_mul(self.priv, peer_pub)
        if shared is None:
            raise ValueError("ECDH 结果为无穷远点")
        return shared[0].to_bytes(32, "big")

    def pub_hex(self) -> str:
        return f"04{self.pub[0]:064x}{self.pub[1]:064x}"


# ---------------------------------------------------------------------------
# 2. HKDF-SHA256 (RFC 5869)
# ---------------------------------------------------------------------------
def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 64) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, counter = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


# ---------------------------------------------------------------------------
# 3. SHA256-CTR 流加密 + HMAC-SHA256 (encrypt-then-MAC)
# ---------------------------------------------------------------------------
def _keystream(key: bytes, nonce: bytes, n: int) -> bytes:
    out, ctr = b"", 0
    while len(out) < n:
        out += hashlib.sha256(key + nonce + ctr.to_bytes(8, "big")).digest()
        ctr += 1
    return out[:n]


def aead_encrypt(session_key: bytes, plaintext: bytes, aad: bytes = b"") -> dict:
    """返回 {nonce, ct, tag}; 认证标签覆盖 aad||nonce||ct。"""
    enc_key, mac_key = session_key[:32], session_key[32:64]
    nonce = secrets.token_bytes(16)
    ct = bytes(a ^ b for a, b in zip(plaintext, _keystream(enc_key, nonce, len(plaintext))))
    tag = hmac.new(mac_key, aad + nonce + ct, hashlib.sha256).digest()
    return {"nonce": nonce, "ct": ct, "tag": tag}


def aead_decrypt(session_key: bytes, pkt: dict, aad: bytes = b"") -> bytes:
    """先验签后解密; 标签不匹配抛出异常 -> 对应实施例一的完整性校验①。"""
    enc_key, mac_key = session_key[:32], session_key[32:64]
    expect = hmac.new(mac_key, aad + pkt["nonce"] + pkt["ct"], hashlib.sha256).digest()
    if not hmac.compare_digest(expect, pkt["tag"]):
        raise ValueError("认证标签校验失败: 数据在传输中被篡改或密钥不匹配")
    return bytes(a ^ b for a, b in zip(pkt["ct"], _keystream(enc_key, pkt["nonce"], len(pkt["ct"]))))


# ---------------------------------------------------------------------------
# 4. Pedersen 承诺 (RFC 3526 MODP Group 14, 2048-bit 安全素数)
#    p = 2q + 1, 在阶为 q 的子群中工作
#    Com(m, r) = g^m * h^r mod p, 加法同态: Com(m1,r1)*Com(m2,r2)=Com(m1+m2, r1+r2)
# ---------------------------------------------------------------------------
MODP_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
    "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
    "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
    "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
    "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C"
    "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFF"
    "FFFFFFFF", 16)
MODP_Q = (MODP_P - 1) // 2
PED_G = pow(2, 2, MODP_P)  # 平方后落入阶为 q 的子群


def _derive_h() -> int:
    """h = H(domain)^2 mod p, 以 nothing-up-my-sleeve 方式生成, 保证 log_g(h) 未知。"""
    seed = hashlib.sha256(b"ALC-Pedersen-h/v1").digest()
    return pow(int.from_bytes(seed, "big") % MODP_P, 2, MODP_P)


PED_H = _derive_h()


RAND_BITS = 256  # 短指数随机数: 保证计算隐藏性的同时把模幂开销降低约 8 倍


def ped_commit(m: int, r: Optional[int] = None) -> Tuple[int, int]:
    """Pedersen 承诺; 返回 (承诺值 C, 随机数 r)。m 为整数(定点化后的数值)。"""
    if r is None:
        r = secrets.randbits(RAND_BITS)
    c = pow(PED_G, m % MODP_Q, MODP_P) * pow(PED_H, r % MODP_Q, MODP_P) % MODP_P
    return c, r


def ped_add(c1: int, c2: int) -> int:
    """同态加: Com(m1)*Com(m2) = Com(m1+m2)。"""
    return c1 * c2 % MODP_P


def ped_verify(c: int, m: int, r: int) -> bool:
    return c == pow(PED_G, m % MODP_Q, MODP_P) * pow(PED_H, r % MODP_Q, MODP_P) % MODP_P


# ---------------------------------------------------------------------------
# 5. Schnorr 离散对数知识证明 (Fiat-Shamir NIZK)
#    证明: 已知 w 使得 y = h^w mod p, 且不泄露 w
# ---------------------------------------------------------------------------
def schnorr_prove(y: int, w: int, base: int = PED_H, ctx: bytes = b"") -> dict:
    k = secrets.randbits(RAND_BITS + 128)
    t = pow(base, k, MODP_P)
    e = int.from_bytes(
        hashlib.sha256(ctx + b"|" + str((base, y, t)).encode()).digest(), "big")
    s = (k + e * w) % MODP_Q
    return {"t": t, "s": s}


def schnorr_verify(y: int, proof: dict, base: int = PED_H, ctx: bytes = b"") -> bool:
    t, s = proof["t"], proof["s"]
    e = int.from_bytes(
        hashlib.sha256(ctx + b"|" + str((base, y, t)).encode()).digest(), "big")
    # 验证 base^s == t * y^e
    return pow(base, s, MODP_P) == t * pow(y, e, MODP_P) % MODP_P


# ---------------------------------------------------------------------------
# 6. 通用哈希工具
# ---------------------------------------------------------------------------
def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_to_subgroup(data: bytes) -> int:
    """把任意字节串映射到阶为 q 的子群元素, 用于 DH-PSI。"""
    return pow(int.from_bytes(hashlib.sha256(data).digest(), "big") % MODP_P, 2, MODP_P)
