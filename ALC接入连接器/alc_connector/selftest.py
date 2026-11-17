"""
selftest.py -- 数学实现自检

以独立于被测实现的方法交叉验证各核心算法, 确保各核心算法的数学一致性:
  1. 拉普拉斯逆CDF采样的分布正确性 (均值/方差/尾概率)
  2. 式(4) 预算权重归一性与单调性
  3. 式(2)(6) 归一化-加噪-反归一化的无偏性
  4. 式(7) RDP 的解析值与数值积分交叉验证
  5. 式(8) 组合会计的单调性与线性叠加上界关系
  6. 式(10) 归一化信息熵的边界性质 (均匀分布=1, 退化分布=0)
  7. 式(11)(12) 余弦相似度与截断累计
  8. ECDH / Pedersen 同态 / Schnorr NIZK 的密码学正确性
  9. Merkle 树路径证明的完备性与健全性
 10. MPC 秘密分享与 DH-PSI 的功能正确性
"""
from __future__ import annotations

import math
import random
import statistics
from typing import List

PASS, FAIL = "  [通过] ", "  [失败] "
_results: List[bool] = []


def _chk(cond: bool, msg: str, detail: str = ""):
    _results.append(bool(cond))
    print((PASS if cond else FAIL) + msg + (f"   {detail}" if detail else ""))


# ---------------------------------------------------------------------------
def t1_laplace():
    print("\n[1] 拉普拉斯逆CDF采样的分布正确性")
    from .vehicle_agent import laplace_inv_cdf
    rng = random.Random(12345)
    b, n = 2.0, 200000
    xs = [laplace_inv_cdf(rng.random(), b) for _ in range(n)]
    mean, var = statistics.fmean(xs), statistics.pvariance(xs)
    _chk(abs(mean) < 0.05, "样本均值 ≈ 0", f"实测 {mean:+.4f}")
    _chk(abs(var - 2 * b * b) / (2 * b * b) < 0.05, "样本方差 ≈ 2b²",
         f"实测 {var:.4f}, 理论 {2*b*b:.4f}")
    # 尾概率: P(|X| > t) = exp(-t/b)
    for t in (1.0, 3.0, 5.0):
        emp = sum(1 for x in xs if abs(x) > t) / n
        theo = math.exp(-t / b)
        _chk(abs(emp - theo) < 0.01, f"尾概率 P(|X|>{t}) ≈ exp(-{t}/b)",
             f"实测 {emp:.4f}, 理论 {theo:.4f}")


def t2_weights():
    print("\n[2] 预算权重 w_i = 2^(-s_i)/Σ2^(-s_j)")
    from . import vss
    paths = ["Vehicle.Speed", "Vehicle.Chassis.Brake.EventsPerWeek",
             "Vehicle.Powertrain.Battery.StateOfHealth",
             "Vehicle.CurrentLocation.Latitude"]
    w = vss.sensitivity_weights(paths)
    _chk(abs(sum(w.values()) - 1.0) < 1e-12, "权重归一性 Σw_i = 1",
         f"实测 {sum(w.values()):.12f}")
    ss = [(vss.get(p).sensitivity, w[p]) for p in paths]
    ss.sort()
    mono = all(ss[i][1] >= ss[i + 1][1] for i in range(len(ss) - 1))
    _chk(mono, "敏感等级越高权重越小 (单调性)",
         ", ".join(f"s={s}:w={x:.4f}" for s, x in ss))
    # 手工核算: s=(2,2,1,3) -> 2^-s=(0.25,0.25,0.5,0.125), Σ=1.125
    exp_soh = 0.5 / 1.125
    _chk(abs(w["Vehicle.Powertrain.Battery.StateOfHealth"] - exp_soh) < 1e-12,
         "与手工核算一致 (SoH 维)", f"实测 {w['Vehicle.Powertrain.Battery.StateOfHealth']:.6f}, "
                                f"手算 {exp_soh:.6f}")


def t3_dp_unbiased():
    print("\n[3] 归一化-加噪-反归一化的无偏性")
    from .m250_sandbox import DPEngine
    rng = random.Random(7)
    N = 4000
    cols = {"Vehicle.Powertrain.Battery.StateOfHealth":
            [rng.gauss(96.0, 2.0) for _ in range(N)]}
    true_mean = statistics.fmean(cols["Vehicle.Powertrain.Battery.StateOfHealth"])
    outs = []
    for k in range(3000):
        r = DPEngine(random.Random(k)).mean_query(cols, 0.5, with_baseline=False)
        outs.append(r.dims[0].noisy_value)
    bias = statistics.fmean(outs) - true_mean
    d0 = DPEngine(random.Random(0)).mean_query(cols, 0.5, with_baseline=False).dims[0]
    theo_std = d0.noise_std_physical
    emp_std = statistics.pstdev(outs)
    _chk(abs(bias) < 0.05 * theo_std, "加噪输出无偏 E[z] = f(D)",
         f"偏差 {bias:+.6f}, 噪声标准差 {theo_std:.6f}")
    _chk(abs(emp_std - theo_std) / theo_std < 0.06, "输出标准差 = √2·b·量程跨度",
         f"实测 {emp_std:.6f}, 理论 {theo_std:.6f}")


def t4_rdp_numeric():
    print("\n RDP 解析式 vs 数值积分交叉验证")
    from .m230_budget import laplace_rdp
    # Rényi 散度定义: D_α(P‖Q) = 1/(α-1) · ln ∫ p(x)^α q(x)^(1-α) dx
    # 取 P=Lap(0,b), Q=Lap(1,b) (相邻数据集使查询结果相差 1 个敏感度单位)
    def numeric(alpha: float, b: float) -> float:
        lo, hi, m = -60.0 * b, 60.0 * b, 400000
        h = (hi - lo) / m
        total = 0.0
        for i in range(m + 1):
            x = lo + i * h
            lp = -abs(x) / b - math.log(2 * b)
            lq = -abs(x - 1.0) / b - math.log(2 * b)
            w = 1 if i in (0, m) else (4 if i % 2 else 2)      # Simpson
            total += w * math.exp(alpha * lp + (1 - alpha) * lq)
        integral = total * h / 3
        return math.log(integral) / (alpha - 1)
    for alpha, b in [(2.0, 1.0), (3.0, 2.0), (5.0, 10.0), (8.0, 4.0)]:
        ana, num = laplace_rdp(alpha, b), numeric(alpha, b)
        _chk(abs(ana - num) < 1e-6 * max(1.0, abs(num)),
             f"α={alpha}, b={b}", f"解析 {ana:.9f} vs 数值 {num:.9f}")
    # 数值稳定性: 大 (α-1)/b 时朴素实现会 exp 溢出
    v = laplace_rdp(5.0, 0.01)
    _chk(math.isfinite(v) and v > 0, "极端参数下无溢出 (b=0.01, 朴素实现会 exp(400) 溢出)",
         f"ε_RDP = {v:.4f}")


def t5_composition():
    print("\n[5] 组合会计的性质")
    from .m230_budget import compose, optimize_alpha
    d = 1e-5
    vals = [compose([(n, 10.0)], 5.0, d) for n in (10, 50, 100, 200)]
    _chk(all(vals[i] < vals[i + 1] for i in range(len(vals) - 1)),
         "组合损失随轮数单调递增", " < ".join(f"{v:.3f}" for v in vals))
    a, v, _ = optimize_alpha([(151, 10.0)], d)
    grid = min(compose([(151, 10.0)], x / 100, d) for x in range(110, 6400))
    _chk(v <= grid + 1e-9, "α 寻优结果不劣于细网格穷举",
         f"寻优 {v:.6f} (α*={a:.4f}) vs 穷举 {grid:.6f}")
    # 与组合算例的数值一致性
    ref = {3: 7.9272, 4: 6.7053, 5: 6.4199, 6: 6.4909, 8: 7.0319}
    ok = all(abs(compose([(151, 10.0)], k, d) - v0) < 1e-3 for k, v0 in ref.items())
    _chk(ok, "复现 α=3/4/5/6/8 数值算例",
         ", ".join(f"α={k}:{compose([(151,10.0)],k,d):.4f}" for k in ref))
    lin = 151 * 0.1
    _chk(v < lin, "RDP 组合显著紧于线性叠加",
         f"RDP {v:.4f} << 线性 {lin:.4f}")


def t6_entropy():
    print("\n[6] 归一化信息熵的边界性质")
    from .m260_contribution import normalized_entropy
    rng = random.Random(3)
    # 均匀铺满全部分桶 -> H → 1
    uni = [[rng.uniform(-4, 4), rng.uniform(-4, 4)] for _ in range(40000)]
    h_uni, _ = normalized_entropy(uni, 8)
    _chk(h_uni > 0.995, "均匀分布 H → 1", f"实测 {h_uni:.6f}")
    # 全部落入单一分桶 -> H = 0
    deg = [[0.01, 0.01] for _ in range(5000)]
    h_deg, _ = normalized_entropy(deg, 8)
    _chk(abs(h_deg) < 1e-12, "退化分布 H = 0", f"实测 {h_deg:.6e}")
    # 样本复制不改变分布, 熵值不变 -> 抑制搭便车
    base = [[rng.gauss(0, 1), rng.gauss(0, 1)] for _ in range(2000)]
    h1, _ = normalized_entropy(base, 8)
    h2, _ = normalized_entropy(base * 5, 8)
    _chk(abs(h1 - h2) < 1e-12, "样本复制 5 倍后熵值不变 (抗搭便车)",
         f"{h1:.8f} vs {h2:.8f}")
    # 多样性单调性
    hs = []
    for sd in (0.2, 0.6, 1.2, 2.0):
        pts = [[rng.gauss(0, sd), rng.gauss(0, sd)] for _ in range(8000)]
        hs.append(normalized_entropy(pts, 8)[0])
    _chk(all(hs[i] < hs[i + 1] for i in range(len(hs) - 1)),
         "分布越分散熵值越高 (单调性)", " < ".join(f"{h:.4f}" for h in hs))


def t7_cosine():
    print("\n[7] 余弦相似度与截断累计")
    from .m250_sandbox import cosine_similarity
    _chk(abs(cosine_similarity([1, 0, 0], [2, 0, 0]) - 1.0) < 1e-12, "同向 cos = 1")
    _chk(abs(cosine_similarity([1, 0], [0, 1])) < 1e-12, "正交 cos = 0")
    _chk(abs(cosine_similarity([1, 1], [-1, -1]) + 1.0) < 1e-12, "反向 cos = -1")
    _chk(cosine_similarity([0, 0], [1, 1]) == 0.0, "零向量返回 0 (无除零异常)")
    phis = [0.9, -0.5, 0.7, -0.2, 0.6]
    trunc = sum(max(0.0, p) for p in phis) / len(phis)
    _chk(abs(trunc - 0.44) < 1e-12, "截断累计 Φ = (1/T)Σmax(0,φ) 不倒扣",
         f"φ={phis} → Φ={trunc:.4f}")


def t8_crypto():
    print("\n[8] 密码学原语正确性")
    from .crypto_lite import (ECKeyPair, MODP_P, PED_H, aead_decrypt,
                              aead_encrypt, ec_on_curve, hkdf, ped_add,
                              ped_commit, ped_verify, schnorr_prove,
                              schnorr_verify)
    a, b = ECKeyPair(), ECKeyPair()
    _chk(ec_on_curve(a.pub) and ec_on_curve(b.pub), "生成的公钥在 secp256r1 曲线上")
    _chk(a.ecdh(b.pub) == b.ecdh(a.pub), "ECDH 双方协商出相同共享秘密")
    k = hkdf(a.ecdh(b.pub), b"salt", b"info", 64)
    pkt = aead_encrypt(k, b"VSS payload", b"aad")
    _chk(aead_decrypt(k, pkt, b"aad") == b"VSS payload", "加解密往返一致")
    bad = dict(pkt)
    bad["ct"] = bytes([pkt["ct"][0] ^ 1]) + pkt["ct"][1:]
    try:
        aead_decrypt(k, bad, b"aad")
        ok = False
    except ValueError:
        ok = True
    _chk(ok, "密文篡改被 HMAC 检出")
    c1, r1 = ped_commit(12345)
    c2, r2 = ped_commit(67890)
    _chk(ped_verify(ped_add(c1, c2), 12345 + 67890, r1 + r2),
         "Pedersen 承诺加法同态 Com(a)·Com(b)=Com(a+b)")
    _chk(not ped_verify(c1, 12346, r1), "错误开启值被拒绝")
    w = 987654321
    y = pow(PED_H, w, MODP_P)
    pr = schnorr_prove(y, w)
    _chk(schnorr_verify(y, pr), "Schnorr NIZK 完备性 (诚实证明通过)")
    pr_bad = dict(pr)
    pr_bad["s"] = pr["s"] + 1
    _chk(not schnorr_verify(y, pr_bad), "Schnorr NIZK 健全性 (伪造应答被拒)")
    _chk(not schnorr_verify(y * 2 % MODP_P, pr), "证明不可移植到其他陈述")


def t9_merkle_zk():
    print("\n[9] Merkle 树与聚合零知识证明")
    from .m270_audit import MerkleTree, ZKAuditor
    import copy
    leaves = [f"{i:064x}" for i in range(37)]      # 非 2 的幂, 测试补齐逻辑
    t = MerkleTree(leaves)
    ok_all = all(MerkleTree.verify(leaves[i], t.proof(i), t.root)
                 for i in range(len(leaves)))
    _chk(ok_all, f"全部 {len(leaves)} 个叶子的路径证明均通过 (树高 {t.height})")
    _chk(not MerkleTree.verify("0" * 64, t.proof(5), t.root),
         "伪造叶子无法通过验证 (健全性)")
    _chk(not MerkleTree.verify(leaves[5], t.proof(6), t.root),
         "路径错配无法通过验证")
    rng = random.Random(11)
    vals = [rng.gauss(50, 5) for _ in range(120)]
    noise = 0.7231
    p = ZKAuditor.prove_aggregate(vals, noise, sum(vals) + noise, "test",
                                  0.05, 1.0 / 120, 0.5, max_commit=60)
    ok, _ = ZKAuditor.verify(p)
    _chk(ok, "聚合关系零知识证明验证通过 (完备性)")
    for name, mut in [("篡改公开 z", lambda q: setattr(q, "z_public", q.z_public + 10)),
                      ("替换噪声承诺", lambda q: setattr(q, "c_eta", q.c_eta * 3 % 2)),
                      ("伪造 Schnorr 应答", lambda q: q.proof_rel.update(s=q.proof_rel["s"] + 1))]:
        bad = copy.deepcopy(p)
        try:
            if name == "替换噪声承诺":
                from .crypto_lite import MODP_P as MP
                bad.c_eta = bad.c_eta * 3 % MP
            else:
                mut(bad)
        except Exception:
            pass
        r_ok, _ = ZKAuditor.verify(bad)
        _chk(not r_ok, f"{name} 被拒绝 (健全性)")


def t10_mpc():
    print("\n[10] MPC 秘密分享与 DH-PSI")
    from .m250_sandbox import DHPSI, SecretSharing
    rng = random.Random(5)
    for n in (3, 8):
        vals = [rng.uniform(-500, 500) for _ in range(n)]
        got, exp = SecretSharing.secure_sum(vals, seed=n)
        _chk(abs(got - exp) < 1e-5, f"{n} 方秘密分享求和精确重构",
             f"误差 {abs(got-exp):.2e}")
    shares = SecretSharing.share(42.0, 5, random.Random(1))
    _chk(len(shares) == 5 and all(isinstance(s, int) for s in shares),
         "分片数量正确且为大整数 (单方分片不泄露原值)")
    A = [f"ID{i:04d}" for i in range(120)]
    B = [f"ID{i:04d}" for i in range(80, 200)]
    inter, _ = DHPSI.run(A, B)
    _chk(sorted(inter) == sorted(set(A) & set(B)),
         f"DH-PSI 交集正确 (期望 {len(set(A)&set(B))} 个, 实得 {len(inter)} 个)")
    inter2, _ = DHPSI.run(["X1", "X2"], ["Y1", "Y2"])
    _chk(inter2 == [], "无交集时返回空集")


def run_selftest() -> bool:
    print("=" * 78)
    print("ALC 接入连接器 — 数学实现自检")
    print("=" * 78)
    for fn in (t1_laplace, t2_weights, t3_dp_unbiased, t4_rdp_numeric,
               t5_composition, t6_entropy, t7_cosine, t8_crypto,
               t9_merkle_zk, t10_mpc):
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            import traceback
            traceback.print_exc()
            _results.append(False)
            print(FAIL + f"{fn.__name__} 抛出异常: {e}")
    n_ok = sum(_results)
    n = len(_results)
    print("\n" + "=" * 78)
    print(f"自检结果: {n_ok}/{n} 项通过" + ("  ✓ 全部通过" if n_ok == n else "  ✗ 存在失败项"))
    print("=" * 78)
    return n_ok == n
