"""
m250_sandbox.py -- 隐私计算沙箱 (图2 模块 250)

模块说明:
  251 MPC : 加法秘密分享(精确求和) + Diffie-Hellman 隐私集合求交(DH-PSI)
  252 FL  : 联邦学习(FedAvg), 逐轮记录梯度范数与余弦相似度供贡献度结算
  253 TEE : 可信执行环境(远程证明 + 飞地内聚合)
  DP  引擎: VSS 元数据驱动的维度级敏感度标定与差异化预算分配

维度级差分隐私(式(2)~(6)):
  ① 逐维归一化   x~_i = (x_i - min_i)/(max_i - min_i)   -> 归一化敏感度 Δf~_i = 1/|D|
  ② 差异化分配   w_i = 2^(-s_i)/Σ_j 2^(-s_j),  ε_i = w_i·ε_q
  ③ 加噪反归一化 z~_i = f~_i(D) + Lap(0, Δf~_i/ε_i),  z_i = z~_i·(max_i-min_i)+min_i
"""
from __future__ import annotations

import hashlib
import math
import random
import secrets
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from . import vss
from .crypto_lite import MODP_P, MODP_Q, hash_to_subgroup, sha256_hex
from .vehicle_agent import laplace_inv_cdf


# ===========================================================================
# 一、差分隐私统计查询引擎 (维度级标定)
# ===========================================================================
@dataclass
class DimResult:
    path: str
    name: str
    unit: str
    sensitivity: int
    weight: float          # w_i
    eps_i: float           # ε_i
    b_norm: float          # 归一化噪声尺度 Δf~_i/ε_i
    true_value: float
    noisy_value: float
    noise_std_physical: float
    rel_error: float
    baseline_value: float = 0.0      # 现有技术(统一全局敏感度)对照
    baseline_std: float = 0.0
    baseline_rel_error: float = 0.0
    # 量程归一化误差 = 噪声标准差 / 该维物理量程跨度。
    # 这是跨异构维度唯一公平的效用口径: 消除量纲后各维误差方可横向相加比较。
    norm_std: float = 0.0
    baseline_norm_std: float = 0.0


@dataclass
class DPQueryResult:
    eps_q: float
    n_records: int
    dims: List[DimResult]
    seeds: List[float] = field(default_factory=list)   # 噪声采样随机数 u_i (供 ZK 承诺)
    true_vec: List[float] = field(default_factory=list)
    noisy_vec: List[float] = field(default_factory=list)

    def utility(self) -> Dict[str, float]:
        """
        跨维度聚合效用指标(理论值, 不含单次采样波动):
          mean_norm_std   本方案的平均量程归一化噪声标准差
          base_norm_std   现有技术(统一全局敏感度)的同口径值
          gain            效用增益倍数 = base / ours (>1 表示本方案更优)
          worst_ours/base 各自最差维度的归一化误差(体现最坏情况保障)
        """
        ours = [d.norm_std for d in self.dims]
        base = [d.baseline_norm_std for d in self.dims]
        mo = sum(ours) / len(ours)
        mb = sum(base) / len(base)
        return {"mean_norm_std": mo, "base_norm_std": mb,
                "gain": mb / mo if mo > 0 else float("inf"),
                "worst_ours": max(ours), "worst_base": max(base),
                "worst_gain": max(base) / max(ours) if max(ours) > 0 else float("inf")}


class DPEngine:
    """差分隐私统计查询执行引擎。"""

    def __init__(self, rng: Optional[random.Random] = None):
        self.rng = rng or random.Random(20260701)

    def mean_query(self, columns: Dict[str, List[float]], eps_q: float,
                   with_baseline: bool = True) -> DPQueryResult:
        """
        多维均值查询。columns: VSS 路径 -> 该维数值列表。
        """
        paths = list(columns.keys())
        n = min(len(v) for v in columns.values())
        if n == 0:
            raise ValueError("数据集为空")
        weights = vss.sensitivity_weights(paths)

        # --- 现有技术对照: 在原始量纲上直接叠加各维敏感度 ---
        # Δf = Σ_i (max_i - min_i)/|D|, 全部维度统一注入 b = Δf/ε_q
        raw_sens = sum(vss.get(p).span for p in paths) / n
        baseline_b = raw_sens / eps_q if with_baseline else 0.0

        dims: List[DimResult] = []
        seeds: List[float] = []
        for p in paths:
            node = vss.get(p)
            col = columns[p][:n]
            true_val = sum(col) / n

            # ① 逐维归一化 -> 归一化敏感度 Δf~_i = 1/|D|
            true_norm = node.normalize(true_val)
            delta_f_norm = 1.0 / n
            # ② 差异化预算分配
            w_i = weights[p]
            eps_i = w_i * eps_q
            # ③ 逆CDF法采样拉普拉斯噪声并加噪
            b_norm = delta_f_norm / eps_i
            u = self.rng.random()
            seeds.append(u)
            noisy_norm = true_norm + laplace_inv_cdf(u, b_norm)
            noisy_val = node.denormalize(noisy_norm)

            noise_std_phys = math.sqrt(2.0) * b_norm * node.span   # Lap(b) 标准差 = √2·b
            rel = abs(noisy_val - true_val) / (abs(true_val) + 1e-12)

            d = DimResult(p, node.name, node.unit, node.sensitivity, w_i, eps_i,
                          b_norm, true_val, noisy_val, noise_std_phys, rel)
            # 本方案的归一化误差只取决于本维分得的预算 ε_i, 与其他维量程完全解耦
            d.norm_std = math.sqrt(2.0) * b_norm
            if with_baseline:
                bn = true_val + laplace_inv_cdf(self.rng.random(), baseline_b)
                d.baseline_value = bn
                d.baseline_std = math.sqrt(2.0) * baseline_b
                d.baseline_rel_error = abs(bn - true_val) / (abs(true_val) + 1e-12)
                # 现有技术的归一化误差被全体维度的量程之和污染 -> 小量程维度受害最深
                d.baseline_norm_std = d.baseline_std / node.span if node.span else 0.0
            dims.append(d)

        return DPQueryResult(eps_q, n, dims, seeds,
                             [d.true_value for d in dims],
                             [d.noisy_value for d in dims])


# ===========================================================================
# 二、联邦学习 (FL) —— 逻辑回归 + FedAvg
# ===========================================================================
def _dot(a: Sequence[float], b: Sequence[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


def _norm(a: Sequence[float]) -> float:
    return math.sqrt(sum(x * x for x in a))


def cosine_similarity(a: Sequence[float], b: Sequence[float]) -> float:
    na, nb = _norm(a), _norm(b)
    if na == 0 or nb == 0:
        return 0.0
    return _dot(a, b) / (na * nb)


@dataclass
class ClientData:
    oem: str
    X: List[List[float]]
    y: List[int]


@dataclass
class FLRound:
    t: int
    grad_norms: Dict[str, float]
    cosines: Dict[str, float]
    global_loss: float


class FederatedLearning:
    """
    联邦学习(FedAvg)。模型为逻辑回归, 损失为对数似然。
    梯度: ∇L = (1/m)·Σ (σ(w·x) - y)·x
    """

    def __init__(self, dim: int, lr: float = 0.5, seed: int = 7):
        self.dim = dim
        self.lr = lr
        self.w = [0.0] * dim
        self.rng = random.Random(seed)
        self.rounds: List[FLRound] = []

    @staticmethod
    def _sigmoid(z: float) -> float:
        if z >= 0:
            return 1.0 / (1.0 + math.exp(-z))
        e = math.exp(z)
        return e / (1.0 + e)

    def _grad(self, w: List[float], X: List[List[float]], y: List[int]) -> List[float]:
        g = [0.0] * self.dim
        m = len(X)
        for xi, yi in zip(X, y):
            err = self._sigmoid(_dot(w, xi)) - yi
            for j in range(self.dim):
                g[j] += err * xi[j]
        return [v / m for v in g]

    def _loss(self, w: List[float], X: List[List[float]], y: List[int]) -> float:
        s = 0.0
        for xi, yi in zip(X, y):
            z = _dot(w, xi)
            s += math.log(1 + math.exp(-abs(z))) + max(z, 0) - z * yi
        return s / max(len(X), 1)

    def train(self, clients: List[ClientData], T: int = 100,
              poison_plan: Optional[Dict[str, List[int]]] = None,
              progress=None) -> List[FLRound]:
        """
        poison_plan: {oem: [轮次列表]} —— 在指定轮次注入异常梯度,
        用于验证实施例六的异常梯度检测(范数放大 / 方向反转)。
        """
        poison_plan = poison_plan or {}
        for t in range(1, T + 1):
            grads: Dict[str, List[float]] = {}
            for c in clients:
                g = self._grad(self.w, c.X, c.y)
                rounds_for_c = poison_plan.get(c.oem, [])
                if t in rounds_for_c:
                    idx = rounds_for_c.index(t)
                    if idx % 2 == 0:
                        g = [v * 9.0 for v in g]            # 范数放大型投毒(触发范数判据)
                    else:
                        g = [-v * 0.5 for v in g]           # 方向反转型投毒(触发夹角判据)
                grads[c.oem] = g
            # 安全聚合: 各方梯度按样本量加权平均(此处等权)
            g_glob = [sum(grads[c.oem][j] for c in clients) / len(clients)
                      for j in range(self.dim)]
            rec = FLRound(
                t=t,
                grad_norms={k: _norm(v) for k, v in grads.items()},
                cosines={k: cosine_similarity(v, g_glob) for k, v in grads.items()},
                global_loss=sum(self._loss(self.w, c.X, c.y) for c in clients) / len(clients),
            )
            self.rounds.append(rec)
            self.w = [self.w[j] - self.lr * g_glob[j] for j in range(self.dim)]
            if progress and t % 10 == 0:
                progress(t, T, rec.global_loss)
        return self.rounds

    def accuracy(self, clients: List[ClientData]) -> float:
        ok = tot = 0
        for c in clients:
            for xi, yi in zip(c.X, c.y):
                ok += int((self._sigmoid(_dot(self.w, xi)) >= 0.5) == bool(yi))
                tot += 1
        return ok / max(tot, 1)


def make_client_data(oem: str, n: int, diversity: float, seed: int,
                     dim: int = 8) -> ClientData:
    """
    构造驾驶风险评分训练数据。diversity 控制特征分布的多样性,
    直接决定实施例六第一贡献因子(归一化信息熵 H_i)的高低。
    标签 y = 1 表示高风险(由真实线性模型加噪生成)。
    """
    rng = random.Random(seed)
    true_w = [0.9, -0.6, 0.5, 0.7, -0.4, 0.3, 0.2, -0.5][:dim]
    X, y = [], []
    for _ in range(n):
        xi = [rng.gauss(0.0, diversity) for _ in range(dim)]
        xi[0] = abs(xi[0])                                # 车速相关特征取正
        z = _dot(true_w, xi) + rng.gauss(0, 0.3)
        X.append(xi)
        y.append(1 if z > 0 else 0)
    return ClientData(oem, X, y)


# ===========================================================================
# 三、MPC —— 加法秘密分享求和 + DH 隐私集合求交
# ===========================================================================
class SecretSharing:
    """
    加法秘密分享(模大素数)。各方将私有值拆为 n 份随机分片,
    求和后重构得精确结果, 单方分片不泄露任何信息。
    """
    MOD = 2 ** 127 - 1
    SCALE = 10 ** 6

    @classmethod
    def share(cls, value: float, n: int, rng: random.Random) -> List[int]:
        v = int(round(value * cls.SCALE)) % cls.MOD
        parts = [rng.randrange(cls.MOD) for _ in range(n - 1)]
        parts.append((v - sum(parts)) % cls.MOD)
        return parts

    @classmethod
    def reconstruct(cls, shares: List[int]) -> float:
        s = sum(shares) % cls.MOD
        if s > cls.MOD // 2:
            s -= cls.MOD
        return s / cls.SCALE

    @classmethod
    def secure_sum(cls, values: List[float], seed: int = 0) -> Tuple[float, float]:
        """返回 (MPC 精确求和, 明文求和) 以验证零误差。"""
        rng = random.Random(seed)
        n = len(values)
        tables = [cls.share(v, n, rng) for v in values]
        # 各方持有的分片列之和
        col_sums = [sum(tables[i][j] for i in range(n)) % cls.MOD for j in range(n)]
        return cls.reconstruct(col_sums), sum(values)


class DHPSI:
    """
    Diffie-Hellman 隐私集合求交 (DH-PSI)。
    双方各持私钥 a、b, 交换 H(x)^a 与 H(y)^b, 再各自求幂得 H(·)^{ab} 比对,
    仅泄露交集本身, 不泄露非交集元素。
    """

    def __init__(self, seed: Optional[int] = None):
        # 256 位短指数: 在保持安全性的同时把模幂开销降低约 8 倍
        self.key = secrets.randbits(256) | 1

    def blind(self, items: List[str]) -> List[int]:
        return [pow(hash_to_subgroup(s.encode()), self.key, MODP_P) for s in items]

    def rerandomize(self, blinded: List[int]) -> List[int]:
        return [pow(b, self.key, MODP_P) for b in blinded]

    @staticmethod
    def intersect(a_double: List[int], b_double: List[int],
                  a_items: List[str]) -> List[str]:
        bset = set(b_double)
        return [it for it, v in zip(a_items, a_double) if v in bset]

    @classmethod
    def run(cls, set_a: List[str], set_b: List[str]) -> Tuple[List[str], int]:
        """完整两方协议, 返回 (交集, 群指数运算次数)。"""
        pa, pb = cls(), cls()
        a1 = pa.blind(set_a)              # A: H(x)^a
        b1 = pb.blind(set_b)              # B: H(y)^b
        a2 = pb.rerandomize(a1)           # B 对 A 的盲化值再求幂 -> H(x)^{ab}
        b2 = pa.rerandomize(b1)           # A 对 B 的盲化值再求幂 -> H(y)^{ab}
        inter = cls.intersect(a2, b2, set_a)
        return inter, 2 * (len(set_a) + len(set_b))


# ===========================================================================
# 四、TEE —— 远程证明 + 飞地内聚合
# ===========================================================================
@dataclass
class EnclaveQuote:
    mrenclave: str        # 代码度量值
    nonce: str
    signature: str

    def verify(self, expected_mrenclave: str) -> bool:
        return self.mrenclave == expected_mrenclave and self.signature == sha256_hex(
            (self.mrenclave + self.nonce).encode())


class TEEEnclave:
    """
    可信执行环境模拟。remote_attest() 提供代码度量值证明,
    各参与方验证通过后才把加密梯度送入飞地; 飞地对外仅输出聚合结果与中间量摘要。
    注意: 本实现为软件模拟, 真实部署需 Intel SGX / ARM TrustZone 硬件支持。
    """
    EXPECTED_MRENCLAVE = sha256_hex(b"ALC-aggregator-v1.0.3")

    def __init__(self):
        self.mrenclave = self.EXPECTED_MRENCLAVE
        self._sealed: Dict[str, List[float]] = {}

    def remote_attest(self, nonce: str) -> EnclaveQuote:
        return EnclaveQuote(self.mrenclave, nonce,
                            sha256_hex((self.mrenclave + nonce).encode()))

    def submit(self, party: str, vec: List[float]):
        """密文提交(此处以密封内存模拟), 个体梯度对宿主不可见。"""
        self._sealed[party] = list(vec)

    def aggregate(self) -> Tuple[List[float], Dict[str, dict]]:
        """飞地内聚合并计算贡献度中间量, 对外仅输出全局向量与摘要。"""
        parties = list(self._sealed)
        d = len(next(iter(self._sealed.values())))
        g = [sum(self._sealed[p][j] for p in parties) / len(parties) for j in range(d)]
        meta = {p: {"norm": _norm(self._sealed[p]),
                    "cosine": cosine_similarity(self._sealed[p], g)} for p in parties}
        self._sealed.clear()      # 计算完毕清空密封内存
        return g, meta
