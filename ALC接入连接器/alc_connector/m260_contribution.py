"""
m260_contribution.py -- 双因子贡献度量化与智能合约结算模块 (图2 模块 260)

模块说明:

  第一因子(数据信息量·熵权), 式(10):
      H_i = -(1/ln K) · Σ_{k=1..K} p_{i,k} · ln p_{i,k}          H_i ∈ [0,1]

  第二因子(梯度方向一致性), 式(11)(12):
      φ_i^t = <g_i^t, g_g^t> / (‖g_i^t‖·‖g_g^t‖)
      Φ_i   = (1/T) · Σ_t max(0, φ_i^t)                  截断累计, 负相关轮次记零

  双因子融合与信誉, 式(13):
      C_i = [λ·H_i + (1-λ)·Φ_i] · rep_i ,   Ĉ_i = C_i / Σ_j C_j

  异常梯度检测与信誉衰减, 式(14):
      ‖g_i^t‖ > γ·median_j‖g_j^t‖  或  arccos(φ_i^t) > θ_th  ->  该轮贡献置零
      rep_i^{t+1} = β · rep_i^t              (异常轮次)
      rep_i^{t+1} = min(1, rep_i^t + η)      (正常轮次, 缓慢恢复)
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from statistics import median
from typing import Dict, List, Optional, Sequence, Tuple


# 联合特征空间的共同分桶量程(所有参与方一致), 由数据可信空间统一登记
COMMON_FEATURE_RANGE = (-4.0, 4.0)


# ---------------------------------------------------------------------------
# 归一化信息熵
# ---------------------------------------------------------------------------
def normalized_entropy(samples: Sequence[Sequence[float]], bins_per_dim: int = 8,
                       dims: Tuple[int, int] = (0, 1),
                       ranges: Optional[List[Tuple[float, float]]] = None) -> Tuple[float, List[float]]:
    """
    将指定的二维特征空间按等宽方式划分为 K = bins_per_dim^2 个分桶,
    统计落桶比例 p_{i,k} 并计算归一化信息熵。
    仅上传直方图即可完成, 不泄露原始样本(可在参与方本地或 TEE 内完成)。
    返回 (H_i, 直方图比例向量)。
    """
    d0, d1 = dims
    if ranges is None:
        # 必须使用跨参与方一致的固定分桶量程: 若各方按自身数据自适应取量程,
        # 分布的多样性差异会被归一化抹平, 熵值将趋于相同, 熵权因子随之失效。
        ranges = [COMMON_FEATURE_RANGE, COMMON_FEATURE_RANGE]
    K = bins_per_dim * bins_per_dim
    counts = [0] * K
    for s in samples:
        idx = []
        for v, (lo, hi) in zip((s[d0], s[d1]), ranges):
            span = hi - lo
            b = 0 if span <= 0 else int((v - lo) / span * bins_per_dim)
            idx.append(min(max(b, 0), bins_per_dim - 1))
        counts[idx[0] * bins_per_dim + idx[1]] += 1
    n = sum(counts)
    if n == 0:
        return 0.0, [0.0] * K
    p = [c / n for c in counts]
    h = -sum(pi * math.log(pi) for pi in p if pi > 0) / math.log(K)
    return h, p


# ---------------------------------------------------------------------------
# 参与方状态
# ---------------------------------------------------------------------------
@dataclass
class Participant:
    oem: str
    entropy: float = 0.0                       # H_i
    phi_sum: float = 0.0                       # Σ max(0, φ)
    phi_series: List[float] = field(default_factory=list)
    reputation: float = 1.0                    # rep_i
    rep_series: List[float] = field(default_factory=list)
    anomalies: List[dict] = field(default_factory=list)
    rounds_counted: int = 0

    @property
    def phi(self) -> float:
        return self.phi_sum / max(self.rounds_counted, 1)


@dataclass
class SettlementRow:
    oem: str
    entropy: float
    phi: float
    reputation: float
    contribution: float          # C_i
    normalized: float            # Ĉ_i
    payout: float
    anomaly_rounds: List[int]
    baseline_normalized: float   # 现有技术(仅余弦, 无信誉)对照


class ContributionSettlement:
    """双因子贡献度结算模块。"""

    def __init__(self, lam: float = 0.5, gamma: float = 3.0,
                 theta_th_deg: float = 120.0, beta: float = 0.8,
                 eta: float = 0.002, audit=None):
        self.lam = lam                 # λ 融合系数
        self.gamma = gamma             # γ 范数倍数阈值
        self.theta_th = theta_th_deg   # θ_th 方向角阈值(度)
        self.beta = beta               # β 信誉衰减因子
        self.eta = eta                 # η 信誉恢复步长
        self.parties: Dict[str, Participant] = {}
        self.audit = audit
        self.log: List[str] = []

    def register(self, oem: str, samples: Sequence[Sequence[float]],
                 bins_per_dim: int = 8) -> float:
        """登记参与方并计算其第一贡献因子 H_i。"""
        h, _ = normalized_entropy(samples, bins_per_dim)
        p = self.parties.setdefault(oem, Participant(oem))
        p.entropy = h
        self.log.append(f"{oem}: 归一化信息熵 H = {h:.4f} "
                        f"(K={bins_per_dim**2} 分桶, 仅上传直方图)")
        return h

    # -- 逐轮处理: 异常检测 + 方向一致性累计 + 信誉更新 ----------------------
    def process_round(self, t: int, grad_norms: Dict[str, float],
                      cosines: Dict[str, float]):
        norms = list(grad_norms.values())
        med = median(norms) if norms else 0.0
        for oem, gn in grad_norms.items():
            p = self.parties.setdefault(oem, Participant(oem))
            phi = cosines[oem]
            # 异常判定条件
            norm_bad = med > 0 and gn > self.gamma * med
            ang = math.degrees(math.acos(max(-1.0, min(1.0, phi))))
            angle_bad = ang > self.theta_th
            p.rounds_counted += 1
            p.phi_series.append(phi)
            if norm_bad or angle_bad:
                reason = []
                if norm_bad:
                    reason.append(f"范数 {gn:.4f} > γ·median = {self.gamma}×{med:.4f}")
                if angle_bad:
                    reason.append(f"夹角 {ang:.1f}° > θ_th = {self.theta_th}°")
                p.anomalies.append({"round": t, "reason": "; ".join(reason),
                                    "norm": gn, "median": med, "angle": ang})
                # 该轮贡献置零 + 信誉按 β 衰减
                p.reputation *= self.beta
                if self.audit:
                    self.audit.record("anomaly_gradient", {
                        "round": t, "oem": oem, "reason": "; ".join(reason),
                        "reputation_after": round(p.reputation, 6)})
                self.log.append(f"第{t}轮 {oem} 异常梯度: {'; '.join(reason)} "
                                f"-> 贡献置零, rep={p.reputation:.4f}")
            else:
                p.phi_sum += max(0.0, phi)          # 截断累计
                p.reputation = min(1.0, p.reputation + self.eta)
            p.rep_series.append(p.reputation)

    # -- 融合、归一化与合约分账 --------------------------------------
    def settle(self, total_price: float) -> List[SettlementRow]:
        rows: List[SettlementRow] = []
        cs: Dict[str, float] = {}
        base_cs: Dict[str, float] = {}
        for oem, p in self.parties.items():
            c = (self.lam * p.entropy + (1 - self.lam) * p.phi) * p.reputation
            cs[oem] = c
            # 现有技术对照: 仅用梯度余弦相似度(含负值不截断), 无熵权、无信誉
            base_cs[oem] = max(0.0, sum(p.phi_series) / max(len(p.phi_series), 1))
        tot, btot = sum(cs.values()), sum(base_cs.values())
        for oem, p in self.parties.items():
            nc = cs[oem] / tot if tot > 0 else 0.0
            rows.append(SettlementRow(
                oem=oem, entropy=p.entropy, phi=p.phi, reputation=p.reputation,
                contribution=cs[oem], normalized=nc, payout=nc * total_price,
                anomaly_rounds=[a["round"] for a in p.anomalies],
                baseline_normalized=base_cs[oem] / btot if btot > 0 else 0.0))
        rows.sort(key=lambda r: -r.normalized)
        if self.audit:
            self.audit.record("settlement", {
                "total_price": total_price,
                "shares": {r.oem: round(r.normalized, 6) for r in rows},
                "payouts": {r.oem: round(r.payout, 2) for r in rows},
                "params": {"lambda": self.lam, "gamma": self.gamma,
                           "theta_th": self.theta_th, "beta": self.beta, "eta": self.eta},
            })
        for r in rows:
            self.log.append(
                f"{r.oem}: H={r.entropy:.4f} Φ={r.phi:.4f} rep={r.reputation:.4f} "
                f"-> C={r.contribution:.4f} Ĉ={r.normalized:.4f} 分账 {r.payout:,.2f} 元 "
                f"(现有技术对照 {r.baseline_normalized:.4f})")
        return rows


# ---------------------------------------------------------------------------
# 智能合约: 使用次数限额与自动分账
# ---------------------------------------------------------------------------
class SmartContract:
    """
    区块链智能合约模拟。强制执行数据资产的使用规则:
      Price = f(DataVolume, PrecisionLevel, TimeRange)
      UsageLimit = N 次/天
    """

    def __init__(self, asset_id: str, daily_limit: int = 1, price_base: float = 100000.0,
                 audit=None):
        self.asset_id = asset_id
        self.daily_limit = daily_limit
        self.price_base = price_base
        self.counters: Dict[Tuple[str, str], int] = {}   # (消费方, 日期) -> 次数
        self.audit = audit
        self.log: List[str] = []

    def price(self, volume: int, precision_level: int, months: int = 1) -> float:
        """计费函数: 数据量对数增长 × 精度系数 × 时间范围。"""
        prec_factor = {1: 1.6, 2: 1.0, 3: 0.6}.get(precision_level, 1.0)
        return self.price_base * math.log10(max(volume, 10)) / 4.0 * prec_factor * months

    def check_usage(self, consumer: str, day: str) -> Tuple[bool, str]:
        k = (consumer, day)
        used = self.counters.get(k, 0)
        if used >= self.daily_limit:
            msg = f"合约计数器拦截: {consumer} 于 {day} 已使用 {used}/{self.daily_limit} 次"
            if self.audit:
                self.audit.record("contract_reject", {"consumer": consumer, "day": day,
                                                      "used": used, "limit": self.daily_limit})
            self.log.append(msg)
            return False, msg
        self.counters[k] = used + 1
        self.log.append(f"合约放行: {consumer} 于 {day} 第 {used + 1}/{self.daily_limit} 次使用")
        return True, "放行"

    def distribute(self, rows: List[SettlementRow], total: float) -> Dict[str, float]:
        out = {r.oem: r.normalized * total for r in rows}
        self.log.append(f"合约自动分账总额 {total:,.2f} 元: " +
                        ", ".join(f"{k} {v:,.2f}" for k, v in out.items()))
        return out
