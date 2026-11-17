"""
m230_budget.py -- 隐私预算账本模块 (图2 模块 230)

模块说明:
  采用 Rényi 差分隐私(RDP)组合会计核算多轮查询的隐私损失, 对阶数 α 寻优,
  超出剩余预算时拒绝请求或触发降级策略。

核心公式(式(7)(8)):
  单次拉普拉斯机制的 RDP 损失(b 为以敏感度归一的噪声尺度, b = 1/ε_q):

      ε_RDP(α) = 1/(α-1) · ln[ α/(2α-1) · e^{(α-1)/b} + (α-1)/(2α-1) · e^{-α/b} ]

  n 轮组合后转换回 (ε, δ)-DP:

      ε_composed = n · ε_RDP(α) + ln(1/δ)/(α-1)

数值实现要点:
  (α-1)/b 在 ε 较大时会溢出 exp, 故采用 log-sum-exp 稳定化:
      ln(w1·e^A + w2·e^B) = M + ln(w1·e^{A-M} + w2·e^{B-M}),  M = max(A, B)
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# 拉普拉斯机制的 Rényi 差分隐私损失
# ---------------------------------------------------------------------------
def laplace_rdp(alpha: float, b: float) -> float:
    """
    参数:
        alpha: Rényi 阶数 α > 1
        b    : 以敏感度归一的噪声尺度 (b = Δf/ε 归一后即 1/ε)
    返回:
        ε_RDP(α)
    """
    if alpha <= 1:
        raise ValueError("Rényi 阶数 α 必须大于 1")
    if b <= 0:
        return float("inf")
    w1 = alpha / (2 * alpha - 1)
    w2 = (alpha - 1) / (2 * alpha - 1)
    a_exp = (alpha - 1) / b
    b_exp = -alpha / b
    m = max(a_exp, b_exp)                       # log-sum-exp 稳定化
    inner = math.log(w1 * math.exp(a_exp - m) + w2 * math.exp(b_exp - m)) + m
    return inner / (alpha - 1)


# ---------------------------------------------------------------------------
# RDP -> (ε, δ)-DP 转换
# ---------------------------------------------------------------------------
def rdp_to_dp(alpha: float, rdp_total: float, delta: float) -> float:
    return rdp_total + math.log(1.0 / delta) / (alpha - 1)


def compose(rounds: List[Tuple[int, float]], alpha: float, delta: float) -> float:
    """
    多批查询组合。rounds 为 [(轮数 n, 噪声尺度 b), ...]。
    RDP 在同阶 α 下可直接相加, 这是其相较线性叠加 (ε,δ) 更紧的根本原因。
    """
    total = sum(n * laplace_rdp(alpha, b) for n, b in rounds)
    return rdp_to_dp(alpha, total, delta)


def optimize_alpha(rounds: List[Tuple[int, float]], delta: float,
                   alpha_min: float = 1.05, alpha_max: float = 64.0,
                   grid: int = 240) -> Tuple[float, float, List[Tuple[float, float]]]:
    """
    对 α 在预设区间内寻优, 取使 ε_composed 最小的 α*。
    先做对数均匀网格粗搜, 再在最优点邻域做黄金分割精搜。
    返回 (α*, ε_composed_min, 曲线采样点)。
    """
    lo, hi = math.log(alpha_min), math.log(alpha_max)
    curve: List[Tuple[float, float]] = []
    best_a, best_v = alpha_min, float("inf")
    for i in range(grid + 1):
        a = math.exp(lo + (hi - lo) * i / grid)
        v = compose(rounds, a, delta)
        curve.append((a, v))
        if v < best_v:
            best_a, best_v = a, v
    # 黄金分割精搜
    span = (hi - lo) / grid
    a_lo = max(alpha_min, math.exp(math.log(best_a) - span))
    a_hi = min(alpha_max, math.exp(math.log(best_a) + span))
    phi = (math.sqrt(5) - 1) / 2
    for _ in range(60):
        x1 = a_hi - phi * (a_hi - a_lo)
        x2 = a_lo + phi * (a_hi - a_lo)
        if compose(rounds, x1, delta) < compose(rounds, x2, delta):
            a_hi = x2
        else:
            a_lo = x1
    a_star = (a_lo + a_hi) / 2
    v_star = compose(rounds, a_star, delta)
    if v_star > best_v:
        a_star, v_star = best_a, best_v
    return a_star, v_star, curve


# ---------------------------------------------------------------------------
# 降级策略
# ---------------------------------------------------------------------------
@dataclass
class Degradation:
    kind: str          # precision / granularity / timewindow
    desc: str
    new_eps_q: float
    new_rounds: int


@dataclass
class BudgetDecision:
    admitted: bool
    alpha_star: float
    eps_composed: float
    eps_total: float
    eps_remaining: float
    linear_eps: float                     # 线性叠加对照值
    degradation: Optional[Degradation] = None
    curve: List[Tuple[float, float]] = field(default_factory=list)
    message: str = ""


class BudgetLedger:
    """
    隐私预算账本。以 (数据主体, 资产) 为粒度维护总预算与历史消耗。
    本实现以资产为账户粒度, 数据主体维度通过 subject_scale 体现。
    """

    def __init__(self, eps_total: float = 8.0, delta: float = 1e-5, audit=None):
        self.eps_total = eps_total
        self.delta = delta
        self.history: Dict[str, List[Tuple[int, float]]] = {}   # asset -> [(n, b)]
        self.audit = audit
        self.log: List[str] = []

    def preload(self, asset_id: str, rounds: int, eps_q: float):
        """预置历史查询记录(模拟资产上线以来的累计消耗)。"""
        self.history.setdefault(asset_id, []).append((rounds, 1.0 / eps_q))
        self.log.append(f"账本预置: {asset_id} 历史 {rounds} 轮 @ ε_q={eps_q} "
                        f"(噪声尺度 b={1.0/eps_q:g})")

    def _rounds_with(self, asset_id: str, extra: Optional[Tuple[int, float]] = None):
        r = list(self.history.get(asset_id, []))
        if extra:
            r.append(extra)
        return r

    def linear_composition(self, asset_id: str, extra=None) -> float:
        """朴素线性叠加对照: Σ n_i · ε_i"""
        return sum(n / b for n, b in self._rounds_with(asset_id, extra))

    def evaluate(self, asset_id: str, eps_q: float, n_rounds: int = 1) -> BudgetDecision:
        """核算本次请求的隐私损失并判定准入。"""
        b = 1.0 / eps_q
        extra = (n_rounds, b)
        a_star, eps_c, curve = optimize_alpha(
            self._rounds_with(asset_id, extra), self.delta)
        linear = self.linear_composition(asset_id, extra)
        used_before = optimize_alpha(self._rounds_with(asset_id), self.delta)[1] \
            if self.history.get(asset_id) else 0.0
        admitted = eps_c <= self.eps_total
        d = BudgetDecision(
            admitted=admitted, alpha_star=a_star, eps_composed=eps_c,
            eps_total=self.eps_total, eps_remaining=max(0.0, self.eps_total - eps_c),
            linear_eps=linear, curve=curve,
            message=("准入通过" if admitted else "预算超限, 需降级或拒绝"))
        if not admitted:
            d.degradation = self._degrade(asset_id, eps_q, n_rounds)
        self._audit(asset_id, eps_q, n_rounds, d, used_before)
        return d

    def _degrade(self, asset_id: str, eps_q: float, n_rounds: int) -> Optional[Degradation]:
        """
        降级策略: 依次尝试
          ① 降低查询精度(增大噪声, 减小 ε_q)
          ② 扩大聚合粒度(单车 -> 车队, 等效减少独立查询数)
          ③ 延长统计时间窗(日粒度 -> 周粒度, 轮数下降)
        """
        candidates = [
            Degradation("precision", "精度等级 2 -> 3 (ε_q 0.1 -> 0.05)", 0.05, n_rounds),
            Degradation("granularity", "聚合粒度: 单车级 -> 车队级 (轮数减半)",
                        eps_q, max(1, n_rounds // 2)),
            Degradation("timewindow", "统计时间窗: 日粒度 -> 周粒度 (30点 -> 5点)",
                        0.05, max(1, n_rounds // 6)),
        ]
        for c in candidates:
            _, eps_c, _ = optimize_alpha(
                self._rounds_with(asset_id, (c.new_rounds, 1.0 / c.new_eps_q)), self.delta)
            if eps_c <= self.eps_total:
                c.desc += f"  =>  ε_composed={eps_c:.4f} ≤ {self.eps_total}"
                return c
        return None

    def commit(self, asset_id: str, eps_q: float, n_rounds: int = 1):
        """请求实际执行后记账。"""
        self.history.setdefault(asset_id, []).append((n_rounds, 1.0 / eps_q))
        self.log.append(f"记账: {asset_id} +{n_rounds} 轮 @ ε_q={eps_q}")

    def _audit(self, asset_id, eps_q, n_rounds, d: BudgetDecision, used_before):
        if self.audit:
            self.audit.record("budget_accounting", {
                "asset_id": asset_id, "eps_q": eps_q, "rounds": n_rounds,
                "alpha_star": round(d.alpha_star, 4),
                "eps_composed": round(d.eps_composed, 6),
                "eps_total": d.eps_total, "admitted": d.admitted,
                "linear_eps": round(d.linear_eps, 6),
                "degradation": d.degradation.desc if d.degradation else None,
            })
        self.log.append(
            f"核算: α*={d.alpha_star:.3f}, ε_composed={d.eps_composed:.4f} "
            f"(线性叠加对照 {d.linear_eps:.2f}), 总预算 {d.eps_total} -> "
            f"{'准入' if d.admitted else '拒绝'}")

    def max_rounds_under_budget(self, eps_q: float) -> Tuple[int, int]:
        """
        计算同一预算下 RDP 组合会计 与 线性叠加 各自可支撑的最大查询轮数,
        用于量化本方案相对现有技术的预算利用率提升。
        """
        b = 1.0 / eps_q
        n_rdp = 0
        while True:
            nxt = n_rdp + 1
            _, eps_c, _ = optimize_alpha([(nxt, b)], self.delta)
            if eps_c > self.eps_total:
                break
            n_rdp = nxt
            if n_rdp > 100000:
                break
        n_lin = int(self.eps_total / eps_q)
        return n_rdp, n_lin
