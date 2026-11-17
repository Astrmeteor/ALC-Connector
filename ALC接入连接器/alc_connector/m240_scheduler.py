"""
m240_scheduler.py -- 隐私计算模式自适应调度模块 (图2 模块 240)

模块说明:
  提取任务特征向量 (τ, T_max, n, V, ε_remain, R), 在候选执行模式
  M = {DP统计查询, MPC, FL, TEE} 中, 于满足延迟约束的候选集内选取
  代价函数式(9)取值最小者:

      cost(m) = w1·T̂_m + w2·B̂_m + w3·L̂_m

  其中 T̂/B̂/L̂ 分别为预估时延、预估通信开销与预估隐私损失(各项组内归一化)。
  当 ε_remain 不足时优先选择不消耗差分隐私预算的 TEE 或 MPC 模式。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class TaskFeature:
    """任务特征向量 (τ, T_max, n, V, ε_remain, R)"""
    task_type: str            # τ: statistics / fl_training / psi / complex_operator
    latency_budget_s: float   # T_max
    participants: int         # n
    data_scale: int           # V: 记录数
    feature_dim: int = 8      # 模型/查询维度
    eps_remaining: float = 1.0
    vehicle_compute: float = 0.3   # R: 车端可用算力归一值 [0,1]
    rounds: int = 1
    raw_data_must_stay_local: bool = True   # 原始数据不出域约束


@dataclass
class ModeEstimate:
    mode: str
    latency_s: float
    comm_mb: float
    privacy_loss: float
    feasible: bool
    reason: str = ""
    cost: float = 0.0


# 各模式的能力矩阵: 模式 -> 可承载的任务类型
CAPABILITY: Dict[str, set] = {
    "DP":  {"statistics"},
    "MPC": {"statistics", "psi"},
    "FL":  {"fl_training"},
    "TEE": {"statistics", "psi", "fl_training", "complex_operator"},
}


class Scheduler:
    """隐私计算调度模块。"""

    def __init__(self, w1: float = 0.5, w2: float = 0.2, w3: float = 0.3, audit=None):
        self.w = (w1, w2, w3)
        self.audit = audit
        self.log: List[str] = []

    # -- 各模式的代价预估模型 ------------------------------------------------
    @staticmethod
    def estimate(mode: str, f: TaskFeature) -> ModeEstimate:
        """
        基于任务特征的解析式预估。系数为工程经验值, 可按实际部署标定。
        """
        n, V, d, R = f.participants, f.data_scale, f.feature_dim, f.rounds
        if mode == "DP":
            # 单次聚合扫描, 时延随数据量线性增长; 通信量仅为结果向量
            lat = 0.05 + V * 3e-5 * max(1, d) / 8
            comm = 0.0002 * d
            loss = 1.0 / max(f.eps_remaining, 1e-9) * 0.1   # 消耗 DP 预算
            loss = 0.1                                       # 单次查询 ε_q 量级
        elif mode == "MPC":
            # 秘密分享: 通信量 ~ O(n^2 · V); 深度模型训练下通信爆炸
            lat = 0.5 + n * n * V * 1.2e-4 * max(1, d) / 8 * (R if f.task_type == "fl_training" else 1)
            comm = n * (n - 1) * V * d * 8e-6 * (R if f.task_type == "fl_training" else 1)
            loss = 0.0                                       # 精确计算, 零 DP 预算消耗
        elif mode == "FL":
            # 仅交换梯度: 通信量 ~ 参与方数 × 轮数 × 模型大小
            model_mb = d * 4e-6 * 2_500_000 / max(d, 1)       # 约 80 MB 量级模型
            lat = 60.0 + R * n * 0.6
            comm = n * R * model_mb
            loss = 0.0
        elif mode == "TEE":
            # 需将数据迁入飞地: 通信量 ~ 全量数据; 有远程证明固定开销
            lat = 1.2 + V * 1.5e-4 + R * 0.2
            comm = V * d * 4e-6 * 1000
            loss = 0.0
        else:
            raise ValueError(mode)

        feasible, reason = True, ""
        if f.task_type not in CAPABILITY[mode]:
            feasible, reason = False, f"能力矩阵不覆盖任务类型 {f.task_type}"
        elif mode == "MPC" and f.participants < 2:
            feasible, reason = False, f"多方安全计算至少需要 2 个参与方(当前 {f.participants})"
        elif lat > f.latency_budget_s:
            feasible, reason = False, f"预估时延 {lat:.2f}s 超出延迟约束 {f.latency_budget_s:g}s"
        elif mode == "DP" and f.eps_remaining < loss:
            feasible, reason = False, f"剩余预算 {f.eps_remaining:.3f} 不足以覆盖 ε_q={loss}"
        elif mode == "TEE" and f.raw_data_must_stay_local and f.task_type == "fl_training":
            feasible, reason = False, "违反原始数据不出域约束(需汇集各方明文特征)"
        return ModeEstimate(mode, lat, comm, loss, feasible, reason)

    # -- 式(9) 代价函数与选优 ------------------------------------------------
    def schedule(self, f: TaskFeature) -> Tuple[Optional[str], List[ModeEstimate]]:
        ests = [self.estimate(m, f) for m in CAPABILITY]
        cands = [e for e in ests if e.feasible]
        if not cands:
            self._audit(f, None, ests)
            return None, ests
        # 组内 min-max 归一化后加权
        def norm(vals: List[float]) -> List[float]:
            lo, hi = min(vals), max(vals)
            return [0.0 if hi == lo else (v - lo) / (hi - lo) for v in vals]

        nt = norm([e.latency_s for e in cands])
        nb = norm([e.comm_mb for e in cands])
        nl = norm([e.privacy_loss for e in cands])
        w1, w2, w3 = self.w
        for e, t, b, l in zip(cands, nt, nb, nl):
            e.cost = w1 * t + w2 * b + w3 * l
        # 预算不足时优先零预算模式
        if f.eps_remaining <= 0.05:
            zero = [e for e in cands if e.privacy_loss == 0.0]
            if zero:
                cands = zero
        best = min(cands, key=lambda e: e.cost)
        self._audit(f, best, ests)
        return best.mode, ests

    def _audit(self, f: TaskFeature, best: Optional[ModeEstimate], ests: List[ModeEstimate]):
        if self.audit:
            self.audit.record("schedule_decision", {
                "task_type": f.task_type, "latency_budget_s": f.latency_budget_s,
                "participants": f.participants, "data_scale": f.data_scale,
                "eps_remaining": round(f.eps_remaining, 4),
                "selected": best.mode if best else None,
                "candidates": {e.mode: {"feasible": e.feasible,
                                        "lat": round(e.latency_s, 3),
                                        "comm": round(e.comm_mb, 3),
                                        "cost": round(e.cost, 4)} for e in ests},
            })
        if best:
            self.log.append(f"任务[{f.task_type}] -> 选定 {best.mode} "
                            f"(cost={best.cost:.4f}, 时延 {best.latency_s:.2f}s, "
                            f"通信 {best.comm_mb:.2f}MB)")
        else:
            self.log.append(f"任务[{f.task_type}] -> 无可行模式")
