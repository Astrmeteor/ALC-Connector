"""
m220_policy.py -- 基于属性的动态脱敏策略引擎 (图2 模块 220)

模块说明:
  以 (主体角色, 使用目的, 时间窗, 空间围栏, 精度等级) 五元组定义动态脱敏策略,
  将 泛化/抑制/扰动 三类脱敏算子绑定至 VSS 语义树对应节点执行,
  策略内容的哈希值上链存证。
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from datetime import date
from typing import Dict, List, Optional, Tuple

from . import vss
from .crypto_lite import sha256_hex

# 精度等级 -> 单次查询总预算 ε_q 的映射 (精度-预算映射表)
PRECISION_EPS: Dict[int, float] = {1: 0.2, 2: 0.1, 3: 0.05}


@dataclass
class GeoFence:
    """空间围栏: 以中心点与半径(km)定义。"""
    name: str
    lat: float
    lon: float
    radius_km: float

    def contains(self, lat: float, lon: float) -> bool:
        # 等距圆近似: 1 度纬度 ≈ 111.32 km
        dlat = (lat - self.lat) * 111.32
        dlon = (lon - self.lon) * 111.32 * math.cos(math.radians(self.lat))
        return math.hypot(dlat, dlon) <= self.radius_km


@dataclass
class Policy:
    """五元组动态脱敏策略。"""
    policy_id: str
    subject_role: str            # 主体角色
    purpose: str                 # 使用目的
    time_window: Tuple[str, str]  # 时间窗 (ISO 日期)
    geofence: GeoFence           # 空间围栏
    max_precision_level: int     # 精度等级(数值越小精度越高, 请求需 >= 本值)
    operators: Dict[str, dict] = field(default_factory=dict)  # VSS 路径 -> 算子
    signer: str = ""

    def content_hash(self) -> str:
        body = {
            "id": self.policy_id, "role": self.subject_role, "purpose": self.purpose,
            "window": list(self.time_window),
            "fence": [self.geofence.name, self.geofence.lat, self.geofence.lon,
                      self.geofence.radius_km],
            "precision": self.max_precision_level,
            "operators": self.operators, "signer": self.signer,
        }
        return sha256_hex(json.dumps(body, sort_keys=True, ensure_ascii=False).encode())


@dataclass
class AccessRequest:
    """数据消费方访问请求。"""
    requester: str
    subject_role: str
    purpose: str
    date_from: str
    date_to: str
    lat: float
    lon: float
    precision_level: int
    asset_id: str
    task_type: str                        # statistics / fl_training / psi
    signal_paths: List[str] = field(default_factory=list)
    latency_budget_s: float = 5.0
    participants: int = 1


@dataclass
class PolicyDecision:
    allowed: bool
    policy_id: Optional[str]
    policy_hash: Optional[str]
    eps_q: float
    plan: Dict[str, dict] = field(default_factory=dict)   # 脱敏执行计划
    reasons: List[str] = field(default_factory=list)
    denied_paths: List[str] = field(default_factory=list)


class PolicyEngine:
    """策略引擎。"""

    def __init__(self, audit=None):
        self.policies: Dict[str, Policy] = {}
        self.audit = audit
        self.log: List[str] = []

    def define(self, policy: Policy) -> str:
        """策略定义 + 签署 + 哈希上链存证。"""
        self.policies[policy.policy_id] = policy
        h = policy.content_hash()
        if self.audit:
            self.audit.record("policy_register",
                              {"policy_id": policy.policy_id, "policy_hash": h,
                               "signer": policy.signer})
        self.log.append(f"策略 {policy.policy_id} 由 {policy.signer} 签署, "
                        f"哈希 {h[:16]}… 已上链")
        return h

    # -- 逐项属性匹配 --------------------------------------------------------
    def _match(self, pol: Policy, req: AccessRequest) -> Tuple[bool, List[str]]:
        rs: List[str] = []
        ok = True
        if pol.subject_role != req.subject_role:
            ok = False
            rs.append(f"主体角色不匹配: 策略要求 {pol.subject_role}, 请求为 {req.subject_role}")
        else:
            rs.append(f"主体角色命中: {req.subject_role}")
        if pol.purpose != req.purpose:
            ok = False
            rs.append(f"使用目的不匹配: 策略要求 {pol.purpose}, 请求为 {req.purpose}")
        else:
            rs.append(f"使用目的命中: {req.purpose}")
        if not (pol.time_window[0] <= req.date_from and req.date_to <= pol.time_window[1]):
            ok = False
            rs.append(f"时间窗越界: 请求 {req.date_from}~{req.date_to} 超出策略 "
                      f"{pol.time_window[0]}~{pol.time_window[1]}")
        else:
            rs.append(f"时间窗命中: {req.date_from}~{req.date_to}")
        if not pol.geofence.contains(req.lat, req.lon):
            ok = False
            rs.append(f"空间围栏越界: 请求点不在 {pol.geofence.name} 内")
        else:
            rs.append(f"空间围栏命中: {pol.geofence.name}")
        if req.precision_level < pol.max_precision_level:
            ok = False
            rs.append(f"精度等级越权: 请求 {req.precision_level} 高于策略允许的 "
                      f"{pol.max_precision_level}")
        else:
            rs.append(f"精度等级合规: {req.precision_level}")
        return ok, rs

    def evaluate(self, req: AccessRequest) -> PolicyDecision:
        """逐请求匹配策略, 生成脱敏执行计划。"""
        for pol in self.policies.values():
            ok, rs = self._match(pol, req)
            if not ok:
                continue
            plan, denied = {}, []
            for path in req.signal_paths:
                op = pol.operators.get(path, {"op": "pass"})
                if op["op"] == "suppress":
                    denied.append(path)
                else:
                    plan[path] = op
            eps_q = PRECISION_EPS[req.precision_level]
            d = PolicyDecision(True, pol.policy_id, pol.content_hash(), eps_q, plan, rs, denied)
            self._audit(req, d)
            return d
        # 无命中策略 -> 拒绝
        best_rs: List[str] = []
        for pol in self.policies.values():
            _, rs = self._match(pol, req)
            best_rs = rs
        d = PolicyDecision(False, None, None, 0.0, {}, best_rs or ["无任何已登记策略"], [])
        self._audit(req, d)
        return d

    def _audit(self, req: AccessRequest, d: PolicyDecision):
        if self.audit:
            self.audit.record("policy_decision", {
                "requester": req.requester, "purpose": req.purpose,
                "policy_hash": d.policy_hash, "allowed": d.allowed,
                "eps_q": d.eps_q, "plan": {k: v["op"] for k, v in d.plan.items()},
                "denied": d.denied_paths,
            })
        self.log.append(
            f"请求[{req.requester}/{req.purpose}] -> "
            f"{'允许' if d.allowed else '拒绝'}"
            + (f", 命中 {d.policy_id}, ε_q={d.eps_q}" if d.allowed else ""))

    # -- 脱敏算子执行 --------------------------------------------------------
    @staticmethod
    def apply_operator(path: str, value: float, op: dict) -> Optional[float]:
        """
        执行绑定在 VSS 节点上的脱敏算子:
          generalize 泛化 : 按栅格量化(如坐标泛化至区县级)
          suppress   抑制 : 直接拦截, 返回 None
          perturb    扰动 : 交由隐私计算沙箱按 ε 加噪(此处仅标记)
          pass       放行
        """
        kind = op.get("op", "pass")
        if kind == "suppress":
            return None
        if kind == "generalize":
            g = op.get("grid", 1.0)
            return round(value / g) * g
        return value

    def apply_plan(self, record: Dict[str, float], d: PolicyDecision) -> Dict[str, float]:
        out = {}
        for path, val in record.items():
            if path in d.denied_paths:
                continue
            op = d.plan.get(path)
            if op is None:
                continue
            v = self.apply_operator(path, val, op)
            if v is not None:
                out[path] = v
        return out


# ---------------------------------------------------------------------------
# 预置策略: 保险 UBI 定价 与 交管事故调查 (实施例六两个场景示例)
# ---------------------------------------------------------------------------
def build_default_policies() -> List[Policy]:
    return [
        Policy(
            policy_id="POL-INS-001",
            subject_role="保险精算类机构",
            purpose="UBI保费定价",
            time_window=("2026-06-01", "2026-06-30"),
            geofence=GeoFence("X市行政区划", 39.90, 116.40, 80.0),
            max_precision_level=2,
            operators={
                "Vehicle.Speed": {"op": "perturb"},
                "Vehicle.Chassis.Brake.EventsPerWeek": {"op": "perturb"},
                "Vehicle.Powertrain.Battery.StateOfHealth": {"op": "perturb"},
                "Vehicle.TraveledDistance": {"op": "perturb"},
                # 位置泛化至区县级(约 0.1 度栅格 ≈ 11 km)
                "Vehicle.CurrentLocation.Latitude": {"op": "generalize", "grid": 0.1},
                "Vehicle.CurrentLocation.Longitude": {"op": "generalize", "grid": 0.1},
                "Vehicle.VehicleIdentification.VIN": {"op": "suppress"},
            },
            signer="车企A",
        ),
        Policy(
            policy_id="POL-GOV-002",
            subject_role="交通管理部门",
            purpose="事故调查",
            time_window=("2026-06-14", "2026-06-16"),
            geofence=GeoFence("事发路段围栏", 39.92, 116.44, 3.0),
            max_precision_level=1,
            operators={
                "Vehicle.Speed": {"op": "pass"},
                "Vehicle.Chassis.Brake.EventsPerWeek": {"op": "pass"},
                # 事故调查放行 100 m 精度轨迹 (约 0.0009 度)
                "Vehicle.CurrentLocation.Latitude": {"op": "generalize", "grid": 0.0009},
                "Vehicle.CurrentLocation.Longitude": {"op": "generalize", "grid": 0.0009},
                "Vehicle.VehicleIdentification.VIN": {"op": "suppress"},
            },
            signer="车企A",
        ),
    ]
