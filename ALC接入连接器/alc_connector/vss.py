"""
vss.py -- VSS (Vehicle Signal Specification) 语义模型

模块说明:
  - 权利要求1: 语义映射单元将原始信号映射为 VSS 语义模型下带元数据标注的标准化信号,
               元数据至少包括信号的物理量程和隐私敏感等级
  - 实施例二 表1: VSS 语义树节点隐私敏感等级标注

设计说明:
  physical_min/max、unit、datatype 属于 COVESA VSS 标准元数据字段;
  sensitivity (敏感等级 s) 属于本方案通过 VSS overlay 机制叠加的自定义隐私元数据,
  二者共同构成"元数据驱动的维度级隐私标定"的输入。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class VSSNode:
    """VSS 语义树节点。type ∈ {branch, sensor, actuator, attribute}"""
    path: str
    type: str = "sensor"
    datatype: str = "float"
    unit: str = ""
    physical_min: float = 0.0
    physical_max: float = 1.0
    sensitivity: int = 1          # overlay 叠加字段: 隐私敏感等级 s ∈ {1..L}
    category: str = ""            # 维度类别(表1)
    description: str = ""

    @property
    def name(self) -> str:
        return self.path.rsplit(".", 1)[-1]

    @property
    def span(self) -> float:
        """物理量程跨度 max_i - min_i, 用于式(2)归一化。"""
        return self.physical_max - self.physical_min

    def normalize(self, x: float) -> float:
        """x~_i = (x_i - min_i) / (max_i - min_i)"""
        if self.span == 0:
            return 0.0
        return (x - self.physical_min) / self.span

    def denormalize(self, xn: float) -> float:
        """反归一化: z_i = z~_i * (max_i - min_i) + min_i"""
        return xn * self.span + self.physical_min


# --- VSS 标准目录子集 + 敏感等级 overlay(敏感等级) -----------------------------
_CATALOG: List[VSSNode] = [
    VSSNode("Vehicle", "branch", description="根节点"),
    VSSNode("Vehicle.Speed", "sensor", "float", "km/h", 0.0, 200.0, 2,
            "驾驶行为类", "车辆行驶速度"),
    VSSNode("Vehicle.Chassis.Brake.EventsPerWeek", "sensor", "float", "count/week",
            0.0, 50.0, 2, "驾驶行为类", "周急刹事件次数"),
    VSSNode("Vehicle.Powertrain.Battery.StateOfHealth", "sensor", "float", "percent",
            0.0, 100.0, 1, "车况状态类", "动力电池健康度 SoH"),
    VSSNode("Vehicle.Exterior.AirTemperature", "sensor", "float", "Celsius",
            -20.0, 60.0, 1, "车况状态类", "车外环境温度"),
    VSSNode("Vehicle.TraveledDistance", "sensor", "float", "km", 0.0, 500000.0, 1,
            "车况状态类", "累计里程(用于演示量纲混叠)"),
    VSSNode("Vehicle.CurrentLocation.Latitude", "sensor", "float", "degrees",
            -90.0, 90.0, 3, "位置轨迹类", "纬度"),
    VSSNode("Vehicle.CurrentLocation.Longitude", "sensor", "float", "degrees",
            -180.0, 180.0, 3, "位置轨迹类", "经度"),
    VSSNode("Vehicle.VehicleIdentification.VIN", "attribute", "string", "", 0, 0, 3,
            "标识类", "车辆识别代号"),
]

CATALOG: Dict[str, VSSNode] = {n.path: n for n in _CATALOG}

# 车端原始信号(CAN/DoIP/MQTT 私有命名) -> VSS 标准路径的可热更新映射表
SIGNAL_MAP: Dict[str, str] = {
    "VehSpd_kph":        "Vehicle.Speed",
    "BrkEvtCnt_wk":      "Vehicle.Chassis.Brake.EventsPerWeek",
    "BattSoH_pct":       "Vehicle.Powertrain.Battery.StateOfHealth",
    "AmbTemp_C":         "Vehicle.Exterior.AirTemperature",
    "OdoTotal_km":       "Vehicle.TraveledDistance",
    "GNSS_Lat":          "Vehicle.CurrentLocation.Latitude",
    "GNSS_Lon":          "Vehicle.CurrentLocation.Longitude",
    "VIN_raw":           "Vehicle.VehicleIdentification.VIN",
}


def get(path: str) -> VSSNode:
    if path not in CATALOG:
        raise KeyError(f"VSS 语义树中不存在节点: {path}")
    return CATALOG[path]


def map_raw_signal(raw_name: str) -> Optional[VSSNode]:
    """语义映射单元(120): 原始信号名 -> VSS 节点。"""
    path = SIGNAL_MAP.get(raw_name)
    return CATALOG.get(path) if path else None


def tree_lines() -> List[str]:
    """按层级渲染语义树, 供 UI 展示。"""
    out = []
    for path in sorted(CATALOG):
        node = CATALOG[path]
        depth = path.count(".")
        pad = "    " * depth
        if node.type == "branch":
            out.append(f"{pad}{node.name}/   [branch]")
        else:
            meta = f"unit={node.unit or '-'}  range=[{node.physical_min:g}, {node.physical_max:g}]  s={node.sensitivity}"
            out.append(f"{pad}{node.name}   [{node.type}]  {meta}")
    return out


def sensitivity_weights(paths: List[str]) -> Dict[str, float]:
    """
    w_i = 2^(-s_i) / Σ_j 2^(-s_j)
    敏感等级越高 -> 权重越小 -> 分得预算越少 -> 噪声越大 -> 保护越强
    """
    raw = {p: 2.0 ** (-get(p).sensitivity) for p in paths}
    total = sum(raw.values())
    return {p: v / total for p, v in raw.items()}
