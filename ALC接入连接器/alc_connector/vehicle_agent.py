"""
vehicle_agent.py -- 车端轻量数据代理 (图2 模块 100)

模块说明:
  110 信号采集单元 : CAN 总线信号矩阵解析 / DoIP / MQTT 遥测
  120 语义映射单元 : 原始信号 -> VSS 语义树节点 + 元数据标注
  130 本地预处理单元: 静态脱敏 + 本地差分隐私扰动 + ECC 加密
  车云通信         : QUIC 0-RTT 会话恢复 (本实现模拟其会话票据与重连语义)
"""
from __future__ import annotations

import hashlib
import json
import math
import random
import secrets
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import vss
from .crypto_lite import ECKeyPair, aead_encrypt, hkdf, sha256_hex


# ---------------------------------------------------------------------------
# 拉普拉斯采样: 逆累积分布法 (对应式(6)与式(15)中的 F_Lap^{-1})
#   F^{-1}(u; b) = -b * sgn(u-0.5) * ln(1 - 2|u-0.5|),  u ~ U(0,1)
# ---------------------------------------------------------------------------
def laplace_inv_cdf(u: float, b: float, mu: float = 0.0) -> float:
    if b <= 0:
        return mu
    u = min(max(u, 1e-12), 1 - 1e-12)
    d = u - 0.5
    return mu - b * math.copysign(1.0, d) * math.log(1.0 - 2.0 * abs(d))


def laplace_sample(b: float, rng: random.Random, mu: float = 0.0) -> float:
    return laplace_inv_cdf(rng.random(), b, mu)


@dataclass
class VehicleProfile:
    """单车画像, 用于生成具有真实分布特征的合成信号。"""
    vin: str
    oem: str
    base_speed: float          # 平均车速中心
    speed_sigma: float         # 车速离散度(刻画工况多样性)
    brake_lambda: float        # 周急刹次数(泊松均值)
    soh: float                 # 电池健康度
    mileage: float             # 累计里程
    lat: float
    lon: float


class VehicleAgent:
    """车端轻量数据代理。每个实例对应一辆车。"""

    STATIC_MASK_GPS_M = 100.0   # 静态脱敏: GPS 精度降至 100 m

    def __init__(self, profile: VehicleProfile, seed: int = 0):
        self.p = profile
        self.rng = random.Random(seed)
        self.keys = ECKeyPair()              # 车端 ECC 密钥对
        self.session_key: Optional[bytes] = None
        self.session_ticket: Optional[str] = None   # QUIC 0-RTT 会话票据
        self.seq = 0                          # 单调序列号, 防重放

    # -- 110 信号采集单元 ---------------------------------------------------
    def collect_raw(self) -> Dict[str, float]:
        """模拟 CAN 信号矩阵解析后得到的一条原始遥测记录(私有命名)。"""
        p, r = self.p, self.rng
        speed = max(0.0, min(200.0, r.gauss(p.base_speed, p.speed_sigma)))
        brake = float(max(0, min(50, int(self._poisson(p.brake_lambda)))))
        return {
            "VehSpd_kph": speed,
            "BrkEvtCnt_wk": brake,
            "BattSoH_pct": max(0.0, min(100.0, r.gauss(p.soh, 1.2))),
            "AmbTemp_C": max(-20.0, min(60.0, r.gauss(24.0, 6.0))),
            "OdoTotal_km": p.mileage,
            "GNSS_Lat": p.lat + r.gauss(0, 0.01),
            "GNSS_Lon": p.lon + r.gauss(0, 0.01),
            "VIN_raw": p.vin,
        }

    def _poisson(self, lam: float) -> int:
        """Knuth 泊松采样, 用于急刹事件计数。"""
        l, k, prod = math.exp(-lam), 0, 1.0
        while True:
            prod *= self.rng.random()
            if prod <= l:
                return k
            k += 1

    # -- 120 语义映射单元 ---------------------------------------------------
    def map_to_vss(self, raw: Dict[str, float]) -> Dict[str, dict]:
        """映射为 VSS 标准化信号, 并附加元数据标注(量程/单位/敏感等级)。"""
        out: Dict[str, dict] = {}
        for raw_name, value in raw.items():
            node = vss.map_raw_signal(raw_name)
            if node is None:
                continue                      # 未登记信号直接丢弃
            out[node.path] = {
                "value": value,
                "unit": node.unit,
                "range": [node.physical_min, node.physical_max],
                "sensitivity": node.sensitivity,
            }
        return out

    # -- 130 本地预处理单元 -------------------------------------------------
    def static_desensitize(self, signals: Dict[str, dict]) -> Dict[str, dict]:
        """静态脱敏: VIN 后 8 位替换为哈希; GPS 坐标精度降至 100 m。"""
        s = {k: dict(v) for k, v in signals.items()}
        vin_path = "Vehicle.VehicleIdentification.VIN"
        if vin_path in s:
            vin = str(s[vin_path]["value"])
            s[vin_path]["value"] = vin[:9] + sha256_hex(vin.encode())[:8].upper()
        # 1 度纬度 ≈ 111320 m, 按 100 m 栅格量化
        step_lat = self.STATIC_MASK_GPS_M / 111320.0
        for path, key in (("Vehicle.CurrentLocation.Latitude", step_lat),
                          ("Vehicle.CurrentLocation.Longitude", step_lat)):
            if path in s:
                s[path]["value"] = round(s[path]["value"] / key) * key
        return s

    def local_dp(self, signals: Dict[str, dict], eps_local: float) -> Dict[str, dict]:
        """
        本地差分隐私扰动: 对每个数值维度按其物理量程归一化后加拉普拉斯噪声。
        单条记录的归一化敏感度为 1, 故噪声尺度 b = 1/eps_local。
        eps_local <= 0 表示关闭本地 DP。
        """
        if eps_local <= 0:
            return signals
        s = {k: dict(v) for k, v in signals.items()}
        paths = [p for p in s if vss.get(p).type == "sensor"]
        w = vss.sensitivity_weights(paths)          # 车端同样按敏感等级分配
        for p in paths:
            node = vss.get(p)
            eps_i = max(w[p] * eps_local, 1e-6)
            xn = node.normalize(s[p]["value"])
            xn += laplace_sample(1.0 / eps_i, self.rng)
            s[p]["value"] = node.denormalize(min(max(xn, 0.0), 1.0))
        return s

    # -- 车云通信: ECDH 会话建立 + QUIC 0-RTT --------------------------------
    def handshake(self, cloud_pub) -> str:
        """与云端连接器完成 ECDH 密钥协商, 生成会话密钥与 0-RTT 会话票据。"""
        shared = self.keys.ecdh(cloud_pub)
        self.session_key = hkdf(shared, salt=b"ALC-v1", info=b"vehicle-cloud", length=64)
        self.session_ticket = sha256_hex(self.session_key + b"ticket")[:32]
        return self.session_ticket

    def resume_0rtt(self) -> bool:
        """QUIC 0-RTT 会话恢复: 凭票据免完整握手, 首包即携带业务数据。"""
        return self.session_ticket is not None

    def upload(self, eps_local: float = 0.0, tamper: bool = False) -> dict:
        """
        完成一次采集->映射->脱敏->扰动->加密的完整上传。
        tamper=True 用于演示实施例一的完整性校验能检出篡改。
        """
        if self.session_key is None:
            raise RuntimeError("尚未完成 ECDH 握手")
        raw = self.collect_raw()
        signals = self.map_to_vss(raw)
        signals = self.static_desensitize(signals)
        signals = self.local_dp(signals, eps_local)
        self.seq += 1
        payload = {
            "vin_hash": sha256_hex(self.p.vin.encode())[:16],
            "oem": self.p.oem,
            "seq": self.seq,
            "signals": signals,
        }
        pt = json.dumps(payload, ensure_ascii=False).encode()
        aad = f"{self.p.oem}|{self.seq}".encode()
        pkt = aead_encrypt(self.session_key, pt, aad)
        if tamper:                                   # 翻转密文首字节模拟中间人篡改
            pkt = dict(pkt)
            pkt["ct"] = bytes([pkt["ct"][0] ^ 0xFF]) + pkt["ct"][1:]
        return {"aad": aad, "pkt": pkt, "pub": self.keys.pub, "oem": self.p.oem,
                "vin_hash": payload["vin_hash"], "seq": self.seq}


# ---------------------------------------------------------------------------
# 车队工厂: 构造三家车企具有差异化数据分布的车队
#   车企A: 城市/高速/山区多工况 -> 分布多样, 熵高
#   车企B: 中等多样性
#   车企C: 同城网约车通勤 -> 工况高度同质, 熵低(对应实施例六搭便车场景)
# ---------------------------------------------------------------------------
FLEET_SPEC = {
    "车企A": dict(base=42.0, sigma=26.0, brake=3.2, soh=96.5, lat=39.90, lon=116.40),
    "车企B": dict(base=45.0, sigma=18.0, brake=3.6, soh=95.2, lat=31.23, lon=121.47),
    "车企C": dict(base=31.0, sigma=5.0,  brake=4.8, soh=93.8, lat=23.13, lon=113.26),
}


def build_fleet(oem: str, n: int, seed: int = 42) -> List[VehicleAgent]:
    spec = FLEET_SPEC[oem]
    rng = random.Random(seed + hash(oem) % 10000)
    agents = []
    for i in range(n):
        prof = VehicleProfile(
            vin=f"LSV{oem[-1]}{i:08d}A{rng.randint(100, 999)}",
            oem=oem,
            base_speed=max(5.0, rng.gauss(spec["base"], 4.0)),
            speed_sigma=max(1.0, rng.gauss(spec["sigma"], 2.0)),
            brake_lambda=max(0.2, rng.gauss(spec["brake"], 0.8)),
            soh=max(60.0, min(100.0, rng.gauss(spec["soh"], 2.0))),
            mileage=max(1000.0, rng.gauss(58000.0, 22000.0)),
            lat=spec["lat"] + rng.gauss(0, 0.05),
            lon=spec["lon"] + rng.gauss(0, 0.05),
        )
        agents.append(VehicleAgent(prof, seed=seed * 1000 + i))
    return agents
