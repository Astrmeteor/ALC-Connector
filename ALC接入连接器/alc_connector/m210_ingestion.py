"""
m210_ingestion.py -- 数据接入模块 (图2 模块 210)

模块说明:
  接收单元      : 维持 QUIC 连接, 支持 0-RTT 会话恢复
  解密单元      : ECDH 会话密钥解密
  完整性校验单元: 三级校验 ① 认证标签/来源 ② 时间戳与单调序列号防重放 ③ VSS 模式与量程校验
  格式落库单元  : 按 VSS 语义路径结构化落库 + 元数据目录登记 + 数据资产上链
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import vss
from .crypto_lite import ECKeyPair, aead_decrypt, hkdf, sha256_hex


@dataclass
class DataAsset:
    """元数据目录中的数据资产条目 (实施例一)。"""
    asset_id: str
    oem: str
    period: str
    record_count: int = 0
    allowed_computations: List[str] = field(default_factory=lambda: ["DP", "FL", "MPC", "TEE"])
    max_precision_level: int = 2      # 允许的最高精度等级(数值越小精度越高)
    daily_usage_limit: int = 1
    price_base: float = 100000.0
    signal_paths: List[str] = field(default_factory=list)

    def rule_hash(self) -> str:
        return sha256_hex(json.dumps({
            "asset": self.asset_id, "comp": self.allowed_computations,
            "prec": self.max_precision_level, "limit": self.daily_usage_limit,
        }, sort_keys=True).encode())


class IngestionModule:
    """数据接入模块。"""

    def __init__(self, audit=None):
        self.keys = ECKeyPair()                        # 云端 ECC 密钥对
        self.sessions: Dict[str, bytes] = {}           # oem -> session_key
        self.store: Dict[str, List[dict]] = {}         # asset_id -> 结构化记录
        self.assets: Dict[str, DataAsset] = {}
        self.quarantine: List[dict] = []               # 校验失败的隔离区
        self.stats = {"accepted": 0, "rejected": 0, "replay": 0, "schema": 0, "mac": 0}
        self.per_asset: Dict[str, Dict[str, int]] = {}   # 按资产分别统计
        self.audit = audit
        self.log: List[str] = []
        self._seen_seq: Dict[str, int] = {}            # 防重放: 每车最大已见序列号

    # -- 会话建立 ------------------------------------------------------------
    def handshake_with(self, agent) -> str:
        ticket = agent.handshake(self.keys.pub)
        shared = self.keys.ecdh(agent.keys.pub)
        self.sessions[agent.p.vin] = hkdf(shared, salt=b"ALC-v1",
                                          info=b"vehicle-cloud", length=64)
        return ticket

    # -- 三级完整性校验 ------------------------------------------------------
    def _verify_and_decrypt(self, envelope: dict, vin: str) -> Optional[dict]:
        key = self.sessions.get(vin)
        if key is None:
            return None
        # 校验① 认证标签(来源真实性 + 传输完整性)
        try:
            pt = aead_decrypt(key, envelope["pkt"], envelope["aad"])
        except ValueError as e:
            self.stats["mac"] += 1
            self.quarantine.append({"vin": vin, "reason": f"校验①失败: {e}"})
            return None
        payload = json.loads(pt.decode())
        # 校验② 单调序列号防重放
        last = self._seen_seq.get(vin, 0)
        if payload["seq"] <= last:
            self.stats["replay"] += 1
            self.quarantine.append({"vin": vin, "reason": f"校验②失败: 序列号重放 seq={payload['seq']}"})
            return None
        self._seen_seq[vin] = payload["seq"]
        # 校验③ VSS 模式校验: 元数据完备性 + 物理量程越界
        for path, sig in payload["signals"].items():
            if path not in vss.CATALOG:
                self.stats["schema"] += 1
                self.quarantine.append({"vin": vin, "reason": f"校验③失败: 未登记 VSS 节点 {path}"})
                return None
            node = vss.CATALOG[path]
            if node.type != "sensor":
                continue
            if not all(k in sig for k in ("value", "unit", "range", "sensitivity")):
                self.stats["schema"] += 1
                self.quarantine.append({"vin": vin, "reason": f"校验③失败: {path} 元数据不完备"})
                return None
            v = sig["value"]
            if not (node.physical_min - 1e-9 <= v <= node.physical_max + 1e-9):
                self.stats["schema"] += 1
                self.quarantine.append(
                    {"vin": vin, "reason": f"校验③失败: {node.name}={v:g} 超出量程"
                                           f"[{node.physical_min:g},{node.physical_max:g}]"})
                return None
        return payload

    # -- 接收与落库 ----------------------------------------------------------
    def ingest(self, agent, envelope: dict, asset_id: str) -> bool:
        payload = self._verify_and_decrypt(envelope, agent.p.vin)
        if payload is None:
            self.stats["rejected"] += 1
            return False
        rec = {"vin_hash": payload["vin_hash"], "oem": payload["oem"], "seq": payload["seq"]}
        for path, sig in payload["signals"].items():
            rec[path] = sig["value"]
        self.store.setdefault(asset_id, []).append(rec)
        self.stats["accepted"] += 1
        return True

    def register_asset(self, asset: DataAsset) -> DataAsset:
        """元数据目录登记 + 智能合约使用规则上链。"""
        asset.record_count = len(self.store.get(asset.asset_id, []))
        asset.signal_paths = [p for p in vss.CATALOG
                              if vss.CATALOG[p].type == "sensor"]
        self.assets[asset.asset_id] = asset
        if self.audit:
            self.audit.record("asset_register", {
                "asset_id": asset.asset_id, "records": asset.record_count,
                "rule_hash": asset.rule_hash(),
            })
        self.log.append(f"资产登记: {asset.asset_id} 共 {asset.record_count} 条记录, "
                        f"规则哈希 {asset.rule_hash()[:16]}…")
        return asset

    def column(self, asset_id: str, path: str) -> List[float]:
        """按 VSS 路径取出一列数值, 供沙箱做统计查询。"""
        return [r[path] for r in self.store.get(asset_id, []) if path in r]

    def run_pipeline(self, agents: List, asset_id: str, oem: str, period: str,
                     eps_local: float = 0.0, batches: int = 1,
                     inject_faults: bool = True) -> DataAsset:
        """完整接入流程: 握手 -> 0-RTT 上传 -> 校验 -> 落库 -> 资产登记。"""
        t0 = time.time()
        for a in agents:
            self.handshake_with(a)
        resumed = sum(1 for a in agents if a.resume_0rtt())
        before = dict(self.stats)
        for _ in range(batches):
            for a in agents:
                self.ingest(a, a.upload(eps_local=eps_local), asset_id)
        if inject_faults and agents:
            # 演示三类校验各自的拦截能力
            bad = agents[0]
            self.ingest(bad, bad.upload(eps_local, tamper=True), asset_id)   # 校验①
            env = bad.upload(eps_local)                                       # 一条正常报文
            self.ingest(bad, env, asset_id)                                   # 首次接收: 通过
            self.ingest(bad, env, asset_id)                                   # 原样重发: 校验②拦截
            self._inject_out_of_range(bad, asset_id)                          # 校验③
        delta = {k: self.stats[k] - before.get(k, 0) for k in self.stats}
        self.per_asset[asset_id] = delta
        self.log.append(f"[{oem}] 握手 {len(agents)} 车, 0-RTT 可恢复 {resumed} 车, "
                        f"接收 {delta['accepted']} 条, 隔离 {delta['rejected']} 条 "
                        f"(标签{delta['mac']}/重放{delta['replay']}/模式{delta['schema']}), "
                        f"耗时 {time.time() - t0:.2f}s")
        asset = DataAsset(asset_id=asset_id, oem=oem, period=period)
        return self.register_asset(asset)

    def _inject_out_of_range(self, agent, asset_id: str):
        """构造一条车速 255 km/h 的越界报文 (实施例一示例)。"""
        import json as _json
        from .crypto_lite import aead_encrypt
        agent.seq += 1
        raw = agent.collect_raw()
        sig = agent.map_to_vss(raw)
        sig["Vehicle.Speed"]["value"] = 255.0
        payload = {"vin_hash": sha256_hex(agent.p.vin.encode())[:16], "oem": agent.p.oem,
                   "seq": agent.seq, "signals": sig}
        aad = f"{agent.p.oem}|{agent.seq}".encode()
        pkt = aead_encrypt(self.sessions[agent.p.vin],
                           _json.dumps(payload, ensure_ascii=False).encode(), aad)
        self.ingest(agent, {"aad": aad, "pkt": pkt, "pub": agent.keys.pub,
                            "oem": agent.p.oem, "vin_hash": payload["vin_hash"],
                            "seq": agent.seq}, asset_id)
