"""
pipeline.py -- 案例编排器

复现贯穿案例:
  保险机构P 以"UBI保费定价"为目的发起一次数据使用请求, 含两个子任务:
    子任务A: 统计查询   —— 车企A车队 2026年6月 三维统计量, 延迟约束 5 秒
    子任务B: 联合建模   —— 车企A/B/C 三方联邦训练驾驶风险评分模型, T 轮
  请求依次流经 210 -> 220 -> 230 -> 240 -> 250 -> 260 -> 270 七个模块。
"""
from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from . import vss
from .m210_ingestion import DataAsset, IngestionModule
from .m220_policy import (AccessRequest, PolicyEngine, PRECISION_EPS,
                          build_default_policies)
from .m230_budget import BudgetLedger
from .m240_scheduler import Scheduler, TaskFeature
from .m250_sandbox import (DHPSI, DPEngine, FederatedLearning, SecretSharing,
                           TEEEnclave, make_client_data)
from .m260_contribution import ContributionSettlement, SmartContract
from .m270_audit import AuditModule, ZKAuditor
from .vehicle_agent import build_fleet


@dataclass
class Config:
    """可在 UI 中调整的运行参数。"""
    fleet_a: int = 200          # 车队规模(每车一次 ECDH 握手, 约 14ms)
    fleet_b: int = 120
    fleet_c: int = 80
    batches: int = 50           # 每车上传批次; 记录数 = 车队规模 × 批次
    eps_local: float = 1.0            # 车端本地 DP 预算; 0 表示关闭
    eps_total: float = 8.0
    delta: float = 1e-5
    history_rounds: int = 150         # 资产历史已消耗轮数
    precision_level: int = 2
    include_mileage: bool = True      # 是否纳入累计里程维(演示量纲混叠)
    fl_rounds: int = 100
    fl_dim: int = 8
    fl_samples: int = 300
    lam: float = 0.5
    gamma: float = 3.0
    theta_th: float = 120.0
    beta: float = 0.8
    eta: float = 0.002
    poison_rounds: List[int] = field(default_factory=lambda: [37, 52])
    zk_max_commit: int = 128
    seed: int = 20260701
    query_date: str = "2026-07-01"


class Pipeline:
    """七模块贯穿案例编排器。"""

    ASSET_A = "ASSET-A-M-202606"

    def __init__(self, cfg: Optional[Config] = None,
                 on_log: Optional[Callable[[str], None]] = None):
        self.cfg = cfg or Config()
        self.on_log = on_log or (lambda s: None)
        self.audit = AuditModule()
        self.ingestion = IngestionModule(audit=self.audit)
        self.policy = PolicyEngine(audit=self.audit)
        self.ledger = BudgetLedger(self.cfg.eps_total, self.cfg.delta, audit=self.audit)
        self.scheduler = Scheduler(audit=self.audit)
        self.contribution = ContributionSettlement(
            lam=self.cfg.lam, gamma=self.cfg.gamma, theta_th_deg=self.cfg.theta_th,
            beta=self.cfg.beta, eta=self.cfg.eta, audit=self.audit)
        self.contract = SmartContract(self.ASSET_A, daily_limit=1, audit=self.audit)
        self.results: Dict[str, object] = {}
        self.fleets: Dict[str, list] = {}

    def _log(self, msg: str):
        self.on_log(msg)

    # -- 模块 210 ------------------------------------------------------------
    def step_ingestion(self) -> dict:
        c = self.cfg
        self._log("【210 数据接入模块】ECDH 握手 -> QUIC 0-RTT 上传 -> 三级校验 -> 落库")
        t0 = time.time()
        for oem, n, aid in (("车企A", c.fleet_a, self.ASSET_A),
                            ("车企B", c.fleet_b, "ASSET-B-M-202606"),
                            ("车企C", c.fleet_c, "ASSET-C-M-202606")):
            fleet = build_fleet(oem, n, seed=c.seed)
            self.fleets[oem] = fleet
            self.ingestion.run_pipeline(
                fleet, aid, oem, "2026-06", eps_local=c.eps_local,
                batches=c.batches, inject_faults=(oem == "车企A"))
        asset = self.ingestion.assets[self.ASSET_A]
        out = {
            "assets": {k: v.record_count for k, v in self.ingestion.assets.items()},
            "stats": dict(self.ingestion.stats),
            "quarantine": self.ingestion.quarantine[:6],
            "asset": asset, "elapsed": time.time() - t0,
            "cloud_pub": self.ingestion.keys.pub_hex()[:34] + "…",
        }
        for line in self.ingestion.log:
            self._log("  " + line)
        self._log(f"  隔离区样例: " + "; ".join(q["reason"] for q in out["quarantine"][:3]))
        self.results["ingestion"] = out
        return out

    # -- 模块 220 ------------------------------------------------------------
    def step_policy(self) -> dict:
        self._log("【220 策略引擎】五元组匹配 -> 脱敏执行计划")
        for p in build_default_policies():
            self.policy.define(p)
        paths = self._query_paths() + ["Vehicle.CurrentLocation.Latitude",
                                       "Vehicle.VehicleIdentification.VIN"]
        req = AccessRequest(
            requester="保险机构P", subject_role="保险精算类机构", purpose="UBI保费定价",
            date_from="2026-06-01", date_to="2026-06-30", lat=39.91, lon=116.41,
            precision_level=self.cfg.precision_level, asset_id=self.ASSET_A,
            task_type="statistics", signal_paths=paths, latency_budget_s=5.0)
        d = self.policy.evaluate(req)
        # 对照场景: 越权请求(超出时间窗与围栏)
        bad = AccessRequest(
            requester="保险机构P", subject_role="保险精算类机构", purpose="UBI保费定价",
            date_from="2026-05-01", date_to="2026-07-31", lat=31.23, lon=121.47,
            precision_level=1, asset_id=self.ASSET_A, task_type="statistics",
            signal_paths=paths)
        d_bad = self.policy.evaluate(bad)
        for line in self.policy.log:
            self._log("  " + line)
        out = {"request": req, "decision": d, "denied_demo": d_bad}
        self.results["policy"] = out
        return out

    def _query_paths(self) -> List[str]:
        paths = ["Vehicle.Speed", "Vehicle.Chassis.Brake.EventsPerWeek",
                 "Vehicle.Powertrain.Battery.StateOfHealth"]
        if self.cfg.include_mileage:
            paths.append("Vehicle.TraveledDistance")
        return paths

    # -- 模块 230 ------------------------------------------------------------
    def step_budget(self) -> dict:
        c = self.cfg
        self._log("【230 隐私预算账本】RDP 组合会计 + α 寻优 + 准入判决")
        eps_q = PRECISION_EPS[c.precision_level]
        self.ledger.preload(self.ASSET_A, c.history_rounds, eps_q)
        d = self.ledger.evaluate(self.ASSET_A, eps_q, n_rounds=1)
        n_rdp, n_lin = self.ledger.max_rounds_under_budget(eps_q)
        # 降级演示: 把历史推到临界点
        probe = BudgetLedger(c.eps_total, c.delta)
        probe.preload(self.ASSET_A, c.history_rounds + 60, eps_q)
        d_over = probe.evaluate(self.ASSET_A, eps_q, n_rounds=1)
        if d.admitted:
            self.ledger.commit(self.ASSET_A, eps_q, 1)
        for line in self.ledger.log:
            self._log("  " + line)
        self._log(f"  预算利用率: RDP 可支撑 {n_rdp} 轮 vs 线性叠加 {n_lin} 轮 "
                  f"(提升 {n_rdp / max(n_lin, 1):.2f}×)")
        out = {"decision": d, "eps_q": eps_q, "n_rdp": n_rdp, "n_linear": n_lin,
               "degrade_demo": d_over}
        self.results["budget"] = out
        return out

    # -- 模块 240 ------------------------------------------------------------
    def step_schedule(self) -> dict:
        c = self.cfg
        self._log("【240 隐私计算调度】任务特征 -> 候选剪枝 -> 代价函数选优")
        eps_rem = self.results["budget"]["decision"].eps_remaining
        n = self.ingestion.assets[self.ASSET_A].record_count
        fa = TaskFeature("statistics", 5.0, 1, n, len(self._query_paths()),
                         eps_rem, 0.3, rounds=1)
        mode_a, ests_a = self.scheduler.schedule(fa)
        fb = TaskFeature("fl_training", 86400.0, 3,
                         c.fl_samples * 3, c.fl_dim, eps_rem, 0.3, rounds=c.fl_rounds)
        mode_b, ests_b = self.scheduler.schedule(fb)
        fc = TaskFeature("psi", 3600.0, 3, 2000, 1, eps_rem, 0.3, rounds=1)
        mode_c, ests_c = self.scheduler.schedule(fc)
        for line in self.scheduler.log:
            self._log("  " + line)
        out = {"A": (mode_a, ests_a, fa), "B": (mode_b, ests_b, fb),
               "C": (mode_c, ests_c, fc)}
        self.results["schedule"] = out
        return out

    # -- 模块 250 ------------------------------------------------------------
    def step_sandbox(self, progress=None) -> dict:
        c = self.cfg
        self._log("【250 隐私计算沙箱】维度级 DP 查询 / 联邦学习 / MPC / TEE")
        # 子任务A: 维度级差分隐私统计查询
        d = self.results["policy"]["decision"]
        paths = self._query_paths()
        cols = {}
        for p in paths:
            raw = self.ingestion.column(self.ASSET_A, p)
            op = d.plan.get(p, {"op": "pass"})
            cols[p] = [self.policy.apply_operator(p, v, op) for v in raw]
        eng = DPEngine(random.Random(c.seed))
        dp = eng.mean_query(cols, self.results["budget"]["eps_q"])
        u = dp.utility()
        self._log(f"  子任务A: {dp.n_records} 条记录, ε_q={dp.eps_q}, "
                  f"平均归一化误差 {u['mean_norm_std']*100:.4f}% "
                  f"vs 现有技术 {u['base_norm_std']*100:.4f}% (增益 {u['gain']:.2f}×)")

        # 子任务B: TEE 内安全聚合的联邦学习
        enclave = TEEEnclave()
        quote = enclave.remote_attest("nonce-20260701")
        attested = quote.verify(TEEEnclave.EXPECTED_MRENCLAVE)
        self._log(f"  TEE 远程证明: {'通过' if attested else '失败'} "
                  f"(MRENCLAVE {quote.mrenclave[:16]}…)")
        clients = [
            make_client_data("车企A", c.fl_samples, 1.30, c.seed + 1, c.fl_dim),
            make_client_data("车企B", c.fl_samples, 0.95, c.seed + 2, c.fl_dim),
            make_client_data("车企C", c.fl_samples, 0.28, c.seed + 3, c.fl_dim),
        ]
        for cl in clients:
            self.contribution.register(cl.oem, cl.X)
        fl = FederatedLearning(c.fl_dim, lr=0.6, seed=c.seed)
        rounds = fl.train(clients, T=c.fl_rounds,
                          poison_plan={"车企C": list(c.poison_rounds)},
                          progress=progress)
        # 逐轮将梯度范数与余弦相似度等贡献度中间量纳入存证体系
        for r in rounds:
            self.audit.record("fl_round", {
                "round": r.t,
                "norms": {k: round(v, 6) for k, v in r.grad_norms.items()},
                "cosines": {k: round(v, 6) for k, v in r.cosines.items()},
                "loss": round(r.global_loss, 6)})
        acc = fl.accuracy(clients)
        self._log(f"  子任务B: 联邦训练 {c.fl_rounds} 轮完成, 全局准确率 {acc*100:.2f}%, "
                  f"末轮损失 {rounds[-1].global_loss:.4f}")

        # MPC: 秘密分享精确求和 + DH-PSI
        sample = self.ingestion.column(self.ASSET_A, "Vehicle.Speed")[:60]
        mpc_sum, plain_sum = SecretSharing.secure_sum(sample, seed=c.seed)
        set_a = [f"CUST{i:05d}" for i in range(300)]
        set_b = [f"CUST{i:05d}" for i in range(200, 500)]
        t0 = time.time()
        inter, ops = DHPSI.run(set_a, set_b)
        self._log(f"  MPC 秘密分享求和误差 {abs(mpc_sum - plain_sum):.2e}; "
                  f"DH-PSI 交集 {len(inter)} 个, {ops} 次群运算, {time.time()-t0:.2f}s")

        out = {"dp": dp, "utility": u, "fl": fl, "rounds": rounds, "clients": clients,
               "accuracy": acc, "attested": attested, "quote": quote,
               "mpc": (mpc_sum, plain_sum), "psi": (len(inter), ops)}
        self.results["sandbox"] = out
        return out

    # -- 模块 260 ------------------------------------------------------------
    def step_contribution(self) -> dict:
        self._log("【260 贡献度结算】熵权 + 方向一致性 + 异常检测 + 合约分账")
        rounds = self.results["sandbox"]["rounds"]
        for r in rounds:
            self.contribution.process_round(r.t, r.grad_norms, r.cosines)
        n = self.ingestion.assets[self.ASSET_A].record_count
        total = self.contract.price(n, self.cfg.precision_level, months=1)
        ok, msg = self.contract.check_usage("保险机构P", self.cfg.query_date)
        rows = self.contribution.settle(total)
        payouts = self.contract.distribute(rows, total)
        ok2, msg2 = self.contract.check_usage("保险机构P", self.cfg.query_date)
        for line in self.contribution.log[-8:]:
            self._log("  " + line)
        self._log(f"  合约: {msg} | 同日二次请求: {msg2}")
        out = {"rows": rows, "total": total, "payouts": payouts,
               "usage_first": (ok, msg), "usage_second": (ok2, msg2)}
        self.results["contribution"] = out
        return out

    # -- 模块 270 ------------------------------------------------------------
    def step_audit(self) -> dict:
        c = self.cfg
        self._log("【270 审计存证】Merkle 组树 -> 链上锚定 -> 零知识证明")
        dp = self.results["sandbox"]["dp"]
        proofs = []
        for i, dim in enumerate(dp.dims):
            col = self.ingestion.column(self.ASSET_A, dim.path)
            noise = dim.noisy_value - dim.true_value
            p = ZKAuditor.prove_aggregate(
                values=col, noise=noise * len(col), z=sum(col) + noise * len(col),
                dimension=dim.name, eps_i=dim.eps_i, delta_f=1.0 / len(col),
                u_seed=dp.seeds[i], max_commit=c.zk_max_commit)
            self.audit.add_zk_proof(p)
            proofs.append((p, ZKAuditor.verify(p)))
        batch = self.audit.anchor_batch("2026-07-01 11时批次")
        idx = max(0, len(self.audit.records) - 5)
        mp = self.audit.prove_record(idx)
        tamper = self.audit.tamper_test(idx)
        summ = self.audit.summary()
        self._log(f"  Merkle 批次: {batch['count']} 条记录, 树高 {batch['height']}, "
                  f"根 {batch['root'][:16]}… 锚定至区块 #{batch['block'].height}")
        self._log(f"  单条记录证明: 路径 {mp['path_bytes']} 字节, 验证 "
                  f"{'通过' if mp['verified'] else '失败'}; 篡改检出 "
                  f"{'成功' if tamper['detected'] else '失败'}")
        for p, (ok, _) in proofs:
            self._log(f"  ZK[{p.dimension}]: {'通过' if ok else '失败'}, "
                      f"生成 {p.gen_ms:.0f}ms, 约 {ZKAuditor.size_bytes(p)} 字节")
        out = {"batch": batch, "merkle_proof": mp, "tamper": tamper,
               "zk": proofs, "summary": summ, "chain": self.audit.chain}
        self.results["audit"] = out
        return out

    # -- 全流程 --------------------------------------------------------------
    def run_all(self, progress=None) -> Dict[str, object]:
        t0 = time.time()
        self.step_ingestion()
        self.step_policy()
        self.step_budget()
        self.step_schedule()
        self.step_sandbox(progress=progress)
        self.step_contribution()
        self.step_audit()
        self.results["elapsed"] = time.time() - t0
        self._log(f"\n===== 案例执行完毕, 总耗时 {self.results['elapsed']:.2f}s =====")
        return self.results
