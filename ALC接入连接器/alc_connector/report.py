"""report.py -- 运行报告生成 (UI 导出与 CLI 模式共用)"""
from __future__ import annotations

from . import vss
from .m230_budget import laplace_rdp
from .m270_audit import ZKAuditor


def _hr(title: str) -> str:
    return f"\n{'=' * 78}\n{title}\n{'=' * 78}\n"


def build_report(pl) -> str:
    r = pl.results
    o = ["车云两级数据可信空间接入连接器-报告",
         f"配置: 车队 A/B/C = {pl.cfg.fleet_a}/{pl.cfg.fleet_b}/{pl.cfg.fleet_c}, "
         f"批次 {pl.cfg.batches}, 联邦轮数 {pl.cfg.fl_rounds}, "
         f"精度等级 {pl.cfg.precision_level}",
         f"总耗时: {r.get('elapsed', 0):.2f}s"]

    # 210
    ing = r["ingestion"]
    o.append(_hr("模块 210  数据接入"))
    for aid, cnt in ing["assets"].items():
        st = pl.ingestion.per_asset.get(aid, {})
        o.append(f"  {aid}: {cnt} 条记录, 接收 {st.get('accepted',0)}, "
                 f"隔离 {st.get('rejected',0)} "
                 f"(标签{st.get('mac',0)}/重放{st.get('replay',0)}/模式{st.get('schema',0)})")
    o.append("  隔离区样例:")
    for q in pl.ingestion.quarantine[:4]:
        o.append(f"    - {q['reason']}")

    # 220
    d = r["policy"]["decision"]
    o.append(_hr("模块 220  策略引擎"))
    o.append(f"  命中策略: {d.policy_id}, 哈希 {d.policy_hash[:32]}…, ε_q={d.eps_q}")
    for x in d.reasons:
        o.append(f"    {x}")
    o.append("  脱敏执行计划:")
    for path, op in d.plan.items():
        o.append(f"    {path} -> {op['op']} {op.get('grid','')}")
    for path in d.denied_paths:
        o.append(f"    {path} -> suppress (拦截)")

    # 230
    b = r["budget"]
    bd = b["decision"]
    o.append(_hr("模块 230  隐私预算账本 (Rényi 组合会计)"))
    o.append(f"  历史 {pl.cfg.history_rounds} 轮 + 本次 1 轮 @ ε_q={b['eps_q']}")
    o.append(f"  寻优阶数 α* = {bd.alpha_star:.4f}")
    o.append(f"  单轮 ε_RDP(α*) = {laplace_rdp(bd.alpha_star, 1/b['eps_q']):.6f}")
    o.append(f"  组合隐私损失 ε_composed = {bd.eps_composed:.4f}  (总预算 {bd.eps_total})")
    o.append(f"  线性叠加对照 = {bd.linear_eps:.4f}  → 早已超限")
    o.append(f"  准入判定: {'通过' if bd.admitted else '拒绝'}, 剩余 {bd.eps_remaining:.4f}")
    o.append(f"  可支撑轮数: RDP {b['n_rdp']} 轮 vs 线性 {b['n_linear']} 轮 "
             f"(提升 {b['n_rdp']/max(b['n_linear'],1):.2f}×)")
    od = b["degrade_demo"]
    if od.degradation:
        o.append(f"  降级演示: ε_composed={od.eps_composed:.4f} 超限 → "
                 f"[{od.degradation.kind}] {od.degradation.desc}")

    # 240
    o.append(_hr("模块 240  隐私计算模式自适应调度"))
    for key, name in [("A", "子任务A 统计查询"), ("B", "子任务B 联邦建模"),
                      ("C", "追加任务 隐私求交")]:
        mode, ests, feat = r["schedule"][key]
        o.append(f"  {name}: 特征(τ={feat.task_type}, T_max={feat.latency_budget_s}s, "
                 f"n={feat.participants}, V={feat.data_scale}, "
                 f"ε_rem={feat.eps_remaining:.3f}) → 选定 {mode}")
        for e in ests:
            flag = "★" if e.mode == mode else " "
            o.append(f"    {flag} {e.mode:4} 可行={'是' if e.feasible else '否'} "
                     f"时延={e.latency_s:8.2f}s 通信={e.comm_mb:9.2f}MB "
                     f"cost={e.cost:.4f} {e.reason}")

    # 250
    s = r["sandbox"]
    dp, u = s["dp"], s["utility"]
    o.append(_hr("模块 250  隐私计算沙箱"))
    o.append(f"  [子任务A] 维度级差分隐私统计查询  记录数={dp.n_records}, ε_q={dp.eps_q}")
    o.append(f"  {'维度':<18}{'s':>3}{'w_i':>8}{'ε_i':>9}{'真实值':>12}"
             f"{'加噪输出':>12}{'本系统%':>11}{'现有技术%':>13}")
    for x in dp.dims:
        o.append(f"  {x.name:<18}{x.sensitivity:>3}{x.weight:>8.3f}{x.eps_i:>9.4f}"
                 f"{x.true_value:>12.3f}{x.noisy_value:>12.3f}"
                 f"{x.norm_std*100:>11.4f}{x.baseline_norm_std*100:>13.4f}")
    o.append(f"  平均归一化误差: 本系统 {u['mean_norm_std']*100:.4f}% vs "
             f"现有技术 {u['base_norm_std']*100:.4f}% → 效用增益 {u['gain']:.2f}×")
    o.append(f"  最坏维度增益: {u['worst_gain']:.2f}×")
    o.append(f"  [子任务B] 联邦学习 {pl.cfg.fl_rounds} 轮, 准确率 {s['accuracy']*100:.2f}%, "
             f"末轮损失 {s['rounds'][-1].global_loss:.6f}")
    o.append(f"  TEE 远程证明: {'通过' if s['attested'] else '失败'}")
    mpc, plain = s["mpc"]
    o.append(f"  MPC 秘密分享: 求和 {mpc:.6f} vs 明文 {plain:.6f}, 误差 {abs(mpc-plain):.2e}")
    o.append(f"  DH-PSI: 交集 {s['psi'][0]} 个, {s['psi'][1]} 次群运算")

    # 260
    c = r["contribution"]
    o.append(_hr("模块 260  双因子贡献度量化与合约结算"))
    o.append(f"  参数: λ={pl.cfg.lam}, γ={pl.cfg.gamma}, θ_th={pl.cfg.theta_th}°, "
             f"β={pl.cfg.beta}, η={pl.cfg.eta}")
    o.append(f"  {'参与方':<8}{'H_i':>9}{'Φ_i':>9}{'rep_i':>9}{'C_i':>9}"
             f"{'Ĉ_i':>9}{'分账(元)':>14}{'现有技术Ĉ':>12}  异常轮次")
    for x in c["rows"]:
        o.append(f"  {x.oem:<8}{x.entropy:>9.4f}{x.phi:>9.4f}{x.reputation:>9.4f}"
                 f"{x.contribution:>9.4f}{x.normalized:>9.4f}{x.payout:>14,.2f}"
                 f"{x.baseline_normalized:>12.4f}  "
                 f"{','.join(map(str, x.anomaly_rounds)) or '无'}")
    o.append(f"  任务总费用: {c['total']:,.2f} 元")
    o.append(f"  合约限额: {c['usage_first'][1]} | 同日二次: {c['usage_second'][1]}")

    # 270
    a = r["audit"]
    bt, mp, summ = a["batch"], a["merkle_proof"], a["summary"]
    o.append(_hr("模块 270  Merkle 锚定存证与零知识审计"))
    o.append(f"  存证记录 {summ['records']} 条, 类型: {', '.join(summ['kinds'])}")
    o.append(f"  Merkle 批次 {bt['count']} 条, 树高 {bt['height']}, "
             f"根 {bt['root'][:32]}…")
    o.append(f"  锚定区块 #{bt['block'].height}, 链完整性 "
             f"{'通过' if summ['chain_valid'] else '失败'}")
    o.append(f"  单条记录 Merkle 证明: {mp['path_bytes']} 字节, "
             f"验证 {'通过' if mp['verified'] else '失败'}")
    o.append(f"  篡改检测: {'成功检出' if a['tamper']['detected'] else '未检出'}")
    o.append("  零知识证明 (Pedersen 承诺 + Fiat-Shamir Schnorr NIZK):")
    for p, (ok, msgs) in a["zk"]:
        o.append(f"    [{p.dimension}] 验证={'通过' if ok else '失败'}, "
                 f"生成 {p.gen_ms:.0f}ms, 约 {ZKAuditor.size_bytes(p)} 字节, "
                 f"登记 ε_i={p.eps_i:.4f}")
    o.append("  说明: 已实现加性关系零知识证明; 噪声分布合规性的完整")
    o.append("        zk-SNARK 电路验证超出轻量实现范畴, 已预留参数承诺接口。")
    return "\n".join(o)
