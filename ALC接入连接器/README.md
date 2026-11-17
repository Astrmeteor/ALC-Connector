# ALC 接入连接器 — 源码目录

车云两级数据可信空间接入连接器的源码。完整的中英文双语说明见仓库根目录的 [README.md](../README.md)。

## 运行

```bash
python run.py              # 图形界面（需 tkinter）
python run.py --cli        # 命令行跑贯穿案例并打印报告
python run.py --cli -o 报告.txt
python run.py --selftest   # 数学自检（49 项）
```

仅需 Python 3.8+ 标准库，无第三方依赖。

## 模块

| 模块 | 职责 |
|---|---|
| `crypto_lite.py` | secp256r1 ECDH、HKDF-SHA256、AEAD、Pedersen 承诺、Schnorr NIZK、DH-PSI |
| `vss.py` | VSS 语义树 + 隐私敏感等级 overlay |
| `vehicle_agent.py` | 车端轻量数据代理 |
| `m210_ingestion.py` | 数据接入 (210) |
| `m220_policy.py` | 基于属性的动态脱敏策略引擎 (220) |
| `m230_budget.py` | 隐私预算账本 / RDP 组合会计 (230) |
| `m240_scheduler.py` | 隐私计算模式自适应调度 (240) |
| `m250_sandbox.py` | 隐私计算沙箱：DP / MPC / FL / TEE (250) |
| `m260_contribution.py` | 双因子贡献度量化与合约结算 (260) |
| `m270_audit.py` | Merkle 锚定存证与零知识审计 (270) |
| `pipeline.py` | 贯穿案例编排（七模块闭环） |
| `ui.py` | Tkinter 图形界面（8 个标签页） |
| `report.py` | 运行报告生成 |
| `selftest.py` | 数学实现自检（49 项） |

## 设计公式对照

| 公式 | 实现位置 |
|---|---|
| 式(2) 逐维归一化 | `vss.VSSNode.normalize` |
| 式(3) 归一化敏感度 | `m250_sandbox.DPEngine.mean_query` |
| 式(4) 敏感度权重 | `vss.sensitivity_weights` |
| 式(5) 预算分配 | `m250_sandbox.DPEngine.mean_query` |
| 式(6) 拉普拉斯加噪（逆 CDF） | `vehicle_agent.laplace_inv_cdf` |
| 式(7) 拉普拉斯机制 RDP 损失 | `m230_budget.laplace_rdp` |
| 式(8) RDP → (ε,δ)-DP 转换与组合 | `m230_budget.compose` / `rdp_to_dp` |
| 式(9) 调度代价 | `m240_scheduler.Scheduler.schedule` |
| 式(10) 归一化信息熵 | `m260_contribution.normalized_entropy` |
| 式(11) 梯度方向一致性 | `m250_sandbox.cosine_similarity` |
| 式(12) 截断累计 | `m260_contribution.Participant.phi` |
| 式(13) 双因子融合与归一化 | `m260_contribution.ContributionSettlement.settle` |
| 式(14) 异常检测与信誉衰减 | `m260_contribution.ContributionSettlement.process_round` |
| 式(15) 加噪合规性零知识证明 | `m270_audit.ZKAuditor` |

## 说明

TEE 为软件模拟、区块链为哈希链模拟；零知识证明覆盖式(15)的加性关系部分。详见根目录 README 的「诚实的边界说明」。
