# 面向智能网联汽车数据可信空间的接入连接器 (AutoLink Connector, ALC)

# An Access Connector for Trusted Data Spaces of Intelligent Connected Vehicles (AutoLink Connector, ALC)

一个面向智能网联汽车数据可信空间的车云两级接入连接器：按「车端轻量代理 → 云端连接器」两级架构组织代码，核心算法按设计公式（式 1–15）实现，并配有独立的数学自检，可在无第三方依赖的环境下端到端运行。

A vehicle–cloud two-tier access connector for trusted data spaces of intelligent connected vehicles. The code follows the "vehicle-side lightweight agent → cloud-side connector" architecture; core algorithms implement the design formulas (Eq. 1–15) and are covered by independent mathematical self-tests. It runs end-to-end with no third-party dependencies.

---

## 快速开始 / Quick Start

**环境要求 / Requirements**：Python 3.8+，**无需安装任何第三方包**。Only the Python standard library — **no third-party packages required**.

```bash
python run.py              # 启动图形界面（推荐）/ launch the GUI (recommended)
python run.py --cli        # 命令行模式，直接跑贯穿案例并打印报告 / CLI: run the end-to-end case and print the report
python run.py --cli -o 报告.txt    # 报告写入文件 / write the report to a file
python run.py --selftest   # 数学实现自检（49 项）/ mathematical self-tests (49 items)
```

图形界面依赖 tkinter：Windows / macOS 官方安装包自带；Ubuntu / Debian 需 `sudo apt install python3-tk`，Fedora / RHEL 需 `sudo dnf install python3-tkinter`。没有图形环境时用 `--cli` 模式，功能完全一致。
The GUI depends on tkinter (bundled with official Windows/macOS Python); on Ubuntu/Debian run `sudo apt install python3-tk`, on Fedora/RHEL `sudo dnf install python3-tkinter`. Without a display, use `--cli` mode — identical functionality.

默认配置（10000 条记录、100 轮联邦训练、四维查询）端到端约 20 秒。
Default configuration (10,000 records, 100 federated-training rounds, 4-D queries) runs end-to-end in about 20 seconds.

---

## 工程结构 / Engineering Structure

```
run.py                        统一入口（GUI / CLI / 自检）/ unified entry (GUI / CLI / self-test)
alc_connector/
├─ crypto_lite.py             密码学底座（纯标准库）/ cryptography foundation (stdlib only)
│                             secp256r1 ECDH、HKDF-SHA256、AEAD、
│                             Pedersen 承诺、Schnorr NIZK、DH-PSI 群运算
├─ vss.py                     VSS 语义树 + 隐私敏感等级 overlay / semantic tree + sensitivity overlay
├─ vehicle_agent.py           车端轻量数据代理 / vehicle-side lightweight agent
├─ m210_ingestion.py          数据接入模块（210）/ data ingestion module (210)
├─ m220_policy.py             基于属性的动态脱敏策略引擎（220）/ attribute-based dynamic desensitization engine (220)
├─ m230_budget.py             隐私预算账本 / RDP 组合会计（230）/ privacy budget ledger & RDP accounting (230)
├─ m240_scheduler.py          隐私计算模式自适应调度（240）/ adaptive scheduling of privacy-computing modes (240)
├─ m250_sandbox.py            隐私计算沙箱（250：DP / MPC / FL / TEE）/ privacy-computing sandbox (250)
├─ m260_contribution.py       双因子贡献度量化与合约结算（260）/ two-factor contribution & contract settlement (260)
├─ m270_audit.py              Merkle 锚定存证与零知识审计（270）/ Merkle-anchored attestation & ZK audit (270)
├─ pipeline.py                贯穿案例编排（七模块闭环）/ end-to-end case orchestration (seven-module loop)
├─ ui.py                      Tkinter 图形界面（8 个标签页）/ Tkinter GUI (8 tabs)
├─ report.py                  运行报告生成 / report generation
└─ selftest.py                数学实现自检（49 项）/ mathematical self-tests (49 items)
```

---

## 贯穿案例 / End-to-End Use Case

保险机构 P 以「UBI 保费定价」为目的发起一次数据使用请求，含两个子任务：
An insurer P issues a data-use request for UBI premium pricing, with two subtasks:

- **子任务 A / Subtask A**：统计查询 —— 车企 A 车队 2026 年 6 月的多维统计量，延迟约束 5 秒。Statistical query over OEM A's fleet for June 2026 multi-dimensional statistics, with a 5-second latency constraint.
- **子任务 B / Subtask B**：联合建模 —— 车企 A/B/C 三方联邦训练驾驶风险评分模型，100 轮。Joint modeling — three-party (OEMs A/B/C) federated training of a driving-risk scoring model, 100 rounds.

请求依次流经 **210 → 220 → 230 → 240 → 250 → 260 → 270**，形成完整闭环。车企 C 的车队为同城通勤数据（分布高度同质），并在第 37、52 轮注入异常梯度，用于演示熵权因子对搭便车的抑制与两类异常判据的检出能力。
The request flows through **210 → 220 → 230 → 240 → 250 → 260 → 270** as a complete loop. OEM C's fleet carries homogeneous urban-commute data and injects anomalous gradients at rounds 37 and 52, demonstrating entropy-weight suppression of free-riding and the two anomaly detectors.

---

## 公式实现对照 / Formula-to-Code Mapping

| 公式 / Eq. | 内容 / Content | 实现位置 / Location |
|---|---|---|
| 式(2) | 逐维归一化 x̃ᵢ = (xᵢ−minᵢ)/(maxᵢ−minᵢ) | `vss.VSSNode.normalize` |
| 式(3) | 归一化敏感度 Δf̃ᵢ = 1/\|D\| | `m250_sandbox.DPEngine.mean_query` |
| 式(4) | 权重 wᵢ = 2^(−sᵢ)/Σ2^(−sⱼ) | `vss.sensitivity_weights` |
| 式(5) | 预算分配 εᵢ = wᵢ·ε_q | `m250_sandbox.DPEngine.mean_query` |
| 式(6) | 拉普拉斯加噪（逆 CDF 法） | `vehicle_agent.laplace_inv_cdf` |
| 式(7) | 拉普拉斯机制 RDP 损失 | `m230_budget.laplace_rdp` |
| 式(8) | RDP → (ε,δ)-DP 转换与组合 | `m230_budget.compose` / `rdp_to_dp` |
| 式(9) | 调度代价 cost(m)=w₁T̂+w₂B̂+w₃L̂ | `m240_scheduler.Scheduler.schedule` |
| 式(10) | 归一化信息熵 Hᵢ | `m260_contribution.normalized_entropy` |
| 式(11) | 梯度方向一致性 φᵢᵗ | `m250_sandbox.cosine_similarity` |
| 式(12) | 截断累计 Φᵢ | `m260_contribution.Participant.phi` |
| 式(13) | 双因子融合 Cᵢ 与归一化 Ĉᵢ | `m260_contribution.ContributionSettlement.settle` |
| 式(14) | 异常检测与信誉衰减 | `m260_contribution.ContributionSettlement.process_round` |
| 式(15) | 加噪合规性零知识证明 | `m270_audit.ZKAuditor` |

---

## 密码学实现说明 / Cryptographic Implementation Notes

以下均为**真实可验证的密码学构造**，不是占位模拟。All of the following are **real, verifiable cryptographic constructions**, not placeholders:

- **ECDH 密钥协商 / Key agreement**：完整的 secp256r1（NIST P-256）仿射坐标点加/倍点/标量乘，含无效曲线点检查。Full secp256r1 (NIST P-256) affine point add/double/scalar-mult with invalid-curve point checks.
- **传输加密 / Transport encryption**：HKDF-SHA256 派生 + SHA256-CTR 流加密 + HMAC-SHA256（encrypt-then-MAC）。HKDF-SHA256 derivation + SHA256-CTR stream encryption + HMAC-SHA256 (encrypt-then-MAC).
- **Pedersen 承诺 / Commitment**：RFC 3526 MODP-2048 素数阶子群，生成元 h 以 nothing-up-my-sleeve 方式派生，保证 log_g(h) 未知；具备加法同态。RFC 3526 MODP-2048 prime-order subgroup; generator h derived nothing-up-my-sleeve so that log_g(h) is unknown; additively homomorphic.
- **零知识证明 / ZK proof**：Fiat-Shamir 非交互化的 Schnorr 协议，证明 `z = Σxᵢ + η` 成立而不泄露任何 xᵢ、Σxᵢ 或 η。Fiat-Shamir-compiled Schnorr protocol proving `z = Σxᵢ + η` without revealing any xᵢ, Σxᵢ or η.
- **DH-PSI**：真实的两方 Diffie-Hellman 隐私集合求交协议。A real two-party Diffie-Hellman private set intersection protocol.
- **Merkle 树 / Merkle tree**：SHA-256，末位叶子复制补齐，支持路径证明与篡改检测。SHA-256 with last-leaf duplication, supporting path proofs and tamper detection.

### 诚实的边界说明 / Honest Scope Boundaries

1. **TEE 为软件模拟 / TEE is simulated in software**。远程证明的度量值比对逻辑是真实的，但没有硬件隔离保障；实际部署需 Intel SGX / ARM TrustZone。The attestation measurement-comparison logic is real, but there is no hardware isolation; production needs Intel SGX / ARM TrustZone.
2. **零知识证明覆盖式(15)的加性关系部分 / The ZK proof covers the additive relation of Eq. 15**。完整验证「噪声确实服从以登记预算参数标定的拉普拉斯分布」，需要在 zk-SNARK 电路内实现逆累积分布函数与范围证明（如 Groth16），其规模远超轻量实现范畴。代码已对噪声参数（εᵢ、Δf̃ᵢ、随机数 u）做承诺登记，为后续接入完整电路预留接口。Fully proving noise was drawn from a Laplace distribution calibrated to the committed budget requires an inverse-CDF circuit and range proofs (e.g. Groth16) — far beyond a lightweight implementation. Noise parameters (εᵢ, Δf̃ᵢ, random u) are committed to, leaving an interface for a full circuit.
3. **区块链为哈希链模拟 / The blockchain is a hash-chain simulation**，用于演示锚定与完整性校验语义，非真实联盟链节点。It demonstrates anchoring and integrity semantics, not real consortium-chain nodes.

---

## 数学自检 / Mathematical Self-Tests

`python run.py --selftest` 运行 49 项交叉验证，覆盖：49 cross-checks covering:

- 拉普拉斯采样的均值、方差与尾概率 P(|X|>t)=exp(−t/b)。Mean, variance and tail probability P(|X|>t)=exp(−t/b) of Laplace sampling.
- **式(7) 解析式与 Simpson 数值积分交叉验证**（9 位有效数字吻合）。Eq. 7 analytical form cross-validated with Simpson numerical integration (9 significant digits).
- 组合会计的单调性、α 寻优不劣于细网格穷举、α=3/4/5/6/8 数值算例复现。Monotonicity of composition accounting, α search no worse than fine-grid enumeration, reproduces the α=3/4/5/6/8 numeric example.
- 加噪输出的无偏性与理论标准差。Unbiasedness and theoretical std-dev of noisy outputs.
- 熵的边界性质（均匀分布→1、退化分布→0）与抗样本复制。Entropy boundary properties (uniform→1, degenerate→0) and resistance to sample duplication.
- 密码学原语的完备性与健全性（含四类伪造攻击测试）。Completeness/soundness of cryptographic primitives (including four forgery attacks).
- Merkle 路径证明的完备性与健全性。Merkle path-proof completeness and soundness.

当前 **49/49 通过**。Currently **49/49 pass**.

---

## 关键实测结论 / Key Empirical Findings

**1. 预算利用率提升为 2.76 倍 / Budget utilization improves 2.76×**

ε_total=8、ε_q=0.1 时，RDP 组合会计可支撑 **221 轮**查询，线性叠加仅 **80 轮**。With ε_total=8 and ε_q=0.1, RDP composition supports **221 queries** vs. **80** under linear composition.

**2. DP 效用对比应改用「量程归一化误差」口径 / DP utility should use a range-normalized error metric**

若仅看 SoH 与急刹两维，噪声约为基线方案的 1.75 倍；但车速维反而差 2.3 倍（量程大且敏感等级高，双重不利）。改用跨维公平口径后：Looking only at SoH and hard-braking, noise is about 1.75× the baseline; but the speed dimension is 2.3× worse (large range and high sensitivity). Under a cross-dimension fair metric:

| 场景 / Scenario | 本方案平均误差 / Ours | 基线 / Baseline | 效用增益 / Gain |
|---|---|---|---|
| 三维（车速/急刹/SoH）/ 3-D | 0.4714% | 0.5775% | 1.22× |
| 四维（+累计里程）/ 4-D (+mileage) | 0.6364% | 619.19% | **972.96×** |

关键结论：优势随维度间量程异构度增大而急剧放大——加入里程维后，基线方案对 SoH 的噪声达 ±707%，统计结果完全失效。UI 参数面板中的「纳入累计里程维」开关可直接演示。Key point: the advantage grows sharply with range heterogeneity — with the mileage dimension, baseline SoH noise reaches ±707% and statistics collapse. The GUI's "include mileage" toggle demonstrates this.

**3. 熵权因子必须使用跨参与方统一的固定分桶量程 / Entropy weighting must use a common fixed binning range across parties**

若各方按自身数据的量程自适应分桶，多样性差异会被完全抹平（实测三家车企熵值均为 0.8123，熵权因子失效）。改用统一登记的共同量程后得 0.638 / 0.495 / 0.167，区分度正确。Adaptive per-party binning erases diversity differences (all three firms measured 0.8123, destroying entropy weighting); a common registered range yields 0.638 / 0.495 / 0.167.

---

## 默认运行结果 / Default Run Results (for reference)

```
记录数 Records          10001
DP 效用增益 DP gain      972.96×  (最坏维 1667.83× / worst dim)
预算利用率 Utilization   221 轮 vs 线性 80 轮 (2.76×)
α* / ε_comp             5.190 / 6.4145
联邦准确率 FL accuracy   89.56%
异常检出 Anomalies      第37轮 范数比 6.55 (阈值 3.0)；第52轮 夹角 129.7° (阈值 120°)
投毒抑制 Poisoning      车企C 0.3404 → 0.2187 (降 35.8%)
存证记录 Attestations    119 条，Merkle 树高 7，单条证明 224 字节
ZK 证明 ZK proofs       4 份全部验证通过，各约 1677 字节，生成约 550ms
总耗时 Wall time        约 20s
```

---

## 参数调整 / Parameters

图形界面点击「⚙ 参数」，或直接修改 `pipeline.Config`。Click "⚙ 参数" in the GUI, or edit `pipeline.Config` directly:

| 参数 / Param | 默认 / Default | 说明 / Description |
|---|---|---|
| `fleet_a/b/c` | 200/120/80 | 车队规模（每车一次 ECDH 握手，约 14ms）/ fleet size (~14 ms ECDH handshake per vehicle) |
| `batches` | 50 | 每车上传批次；**记录数 = 车队规模 × 批次** / upload batches per vehicle; **records = fleet size × batches** |
| `eps_local` | 0.0 | 车端本地 DP 预算，0 表示关闭 / vehicle-side local DP budget, 0 = off |
| `eps_total` | 8.0 | 总隐私预算 / total privacy budget |
| `history_rounds` | 150 | 资产历史已消耗轮数 / already-consumed rounds for the asset |
| `precision_level` | 2 | 精度等级，对应 ε_q = 0.2/0.1/0.05 / precision level, ε_q = 0.2/0.1/0.05 |
| `include_mileage` | True | 是否纳入累计里程维（演示量纲混叠）/ include mileage dimension (demonstrates scale mixing) |
| `fl_rounds` | 100 | 联邦学习轮数 / federated rounds |
| `lam/gamma/theta_th/beta/eta` | 0.5/3.0/120/0.8/0.002 | 贡献度与信誉参数 / contribution & reputation parameters |
| `zk_max_commit` | 128 | ZK 逐条承诺上限（控制生成耗时）/ per-item commitment cap (controls proof time) |

**性能提示 / Performance tip**：记录数由「车队规模 × 批次」决定。握手是 ECDH 开销大头（每车约 14ms），上传是廉价的 AEAD 操作，因此增大 `batches` 比增大车队规模更经济。Records = fleet size × batches. The handshake dominates cost (~14 ms/vehicle); uploads are cheap AEAD ops, so increasing `batches` is cheaper than increasing fleet size.

---

## 附加材料 / Additional Materials

- `ALC运行报告示例.txt` —— 一次默认运行的完整报告 / a full report from one default run

---

## 许可与用途 / License and Usage

本项目采用 **Apache License 2.0** 许可，完整条款见 [LICENSE](LICENSE)。

Licensed under the **Apache License, Version 2.0**. See [LICENSE](LICENSE) for the full terms.

```
Copyright 2026 Astrmeteor

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

**用途说明 / Scope of use**：本代码为技术方案的工程化验证与演示实现，用于验证机制可行性与算法自洽性。不包含生产环境所需的密钥管理、访问审计、高可用等工程设施。

This code is an engineering validation and demo implementation of the technical scheme, verifying mechanism feasibility and algorithmic consistency. It does not include production facilities such as key management, access auditing, or high availability.
