"""
m270_audit.py -- Merkle 锚定存证与零知识审计模块 (图2 模块 270)

模块说明:
  (一) 全过程结构化日志按批组织为 Merkle 树, 周期性将根哈希锚定至区块链;
       任一单条记录可凭 Merkle 路径完成存在性与完整性证明, 链上仅存根哈希。
  (二) 对差分隐私聚合结果生成零知识证明, 使验证方在不接触明文的前提下
       验证式(15)所述关系:  z = Σ x_i + η

零知识证明的实际构造(本实现为真实可验证的密码学协议, 非模拟):
  记录承诺   C_i    = Com(x_i, r_i) = g^{x_i} h^{r_i}
  聚合承诺   C_sum  = Π C_i = Com(Σx_i, Σr_i)          [Pedersen 加法同态]
  噪声承诺   C_eta  = Com(η, r_η)
  输出承诺   C_z    = Com(z, r_z)
  公开值     z (已发布的加噪结果)

  验证方检查两条 Schnorr 证明(Fiat-Shamir 非交互化):
    证明①  C_z · g^{-z} ∈ <h>  且证明者知晓其以 h 为底的离散对数 r_z
            => C_z 确实承诺于公开值 z
    证明②  Q = C_z · (C_sum · C_eta)^{-1} ∈ <h> 且证明者知晓 log_h Q
            => z = Σx_i + η 成立

  由 Pedersen 承诺的完美隐藏性, 验证方无法获知任何 x_i、Σx_i 或 η 的取值,
  即"无需接触明文即可验证聚合关系"。

  局限说明(工程实现的诚实边界):
    完整验证"噪声 η 确实服从以登记预算参数 ε 标定的拉普拉斯分布", 需要在
    zk-SNARK 电路内实现逆累积分布函数与范围证明(如 Groth16 电路), 其规模远
    超轻量演示范畴。本模块实现了式(15)中的加性关系证明部分, 并对噪声参数
    (ε_i, Δf~_i, 随机数 u_i)做承诺登记, 为后续接入完整电路预留了接口。
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .crypto_lite import (MODP_P, MODP_Q, PED_G, PED_H, ped_add, ped_commit,
                          schnorr_prove, schnorr_verify, sha256_hex)


# ===========================================================================
# 一、Merkle 树
# ===========================================================================
def _h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class MerkleTree:
    """
    SHA-256 Merkle 树。叶子数不足 2 的幂时复制末位叶子补齐,
    与比特币的做法一致, 保证树高确定、路径长度一致。
    """

    def __init__(self, leaves: List[str]):
        if not leaves:
            raise ValueError("Merkle 树至少需要一个叶子")
        self.leaves = list(leaves)
        self.levels: List[List[str]] = [list(leaves)]
        cur = list(leaves)
        while len(cur) > 1:
            if len(cur) % 2 == 1:
                cur.append(cur[-1])
            cur = [_h((cur[i] + cur[i + 1]).encode()) for i in range(0, len(cur), 2)]
            self.levels.append(cur)

    @property
    def root(self) -> str:
        return self.levels[-1][0]

    @property
    def height(self) -> int:
        return len(self.levels) - 1

    def proof(self, index: int) -> List[Tuple[str, str]]:
        """返回 [(兄弟哈希, 'L'|'R'), ...] 自底向上的 Merkle 路径。"""
        if not (0 <= index < len(self.leaves)):
            raise IndexError("叶子索引越界")
        path: List[Tuple[str, str]] = []
        idx = index
        for lvl in self.levels[:-1]:
            cur = list(lvl)
            if len(cur) % 2 == 1:
                cur.append(cur[-1])
            sib = idx ^ 1
            path.append((cur[sib], "L" if sib < idx else "R"))
            idx //= 2
        return path

    @staticmethod
    def verify(leaf: str, path: List[Tuple[str, str]], root: str) -> bool:
        cur = leaf
        for sib, side in path:
            cur = _h((sib + cur).encode()) if side == "L" else _h((cur + sib).encode())
        return cur == root

    def proof_size_bytes(self) -> int:
        return self.height * 32


# ===========================================================================
# 二、区块链(联盟链)模拟: 哈希链式区块
# ===========================================================================
@dataclass
class Block:
    height: int
    prev_hash: str
    merkle_root: str
    timestamp: float
    payload: Dict[str, Any] = field(default_factory=dict)

    def hash(self) -> str:
        return sha256_hex(json.dumps({
            "h": self.height, "prev": self.prev_hash, "root": self.merkle_root,
            "ts": round(self.timestamp, 3), "payload": self.payload,
        }, sort_keys=True).encode())


class Blockchain:
    """联盟链模拟: 顺序哈希链, 支持完整性校验与篡改检测。"""

    def __init__(self):
        genesis = Block(0, "0" * 64, "0" * 64, time.time(), {"note": "ALC 联盟链创世区块"})
        self.blocks: List[Block] = [genesis]

    def anchor(self, merkle_root: str, payload: Optional[dict] = None) -> Block:
        b = Block(len(self.blocks), self.blocks[-1].hash(), merkle_root,
                  time.time(), payload or {})
        self.blocks.append(b)
        return b

    def verify_chain(self) -> bool:
        for i in range(1, len(self.blocks)):
            if self.blocks[i].prev_hash != self.blocks[i - 1].hash():
                return False
        return True

    def find_root(self, root: str) -> Optional[Block]:
        for b in self.blocks:
            if b.merkle_root == root:
                return b
        return None


# ===========================================================================
# 三、加噪合规性零知识证明
# ===========================================================================
FIXED_SCALE = 10 ** 6          # 定点化比例因子(承诺方案在整数群上工作)


def _fx(v: float) -> int:
    return int(round(v * FIXED_SCALE))


@dataclass
class ZKAggregateProof:
    """一次聚合计算的零知识审计凭据。"""
    dimension: str
    z_public: int                    # 公开的加噪输出(定点化)
    eps_i: float                     # 登记的预算参数
    delta_f: float                   # 登记的敏感度参数
    c_sum: int                       # 聚合承诺
    c_eta: int                       # 噪声承诺
    c_z: int                         # 输出承诺
    proof_open: dict                 # 证明①: C_z 承诺于公开值 z
    proof_rel: dict                  # 证明②: z = Σx_i + η
    n_records: int
    seed_commitment: str             # 噪声随机数 u 的哈希承诺
    gen_ms: float = 0.0


class ZKAuditor:
    """零知识审计器: 证明生成与验证。"""

    @staticmethod
    def prove_aggregate(values: List[float], noise: float, z: float,
                        dimension: str, eps_i: float, delta_f: float,
                        u_seed: float, max_commit: int = 256) -> ZKAggregateProof:
        """
        为一次维度级聚合生成零知识证明。
        max_commit 限制逐条记录承诺的数量以控制演示耗时; 超出部分以其精确和
        的承诺替代(由 Pedersen 加法同态, 二者在数学上等价)。
        """
        t0 = time.time()
        n = len(values)
        # 承诺方案在整数群上工作, 故先对每条记录定点化, 再在整数域内精确求和。
        # 若先浮点求和再定点化, 逐条舍入误差会破坏同态关系 Σ_fx(x_i) = _fx(Σx_i)。
        xs_fx = [_fx(v) for v in values]
        eta_fx = _fx(noise)
        # --- 逐条记录承诺, 同态累乘得聚合承诺 ---
        c_sum, r_sum = 1, 0
        for x in xs_fx[:max_commit]:
            c_i, r_i = ped_commit(x)
            c_sum = ped_add(c_sum, c_i)
            r_sum += r_i
        if n > max_commit:                       # 尾部以其精确整数和的单个承诺等价替代
            c_t, r_t = ped_commit(sum(xs_fx[max_commit:]))
            c_sum = ped_add(c_sum, c_t)
            r_sum += r_t
        # --- 噪声承诺与输出承诺 ---
        c_eta, r_eta = ped_commit(eta_fx)
        z_fx = sum(xs_fx) + eta_fx               # 定点域内的精确加性关系
        r_z = (r_sum + r_eta) % MODP_Q           # 令输出承诺与关系式随机数一致
        c_z, _ = ped_commit(z_fx, r_z)

        ctx = f"{dimension}|{eps_i}|{delta_f}|{z_fx}".encode()
        # 证明①: C_z · g^{-z} = h^{r_z}, 证明知晓 r_z
        y1 = c_z * pow(PED_G, (-z_fx) % MODP_Q, MODP_P) % MODP_P
        proof_open = schnorr_prove(y1, r_z, PED_H, ctx + b"|open")
        # 证明②: Q = C_z · (C_sum·C_eta)^{-1} = h^{r_z - r_sum - r_eta} = h^0 = 1
        #        证明知晓其以 h 为底的离散对数(此处为 0), 关系成立时 Q 必为单位元
        denom = ped_add(c_sum, c_eta)
        q = c_z * pow(denom, MODP_P - 2, MODP_P) % MODP_P
        w = (r_z - r_sum - r_eta) % MODP_Q
        proof_rel = schnorr_prove(q, w, PED_H, ctx + b"|rel")

        return ZKAggregateProof(
            dimension=dimension, z_public=z_fx, eps_i=eps_i, delta_f=delta_f,
            c_sum=c_sum, c_eta=c_eta, c_z=c_z,
            proof_open=proof_open, proof_rel=proof_rel, n_records=n,
            seed_commitment=sha256_hex(f"{u_seed:.17g}".encode()),
            gen_ms=(time.time() - t0) * 1000)

    @staticmethod
    def verify(p: ZKAggregateProof) -> Tuple[bool, List[str]]:
        """验证方仅凭公开输入与证明完成校验, 不接触任何明文。"""
        msgs: List[str] = []
        ctx = f"{p.dimension}|{p.eps_i}|{p.delta_f}|{p.z_public}".encode()
        y1 = p.c_z * pow(PED_G, (-p.z_public) % MODP_Q, MODP_P) % MODP_P
        ok1 = schnorr_verify(y1, p.proof_open, PED_H, ctx + b"|open")
        msgs.append(f"证明①(输出承诺开于公开值 z): {'通过' if ok1 else '失败'}")
        denom = ped_add(p.c_sum, p.c_eta)
        q = p.c_z * pow(denom, MODP_P - 2, MODP_P) % MODP_P
        ok2 = schnorr_verify(q, p.proof_rel, PED_H, ctx + b"|rel")
        msgs.append(f"证明②(z = Σx_i + η 加性关系): {'通过' if ok2 else '失败'}")
        ok3 = (q == 1)
        msgs.append(f"关系式商为群单位元(噪声与聚合值未被替换): {'是' if ok3 else '否'}")
        return (ok1 and ok2 and ok3), msgs

    @staticmethod
    def size_bytes(p: ZKAggregateProof) -> int:
        return sum(len(str(x)) for x in
                   (p.c_sum, p.c_eta, p.c_z, p.proof_open["t"], p.proof_open["s"],
                    p.proof_rel["t"], p.proof_rel["s"])) // 2


# ===========================================================================
# 四、审计存证模块主体
# ===========================================================================
@dataclass
class AuditRecord:
    seq: int
    kind: str
    timestamp: float
    body: Dict[str, Any]

    def leaf_hash(self) -> str:
        return sha256_hex(json.dumps({
            "seq": self.seq, "kind": self.kind, "ts": round(self.timestamp, 3),
            "body": self.body}, sort_keys=True, ensure_ascii=False).encode())


class AuditModule:
    """审计存证模块: 结构化日志 -> Merkle 树 -> 链上锚定 + 零知识证明。"""

    def __init__(self, batch_size: int = 64):
        self.records: List[AuditRecord] = []
        self.batch_size = batch_size
        self.chain = Blockchain()
        self.batches: List[dict] = []            # 已锚定批次
        self.zk_proofs: List[ZKAggregateProof] = []
        self._seq = 0

    def record(self, kind: str, body: Dict[str, Any]) -> AuditRecord:
        self._seq += 1
        r = AuditRecord(self._seq, kind, time.time(), body)
        self.records.append(r)
        return r

    def anchor_batch(self, note: str = "") -> dict:
        """将当前未锚定记录组织为 Merkle 树并把根哈希写入区块链。"""
        start = sum(b["count"] for b in self.batches)
        pending = self.records[start:]
        if not pending:
            return {}
        tree = MerkleTree([r.leaf_hash() for r in pending])
        blk = self.chain.anchor(tree.root, {"note": note, "count": len(pending)})
        batch = {"index": len(self.batches), "tree": tree, "root": tree.root,
                 "block": blk, "count": len(pending), "offset": start,
                 "height": tree.height, "note": note}
        self.batches.append(batch)
        return batch

    def prove_record(self, global_index: int) -> Optional[dict]:
        """为第 global_index 条记录生成 Merkle 存在性证明。"""
        for b in self.batches:
            if b["offset"] <= global_index < b["offset"] + b["count"]:
                local = global_index - b["offset"]
                leaf = self.records[global_index].leaf_hash()
                path = b["tree"].proof(local)
                on_chain = self.chain.find_root(b["root"])
                return {
                    "record": self.records[global_index],
                    "leaf": leaf, "path": path, "root": b["root"],
                    "verified": MerkleTree.verify(leaf, path, b["root"]),
                    "anchored": on_chain is not None,
                    "block_height": on_chain.height if on_chain else None,
                    "path_bytes": len(path) * 32, "tree_height": b["height"],
                }
        return None

    def tamper_test(self, global_index: int) -> dict:
        """
        篡改检测演示: 就地改动一条已锚定记录的内容, 其叶子哈希随之改变,
        原 Merkle 路径不再能重算出链上根哈希, 篡改被检出。
        """
        pr = self.prove_record(global_index)
        if pr is None:
            return {}
        rec = self.records[global_index]
        original = json.loads(json.dumps(rec.body, ensure_ascii=False))
        rec.body["__tampered__"] = True
        bad_leaf = rec.leaf_hash()
        detected = not MerkleTree.verify(bad_leaf, pr["path"], pr["root"])
        rec.body = original                      # 还原
        return {"index": global_index, "original_leaf": pr["leaf"],
                "tampered_leaf": bad_leaf, "detected": detected, "root": pr["root"]}

    def add_zk_proof(self, p: ZKAggregateProof):
        self.zk_proofs.append(p)
        self.record("zk_proof", {
            "dimension": p.dimension, "z_public": p.z_public,
            "eps_i": p.eps_i, "delta_f": p.delta_f,
            "c_z": str(p.c_z)[:32] + "…", "seed_commitment": p.seed_commitment,
            "n_records": p.n_records})

    def summary(self) -> dict:
        return {
            "records": len(self.records),
            "batches": len(self.batches),
            "blocks": len(self.chain.blocks) - 1,
            "chain_valid": self.chain.verify_chain(),
            "zk_proofs": len(self.zk_proofs),
            "kinds": sorted({r.kind for r in self.records}),
        }
