"""
ui.py -- Tkinter 图形界面

八个标签页:
  总览 | 210 数据接入 | 220 策略引擎 | 230 预算账本 | 240 调度
       | 250 计算沙箱 | 260 贡献结算 | 270 审计存证
所有图表均以 Canvas 手绘, 不依赖 matplotlib, 保证零第三方依赖。
"""
from __future__ import annotations

import math
import queue
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Callable, Dict, List, Optional, Tuple

from . import vss
from .m230_budget import compose, laplace_rdp
from .m270_audit import MerkleTree, ZKAuditor
from .pipeline import Config, Pipeline

FONT = ("Microsoft YaHei UI", 10)
FONT_B = ("Microsoft YaHei UI", 10, "bold")
FONT_T = ("Microsoft YaHei UI", 13, "bold")
MONO = ("Consolas", 9)

CLR_BG = "#F7F7F5"
CLR_ACCENT = "#1D9E75"
CLR_WARN = "#D85A30"
CLR_MUTED = "#73726C"
CLR_LINE = "#D3D1C7"


# ---------------------------------------------------------------------------
# 通用小部件
# ---------------------------------------------------------------------------
class LogBox(ttk.Frame):
    """带滚动条的只读日志框。"""

    def __init__(self, master, height: int = 18, **kw):
        super().__init__(master, **kw)
        self.txt = tk.Text(self, height=height, wrap="word", font=MONO,
                           bg="white", relief="flat", borderwidth=1,
                           highlightthickness=1, highlightbackground=CLR_LINE)
        sb = ttk.Scrollbar(self, orient="vertical", command=self.txt.yview)
        self.txt.configure(yscrollcommand=sb.set, state="disabled")
        self.txt.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.txt.tag_configure("head", foreground=CLR_ACCENT, font=("Consolas", 9, "bold"))
        self.txt.tag_configure("warn", foreground=CLR_WARN)
        self.txt.tag_configure("muted", foreground=CLR_MUTED)

    def write(self, line: str, tag: Optional[str] = None):
        if tag is None:
            tag = "head" if line.startswith("【") else (
                "warn" if ("失败" in line or "拒绝" in line or "异常" in line) else None)
        self.txt.configure(state="normal")
        self.txt.insert("end", line + "\n", tag or "")
        self.txt.see("end")
        self.txt.configure(state="disabled")

    def clear(self):
        self.txt.configure(state="normal")
        self.txt.delete("1.0", "end")
        self.txt.configure(state="disabled")


def make_table(master, columns: List[Tuple[str, int]], height: int = 8) -> ttk.Treeview:
    cols = [c[0] for c in columns]
    tv = ttk.Treeview(master, columns=cols, show="headings", height=height)
    for name, width in columns:
        tv.heading(name, text=name)
        tv.column(name, width=width, anchor="center")
    return tv


def fill_table(tv: ttk.Treeview, rows: List[list]):
    tv.delete(*tv.get_children())
    for r in rows:
        tv.insert("", "end", values=r)


class Plot(tk.Canvas):
    """极简折线/柱状图, 纯 Canvas 绘制。"""

    def __init__(self, master, width=520, height=200, **kw):
        super().__init__(master, width=width, height=height, bg="white",
                         highlightthickness=1, highlightbackground=CLR_LINE, **kw)
        self.W, self.H = width, height
        self.pad = (46, 12, 12, 28)   # 左上右下

    def _axes(self, xlab: str, ylab: str, xr: Tuple[float, float],
              yr: Tuple[float, float]):
        l, t, r, b = self.pad
        self.create_rectangle(l, t, self.W - r, self.H - b, outline=CLR_LINE)
        for i in range(5):
            y = t + (self.H - b - t) * i / 4
            val = yr[1] - (yr[1] - yr[0]) * i / 4
            self.create_line(l, y, self.W - r, y, fill="#EEEEEA")
            self.create_text(l - 4, y, text=f"{val:.3g}", anchor="e",
                             font=("Consolas", 7), fill=CLR_MUTED)
        for i in range(5):
            x = l + (self.W - r - l) * i / 4
            val = xr[0] + (xr[1] - xr[0]) * i / 4
            self.create_text(x, self.H - b + 10, text=f"{val:.3g}",
                             font=("Consolas", 7), fill=CLR_MUTED)
        self.create_text(self.W - r, self.H - 6, text=xlab, anchor="e",
                         font=("Consolas", 8), fill=CLR_MUTED)
        self.create_text(l - 40, t + 2, text=ylab, anchor="w",
                         font=("Consolas", 8), fill=CLR_MUTED)

    def line(self, pts: List[Tuple[float, float]], xlab="", ylab="",
             color=CLR_ACCENT, mark: Optional[Tuple[float, float]] = None,
             yr: Optional[Tuple[float, float]] = None):
        self.delete("all")
        if not pts:
            return
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        xr = (min(xs), max(xs))
        yr = yr or (min(ys), max(ys))
        if yr[1] - yr[0] < 1e-12:
            yr = (yr[0] - 1, yr[1] + 1)
        self._axes(xlab, ylab, xr, yr)
        l, t, r, b = self.pad
        def px(x): return l + (x - xr[0]) / max(xr[1] - xr[0], 1e-12) * (self.W - r - l)
        def py(y): return (self.H - b) - (y - yr[0]) / max(yr[1] - yr[0], 1e-12) * (self.H - b - t)
        flat = []
        for x, y in pts:
            flat += [px(x), py(y)]
        self.create_line(*flat, fill=color, width=2, smooth=True)
        if mark:
            mx, my = px(mark[0]), py(mark[1])
            self.create_oval(mx - 4, my - 4, mx + 4, my + 4, fill=CLR_WARN, outline="")
            self.create_text(mx, my - 12, text=f"α*={mark[0]:.2f}",
                             font=("Consolas", 8, "bold"), fill=CLR_WARN)

    def bars(self, labels: List[str], series: List[Tuple[str, List[float], str]],
             ylab="", log=False):
        """分组柱状图。series: [(名称, 数值列表, 颜色)]"""
        self.delete("all")
        if not labels:
            return
        allv = [v for _, vals, _ in series for v in vals]
        vmax = max(allv) if allv else 1.0
        if log:
            vmax = math.log10(max(vmax, 1e-9)) + 1
        l, t, r, b = self.pad
        self.create_rectangle(l, t, self.W - r, self.H - b, outline=CLR_LINE)
        gw = (self.W - r - l) / len(labels)
        bw = gw / (len(series) + 0.8)
        for gi, lab in enumerate(labels):
            gx = l + gi * gw
            for si, (name, vals, color) in enumerate(series):
                v = vals[gi]
                hv = (math.log10(max(v, 1e-9)) + 1) / vmax if log else v / max(vmax, 1e-12)
                hv = max(0.0, min(1.0, hv))
                x0 = gx + 6 + si * bw
                y0 = (self.H - b) - hv * (self.H - b - t - 6)
                self.create_rectangle(x0, y0, x0 + bw - 3, self.H - b,
                                      fill=color, outline="")
                self.create_text(x0 + bw / 2 - 1, y0 - 6,
                                 text=(f"{v:.3g}"), font=("Consolas", 7), fill=CLR_MUTED)
            self.create_text(gx + gw / 2, self.H - b + 10, text=lab,
                             font=("Consolas", 7), fill=CLR_MUTED)
        for si, (name, _, color) in enumerate(series):
            self.create_rectangle(l + 6 + si * 92, t + 4, l + 16 + si * 92, t + 12,
                                  fill=color, outline="")
            self.create_text(l + 20 + si * 92, t + 8, text=name, anchor="w",
                             font=("Consolas", 7), fill=CLR_MUTED)
        self.create_text(l - 40, t + 2, text=ylab, anchor="w",
                         font=("Consolas", 8), fill=CLR_MUTED)


# ---------------------------------------------------------------------------
# 主窗口
# ---------------------------------------------------------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("车云两级数据可信空间接入连接器系统")
        self.geometry("1180x780")
        self.configure(bg=CLR_BG)
        self.cfg = Config()
        self.pipeline: Optional[Pipeline] = None
        self.msg_q: "queue.Queue[tuple]" = queue.Queue()
        self.running = False
        self._build()
        self.after(80, self._drain)

    # -- 布局 ----------------------------------------------------------------
    def _build(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TNotebook.Tab", font=FONT, padding=(12, 6))
        style.configure("TLabel", font=FONT, background=CLR_BG)
        style.configure("TButton", font=FONT)
        style.configure("TLabelframe.Label", font=FONT_B, background=CLR_BG)
        style.configure("TLabelframe", background=CLR_BG)
        style.configure("TFrame", background=CLR_BG)
        style.configure("Treeview", font=MONO, rowheight=22)
        style.configure("Treeview.Heading", font=("Microsoft YaHei UI", 9, "bold"))

        top = ttk.Frame(self, padding=(10, 8))
        top.pack(fill="x")
        ttk.Label(top, text="车云两级数据可信空间接入连接器",
                  font=FONT_T).pack(side="left")
        self.btn_run = ttk.Button(top, text="▶ 运行案例", command=self.run_all)
        self.btn_run.pack(side="right", padx=4)
        ttk.Button(top, text="⚙ 参数", command=self.open_params).pack(side="right", padx=4)
        ttk.Button(top, text="导出报告", command=self.export_report).pack(side="right", padx=4)
        self.lbl_status = ttk.Label(top, text="就绪", foreground=CLR_MUTED)
        self.lbl_status.pack(side="right", padx=12)

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        self.tabs: Dict[str, ttk.Frame] = {}
        for key, name in [("overview", "总览"), ("m210", "210 数据接入"),
                          ("m220", "220 策略引擎"), ("m230", "230 预算账本"),
                          ("m240", "240 计算调度"), ("m250", "250 计算沙箱"),
                          ("m260", "260 贡献结算"), ("m270", "270 审计存证")]:
            f = ttk.Frame(self.nb, padding=8)
            self.nb.add(f, text=name)
            self.tabs[key] = f
        self._tab_overview()
        self._tab_210()
        self._tab_220()
        self._tab_230()
        self._tab_240()
        self._tab_250()
        self._tab_260()
        self._tab_270()

        self.pb = ttk.Progressbar(self, mode="determinate", maximum=100)
        self.pb.pack(fill="x", padx=10, pady=(0, 8))

    # -- 总览 ----------------------------------------------------------------
    def _tab_overview(self):
        f = self.tabs["overview"]
        left = ttk.Frame(f)
        left.pack(side="left", fill="both", expand=True)
        ttk.Label(left, text="案例执行日志", font=FONT_B).pack(anchor="w")
        self.log_main = LogBox(left, height=26)
        self.log_main.pack(fill="both", expand=True, pady=4)
        self.log_main.write("说明: 点击右上角\"运行案例\"开始。", "muted")
        self.log_main.write("案例: 保险机构P 以\"UBI保费定价\"为目的发起数据使用请求,", "muted")
        self.log_main.write("      含子任务A(三/四维统计查询)与子任务B(三方联邦建模),", "muted")
        self.log_main.write("      依次流经 210→220→230→240→250→260→270 七个模块。", "muted")

        right = ttk.Frame(f, width=330)
        right.pack(side="right", fill="y", padx=(10, 0))
        right.pack_propagate(False)
        box = ttk.LabelFrame(right, text="VSS 语义树 (含敏感等级)", padding=6)
        box.pack(fill="both", expand=True)
        t = tk.Text(box, font=("Consolas", 8), wrap="none", bg="white",
                    relief="flat", highlightthickness=1, highlightbackground=CLR_LINE)
        t.pack(fill="both", expand=True)
        for line in vss.tree_lines():
            t.insert("end", line + "\n")
        t.configure(state="disabled")

        kbox = ttk.LabelFrame(right, text="关键结论", padding=6)
        kbox.pack(fill="x", pady=(8, 0))
        self.lbl_kpi = tk.Text(kbox, height=9, font=("Consolas", 8), wrap="word",
                               bg="white", relief="flat", highlightthickness=1,
                               highlightbackground=CLR_LINE)
        self.lbl_kpi.pack(fill="both")
        self.lbl_kpi.insert("end", "运行后在此显示核心指标。")
        self.lbl_kpi.configure(state="disabled")

    # -- 210 ------------------------------------------------------------------
    def _tab_210(self):
        f = self.tabs["m210"]
        ttk.Label(f, text="ECDH 密钥协商 → QUIC 0-RTT 上传 → 三级完整性校验 → VSS 落库",
                  font=FONT_B).pack(anchor="w")
        self.tv210 = make_table(f, [("数据资产", 220), ("车企", 90), ("记录数", 90),
                                    ("接收", 80), ("隔离", 80), ("规则哈希", 200)], 5)
        self.tv210.pack(fill="x", pady=6)
        ttk.Label(f, text="隔离区 (三类校验各自的拦截样例)", font=FONT_B).pack(anchor="w")
        self.tv210q = make_table(f, [("序号", 60), ("车辆", 140), ("拦截原因", 720)], 6)
        self.tv210q.pack(fill="x", pady=6)
        self.log210 = LogBox(f, height=8)
        self.log210.pack(fill="both", expand=True)

    # -- 220 ------------------------------------------------------------------
    def _tab_220(self):
        f = self.tabs["m220"]
        ttk.Label(f, text="五元组(主体角色/使用目的/时间窗/空间围栏/精度等级)属性匹配",
                  font=FONT_B).pack(anchor="w")
        row = ttk.Frame(f)
        row.pack(fill="x", pady=6)
        b1 = ttk.LabelFrame(row, text="合规请求: 保险机构P / UBI保费定价", padding=6)
        b1.pack(side="left", fill="both", expand=True)
        self.tv220a = make_table(b1, [("属性项", 160), ("匹配结果", 420)], 6)
        self.tv220a.pack(fill="both", expand=True)
        b2 = ttk.LabelFrame(row, text="越权请求对照 (时间窗+围栏+精度越权)", padding=6)
        b2.pack(side="right", fill="both", expand=True, padx=(8, 0))
        self.tv220b = make_table(b2, [("属性项", 160), ("匹配结果", 420)], 6)
        self.tv220b.pack(fill="both", expand=True)
        ttk.Label(f, text="脱敏执行计划 (算子绑定至 VSS 语义树节点)",
                  font=FONT_B).pack(anchor="w", pady=(6, 0))
        self.tv220c = make_table(f, [("VSS 节点", 380), ("脱敏算子", 120),
                                     ("参数", 140), ("效果", 340)], 8)
        self.tv220c.pack(fill="both", expand=True, pady=4)

    # -- 230 ------------------------------------------------------------------
    def _tab_230(self):
        f = self.tabs["m230"]
        ttk.Label(f, text="Rényi 差分隐私组合会计: ε_RDP(α) → ε_composed → α 寻优",
                  font=FONT_B).pack(anchor="w")
        row = ttk.Frame(f)
        row.pack(fill="x", pady=6)
        self.plot230 = Plot(row, width=560, height=230)
        self.plot230.pack(side="left")
        info = ttk.Frame(row)
        info.pack(side="left", fill="both", expand=True, padx=(10, 0))
        self.tv230 = make_table(info, [("指标", 260), ("数值", 260)], 10)
        self.tv230.pack(fill="both", expand=True)
        ttk.Label(f, text="预算超限时的降级策略", font=FONT_B).pack(anchor="w")
        self.log230 = LogBox(f, height=9)
        self.log230.pack(fill="both", expand=True, pady=4)

    # -- 240 ------------------------------------------------------------------
    def _tab_240(self):
        f = self.tabs["m240"]
        ttk.Label(f, text="cost(m) = w₁·T̂ₘ + w₂·B̂ₘ + w₃·L̂ₘ  (各项组内归一化后加权)",
                  font=FONT_B).pack(anchor="w")
        self.nb240 = ttk.Notebook(f)
        self.nb240.pack(fill="both", expand=True, pady=6)
        self.tv240: Dict[str, ttk.Treeview] = {}
        for key, name in [("A", "子任务A 统计查询"), ("B", "子任务B 联邦建模"),
                          ("C", "追加任务 隐私求交")]:
            sub = ttk.Frame(self.nb240, padding=6)
            self.nb240.add(sub, text=name)
            self.tv240[key] = make_table(sub, [("模式", 80), ("可行", 70),
                                               ("预估时延(s)", 110), ("通信(MB)", 110),
                                               ("隐私损失", 100), ("代价 cost", 100),
                                               ("判定依据", 380)], 6)
            self.tv240[key].pack(fill="both", expand=True)
        self.log240 = LogBox(f, height=7)
        self.log240.pack(fill="x")

    # -- 250 ------------------------------------------------------------------
    def _tab_250(self):
        f = self.tabs["m250"]
        nb = ttk.Notebook(f)
        nb.pack(fill="both", expand=True)

        # DP 子页
        p1 = ttk.Frame(nb, padding=6)
        nb.add(p1, text="维度级差分隐私查询")
        ttk.Label(p1, text="归一化 → 按敏感等级分配预算 → 加噪 → 反归一化",
                  font=FONT_B).pack(anchor="w")
        self.tv250 = make_table(p1, [("VSS维度", 150), ("量程", 130), ("s", 40),
                                     ("w_i", 70), ("ε_i", 80), ("真实值", 100),
                                     ("加噪输出", 100), ("本方案误差%", 100),
                                     ("现有技术误差%", 110)], 7)
        self.tv250.pack(fill="x", pady=6)
        self.plot250 = Plot(p1, width=1080, height=210)
        self.plot250.pack(pady=4)
        self.lbl250 = ttk.Label(p1, text="", foreground=CLR_ACCENT, font=FONT_B)
        self.lbl250.pack(anchor="w")

        # FL 子页
        p2 = ttk.Frame(nb, padding=6)
        nb.add(p2, text="联邦学习 (TEE 安全聚合)")
        self.plot250b = Plot(p2, width=1080, height=230)
        self.plot250b.pack(pady=4)
        self.log250b = LogBox(p2, height=12)
        self.log250b.pack(fill="both", expand=True)

        # MPC/TEE 子页
        p3 = ttk.Frame(nb, padding=6)
        nb.add(p3, text="MPC / DH-PSI / TEE")
        self.log250c = LogBox(p3, height=22)
        self.log250c.pack(fill="both", expand=True)

    # -- 260 ------------------------------------------------------------------
    def _tab_260(self):
        f = self.tabs["m260"]
        ttk.Label(f, text="C_i = [λ·H_i + (1-λ)·Φ_i]·rep_i,  Ĉ_i = C_i / ΣC_j",
                  font=FONT_B).pack(anchor="w")
        self.tv260 = make_table(f, [("参与方", 90), ("H_i 熵权", 90), ("Φ_i 一致性", 100),
                                    ("rep_i 信誉", 100), ("C_i", 90), ("Ĉ_i 占比", 90),
                                    ("分账(元)", 110), ("异常轮次", 110),
                                    ("现有技术占比", 110)], 5)
        self.tv260.pack(fill="x", pady=6)
        row = ttk.Frame(f)
        row.pack(fill="both", expand=True)
        b1 = ttk.LabelFrame(row, text="信誉系数演化 rep_i", padding=4)
        b1.pack(side="left", fill="both", expand=True)
        self.plot260 = Plot(b1, width=520, height=200)
        self.plot260.pack()
        b2 = ttk.LabelFrame(row, text="贡献占比: 本系统 vs 现有技术(仅余弦)", padding=4)
        b2.pack(side="right", fill="both", expand=True, padx=(8, 0))
        self.plot260b = Plot(b2, width=520, height=200)
        self.plot260b.pack()
        self.log260 = LogBox(f, height=8)
        self.log260.pack(fill="x", pady=4)

    # -- 270 ------------------------------------------------------------------
    def _tab_270(self):
        f = self.tabs["m270"]
        row = ttk.Frame(f)
        row.pack(fill="x")
        b1 = ttk.LabelFrame(row, text="Merkle 存证与链上锚定", padding=6)
        b1.pack(side="left", fill="both", expand=True)
        self.tv270 = make_table(b1, [("项目", 220), ("数值", 340)], 9)
        self.tv270.pack(fill="both", expand=True)
        b2 = ttk.LabelFrame(row, text="零知识证明 (Pedersen 承诺 + Schnorr NIZK)", padding=6)
        b2.pack(side="right", fill="both", expand=True, padx=(8, 0))
        self.tv270b = make_table(b2, [("维度", 130), ("验证", 80), ("生成(ms)", 90),
                                      ("大小(字节)", 100), ("登记 ε_i", 90)], 9)
        self.tv270b.pack(fill="both", expand=True)
        btns = ttk.Frame(f)
        btns.pack(fill="x", pady=6)
        ttk.Button(btns, text="验证 Merkle 路径", command=self.verify_merkle).pack(side="left", padx=4)
        ttk.Button(btns, text="篡改检测演示", command=self.demo_tamper).pack(side="left", padx=4)
        ttk.Button(btns, text="第三方零知识审计", command=self.demo_zk).pack(side="left", padx=4)
        ttk.Button(btns, text="伪造证明攻击测试", command=self.demo_forge).pack(side="left", padx=4)
        self.log270 = LogBox(f, height=14)
        self.log270.pack(fill="both", expand=True)

    # -- 参数对话框 ----------------------------------------------------------
    def open_params(self):
        win = tk.Toplevel(self)
        win.title("运行参数")
        win.configure(bg=CLR_BG)
        win.transient(self)
        fields = [
            ("车企A车队规模", "fleet_a", int), ("车企B车队规模", "fleet_b", int),
            ("车企C车队规模", "fleet_c", int), ("每车上传批次", "batches", int),
            ("车端本地DP预算 ε_local (0=关闭)", "eps_local", float),
            ("总隐私预算 ε_total", "eps_total", float),
            ("历史已消耗轮数", "history_rounds", int),
            ("精度等级 (1/2/3)", "precision_level", int),
            ("联邦学习轮数 T", "fl_rounds", int),
            ("融合系数 λ", "lam", float), ("范数阈值 γ", "gamma", float),
            ("夹角阈值 θ_th (度)", "theta_th", float),
            ("信誉衰减 β", "beta", float), ("信誉恢复 η", "eta", float),
            ("ZK 逐条承诺上限", "zk_max_commit", int),
        ]
        vars_: Dict[str, tk.StringVar] = {}
        for i, (label, key, _) in enumerate(fields):
            ttk.Label(win, text=label).grid(row=i, column=0, sticky="w", padx=8, pady=3)
            v = tk.StringVar(value=str(getattr(self.cfg, key)))
            vars_[key] = v
            ttk.Entry(win, textvariable=v, width=14).grid(row=i, column=1, padx=8, pady=3)
        self.var_mileage = tk.BooleanVar(value=self.cfg.include_mileage)
        ttk.Checkbutton(win, text="纳入累计里程",
                        variable=self.var_mileage).grid(row=len(fields), column=0,
                                                        columnspan=2, sticky="w", padx=8, pady=4)

        def save():
            try:
                for _, key, cast in fields:
                    setattr(self.cfg, key, cast(vars_[key].get()))
                self.cfg.include_mileage = self.var_mileage.get()
                win.destroy()
            except ValueError as e:
                messagebox.showerror("参数错误", str(e))
        ttk.Button(win, text="保存", command=save).grid(row=len(fields) + 1, column=0,
                                                       columnspan=2, pady=8)

    # -- 运行 ----------------------------------------------------------------
    def run_all(self):
        if self.running:
            return
        self.running = True
        self.btn_run.configure(state="disabled")
        self.lbl_status.configure(text="运行中…", foreground=CLR_WARN)
        self.log_main.clear()
        self.pb["value"] = 0
        threading.Thread(target=self._worker, daemon=True).start()

    def _worker(self):
        import time as _t
        t_start = _t.time()
        try:
            pl = Pipeline(self.cfg, on_log=lambda s: self.msg_q.put(("log", s)))
            self.pipeline = pl
            steps = [("接入", pl.step_ingestion), ("策略", pl.step_policy),
                     ("预算", pl.step_budget), ("调度", pl.step_schedule)]
            for i, (name, fn) in enumerate(steps):
                self.msg_q.put(("status", f"执行 {name} 模块…"))
                fn()
                self.msg_q.put(("pb", (i + 1) * 10))
            self.msg_q.put(("status", "沙箱计算(联邦训练)…"))
            pl.step_sandbox(progress=lambda t, T, l: self.msg_q.put(
                ("pb", 40 + int(35 * t / T))))
            self.msg_q.put(("pb", 78))
            self.msg_q.put(("status", "贡献度结算…"))
            pl.step_contribution()
            self.msg_q.put(("pb", 85))
            self.msg_q.put(("status", "生成零知识证明…"))
            pl.step_audit()
            pl.results["elapsed"] = _t.time() - t_start
            self.msg_q.put(("log", f"\n===== 案例执行完毕, 总耗时 "
                                   f"{pl.results['elapsed']:.2f}s ====="))
            self.msg_q.put(("pb", 100))
            self.msg_q.put(("done", None))
        except Exception as e:  # noqa: BLE001
            import traceback
            self.msg_q.put(("error", traceback.format_exc()))

    def _drain(self):
        while True:
            try:
                kind, data = self.msg_q.get_nowait()
            except queue.Empty:
                break
            if kind == "log":
                self.log_main.write(data)
            elif kind == "pb":
                self.pb["value"] = data
            elif kind == "status":
                self.lbl_status.configure(text=data)
            elif kind == "done":
                self._render_all()
                self.running = False
                self.btn_run.configure(state="normal")
                self.lbl_status.configure(text="完成", foreground=CLR_ACCENT)
            elif kind == "error":
                self.running = False
                self.btn_run.configure(state="normal")
                self.lbl_status.configure(text="出错", foreground=CLR_WARN)
                messagebox.showerror("运行出错", data[-1500:])
        self.after(80, self._drain)

    # -- 渲染 ----------------------------------------------------------------
    def _render_all(self):
        r = self.pipeline.results
        self._render_210(r); self._render_220(r); self._render_230(r)
        self._render_240(r); self._render_250(r); self._render_260(r)
        self._render_270(r); self._render_kpi(r)

    def _render_210(self, r):
        ing = r["ingestion"]
        rows = []
        for aid, cnt in ing["assets"].items():
            st = self.pipeline.ingestion.per_asset.get(aid, {})
            a = self.pipeline.ingestion.assets[aid]
            rows.append([aid, a.oem, cnt, st.get("accepted", 0),
                         st.get("rejected", 0), a.rule_hash()[:24] + "…"])
        fill_table(self.tv210, rows)
        fill_table(self.tv210q, [[i + 1, q["vin"][:16], q["reason"]]
                                 for i, q in enumerate(self.pipeline.ingestion.quarantine[:8])])
        self.log210.clear()
        self.log210.write(f"云端连接器公钥: {ing['cloud_pub']}")
        for line in self.pipeline.ingestion.log:
            self.log210.write(line)
        self.log210.write(f"接入总耗时 {ing['elapsed']:.2f}s")

    def _render_220(self, r):
        d, bad = r["policy"]["decision"], r["policy"]["denied_demo"]
        fill_table(self.tv220a, [[x.split(":")[0], ":".join(x.split(":")[1:]).strip()]
                                 for x in d.reasons])
        fill_table(self.tv220b, [[x.split(":")[0], ":".join(x.split(":")[1:]).strip()]
                                 for x in bad.reasons])
        eff = {"perturb": "交由沙箱按 ε_i 差分隐私加噪",
               "generalize": "按栅格量化泛化", "suppress": "直接拦截, 字段不可见",
               "pass": "原样放行"}
        rows = []
        for path, op in d.plan.items():
            rows.append([path, op["op"], op.get("grid", "-"), eff.get(op["op"], "")])
        for path in d.denied_paths:
            rows.append([path, "suppress", "-", eff["suppress"]])
        fill_table(self.tv220c, rows)

    def _render_230(self, r):
        b = r["budget"]
        d = b["decision"]
        pts = [(a, v) for a, v in d.curve if v < d.eps_composed * 3]
        self.plot230.line(pts, xlab="Rényi 阶数 α", ylab="ε_composed",
                          mark=(d.alpha_star, d.eps_composed))
        n_hist = self.cfg.history_rounds
        fill_table(self.tv230, [
            ["历史查询轮数", f"{n_hist} 轮 @ ε_q={b['eps_q']}"],
            ["本次请求", f"第 {n_hist + 1} 轮, 噪声尺度 b={1/b['eps_q']:g}"],
            ["寻优阶数 α*", f"{d.alpha_star:.4f}"],
            ["单轮 ε_RDP(α*)", f"{laplace_rdp(d.alpha_star, 1/b['eps_q']):.6f}"],
            ["组合隐私损失 ε_composed", f"{d.eps_composed:.4f}"],
            ["线性叠加对照", f"{d.linear_eps:.4f}  (超限 {d.linear_eps/d.eps_total:.1f}×)"],
            ["总预算 ε_total", f"{d.eps_total}"],
            ["剩余预算", f"{d.eps_remaining:.4f}"],
            ["准入判定", "通过" if d.admitted else "拒绝"],
            ["可支撑轮数 RDP / 线性", f"{b['n_rdp']} / {b['n_linear']}  "
                                     f"(提升 {b['n_rdp']/max(b['n_linear'],1):.2f}×)"],
        ])
        self.log230.clear()
        for line in self.pipeline.ledger.log:
            self.log230.write(line)
        od = b["degrade_demo"]
        self.log230.write("")
        self.log230.write("— 降级策略演示 (把历史推至预算临界点) —")
        self.log230.write(f"核算 ε_composed={od.eps_composed:.4f} > ε_total={od.eps_total} "
                          f"→ 拒绝按原参数执行")
        if od.degradation:
            self.log230.write(f"降级方案[{od.degradation.kind}]: {od.degradation.desc}")
        else:
            self.log230.write("三种降级方案均无法满足预算, 请求被最终拒绝")

    def _render_240(self, r):
        for key in ("A", "B", "C"):
            mode, ests, feat = r["schedule"][key]
            rows = []
            for e in sorted(ests, key=lambda x: (not x.feasible, x.cost)):
                rows.append([e.mode + (" ★" if e.mode == mode else ""),
                             "是" if e.feasible else "否",
                             f"{e.latency_s:.2f}", f"{e.comm_mb:.2f}",
                             f"{e.privacy_loss:.3f}",
                             f"{e.cost:.4f}" if e.feasible else "-",
                             e.reason or ("选定: 代价最小" if e.mode == mode else "可行")])
            fill_table(self.tv240[key], rows)
        self.log240.clear()
        for line in self.pipeline.scheduler.log:
            self.log240.write(line)

    def _render_250(self, r):
        s = r["sandbox"]
        dp, u = s["dp"], s["utility"]
        rows = []
        for d in dp.dims:
            node = vss.get(d.path)
            rows.append([d.name, f"[{node.physical_min:g},{node.physical_max:g}]{d.unit}",
                         d.sensitivity, f"{d.weight:.3f}", f"{d.eps_i:.4f}",
                         f"{d.true_value:.3f}", f"{d.noisy_value:.3f}",
                         f"{d.norm_std*100:.4f}", f"{d.baseline_norm_std*100:.4f}"])
        fill_table(self.tv250, rows)
        labels = [d.name[:12] for d in dp.dims]
        self.plot250.bars(labels, [
            ("本系统(维度级标定)", [d.norm_std * 100 for d in dp.dims], CLR_ACCENT),
            ("现有技术(统一敏感度)", [d.baseline_norm_std * 100 for d in dp.dims], CLR_WARN)],
            ylab="量程归一化噪声标准差 % (对数轴)", log=True)
        self.lbl250.configure(
            text=f"平均归一化误差: 本系统 {u['mean_norm_std']*100:.4f}%  vs  "
                 f"现有技术 {u['base_norm_std']*100:.4f}%   →  效用增益 {u['gain']:.2f}× ; "
                 f"最坏维度增益 {u['worst_gain']:.2f}×  (记录数 {dp.n_records}, ε_q={dp.eps_q})")

        rounds = s["rounds"]
        self.plot250b.line([(r_.t, r_.global_loss) for r_ in rounds],
                           xlab="联邦学习轮次 t", ylab="全局损失")
        self.log250b.clear()
        self.log250b.write(f"模型: 逻辑回归 (维度 {self.cfg.fl_dim}), FedAvg, "
                           f"共 {len(rounds)} 轮, 3 家车企参与")
        self.log250b.write(f"TEE 远程证明: {'通过' if s['attested'] else '失败'}, "
                           f"MRENCLAVE={s['quote'].mrenclave[:32]}…")
        self.log250b.write(f"训练完成: 全局准确率 {s['accuracy']*100:.2f}%, "
                           f"末轮损失 {rounds[-1].global_loss:.6f}")
        self.log250b.write("")
        self.log250b.write("逐轮梯度中间量 (供 260 模块贡献度量化, 每 10 轮抽样):")
        for r_ in rounds[::10]:
            self.log250b.write("  t=%3d  " % r_.t + "  ".join(
                f"{k}: ‖g‖={v:.4f} cos={r_.cosines[k]:+.4f}"
                for k, v in r_.grad_norms.items()))
        self.log250c.clear()
        mpc, plain = s["mpc"]
        n_int, ops = s["psi"]
        self.log250c.write("【MPC 加法秘密分享】各方将私有值拆为随机分片, 聚合后精确重构")
        self.log250c.write(f"  MPC 求和 = {mpc:.6f}")
        self.log250c.write(f"  明文求和 = {plain:.6f}")
        self.log250c.write(f"  绝对误差 = {abs(mpc - plain):.3e}  (定点化精度所致, 非协议误差)")
        self.log250c.write("")
        self.log250c.write("【DH-PSI 隐私集合求交】双方交换 H(x)^a 与 H(y)^b, 各自再求幂得 H(·)^ab")
        self.log250c.write(f"  交集元素数 = {n_int}, 群指数运算 {ops} 次")
        self.log250c.write("  仅交集本身被揭示, 非交集元素对双方均不可见")
        self.log250c.write("")
        self.log250c.write("【TEE 可信执行环境】远程证明 + 飞地内聚合")
        self.log250c.write(f"  代码度量值 MRENCLAVE = {s['quote'].mrenclave}")
        self.log250c.write(f"  证明验证 = {'通过' if s['attested'] else '失败'}")
        self.log250c.write("  注: 本实现为软件模拟, 实际部署需 Intel SGX / ARM TrustZone 硬件支持")

    def _render_260(self, r):
        print([x for x in dir(self.plot260b) if not x.startswith('_')])
        c = r["contribution"]
        rows = [[x.oem, f"{x.entropy:.4f}", f"{x.phi:.4f}", f"{x.reputation:.4f}",
                 f"{x.contribution:.4f}", f"{x.normalized:.4f}", f"{x.payout:,.2f}",
                 ",".join(map(str, x.anomaly_rounds)) or "无",
                 f"{x.baseline_normalized:.4f}"] for x in c["rows"]]
        fill_table(self.tv260, rows)
        # 信誉演化曲线(取异常方)
        target = max(self.pipeline.contribution.parties.values(),
                     key=lambda p: len(p.anomalies))
        self.plot260.line([(i + 1, v) for i, v in enumerate(target.rep_series)],
                          xlab=f"轮次 t  ({target.oem})", ylab="rep_i", yr=(0.0, 1.05))
        labels = [x.oem for x in c["rows"]]
        self.plot260b.bars(labels, [
            ("本系统 Ĉ_i", [x.normalized for x in c["rows"]], CLR_ACCENT),
            ("现有技术(仅余弦)", [x.baseline_normalized for x in c["rows"]], CLR_WARN)],
            ylab="贡献占比")
        self.log260.clear()
        for line in self.pipeline.contribution.log:
            self.log260.write(line)
        for line in self.pipeline.contract.log:
            self.log260.write(line)

    def _render_270(self, r):
        a = r["audit"]
        b, mp, summ = a["batch"], a["merkle_proof"], a["summary"]
        fill_table(self.tv270, [
            ["存证记录总数", summ["records"]],
            ["记录类型", ", ".join(summ["kinds"])],
            ["Merkle 批次记录数", b["count"]],
            ["Merkle 树高", b["height"]],
            ["Merkle 根哈希", b["root"][:40] + "…"],
            ["锚定区块高度", f"#{b['block'].height}"],
            ["区块哈希", b["block"].hash()[:40] + "…"],
            ["链完整性校验", "通过" if summ["chain_valid"] else "失败"],
            ["单条记录证明大小", f"{mp['path_bytes']} 字节 ({len(mp['path'])} 个兄弟哈希)"],
        ])
        fill_table(self.tv270b, [[p.dimension, "通过" if ok else "失败",
                                 f"{p.gen_ms:.0f}", ZKAuditor.size_bytes(p),
                                 f"{p.eps_i:.4f}"] for p, (ok, _) in a["zk"]])
        self.log270.clear()
        self.log270.write("点击上方按钮可交互演示 Merkle 路径验证、篡改检测与零知识审计。")

    def _render_kpi(self, r):
        u = r["sandbox"]["utility"]
        b = r["budget"]
        rows = r["contribution"]["rows"]
        c_min = min(rows, key=lambda x: x.normalized)
        txt = (
            f"记录数        {r['sandbox']['dp'].n_records}\n"
            f"DP 效用增益   {u['gain']:.2f}×  (最坏维 {u['worst_gain']:.2f}×)\n"
            f"预算利用率    {b['n_rdp']}轮 vs 线性{b['n_linear']}轮 "
            f"({b['n_rdp']/max(b['n_linear'],1):.2f}×)\n"
            f"α* / ε_comp   {b['decision'].alpha_star:.3f} / "
            f"{b['decision'].eps_composed:.4f}\n"
            f"联邦准确率    {r['sandbox']['accuracy']*100:.2f}%\n"
            f"投毒抑制      {c_min.oem} {c_min.baseline_normalized:.4f}→"
            f"{c_min.normalized:.4f} (降 "
            f"{(1-c_min.normalized/max(c_min.baseline_normalized,1e-9))*100:.1f}%)\n"
            f"存证记录      {r['audit']['summary']['records']} 条, "
            f"树高 {r['audit']['batch']['height']}\n"
            f"ZK 证明       {len(r['audit']['zk'])} 份全部验证通过\n"
            f"总耗时        {r.get('elapsed', 0):.2f}s")
        self.lbl_kpi.configure(state="normal")
        self.lbl_kpi.delete("1.0", "end")
        self.lbl_kpi.insert("end", txt)
        self.lbl_kpi.configure(state="disabled")

    # -- 270 交互演示 --------------------------------------------------------
    def _need_run(self) -> bool:
        if not self.pipeline or "audit" not in self.pipeline.results:
            messagebox.showinfo("提示", "请先运行案例")
            return True
        return False

    def verify_merkle(self):
        if self._need_run():
            return
        mp = self.pipeline.results["audit"]["merkle_proof"]
        self.log270.clear()
        self.log270.write("【Merkle 路径验证】")
        self.log270.write(f"待验证记录: #{mp['record'].seq}  类型={mp['record'].kind}")
        self.log270.write(f"叶子哈希: {mp['leaf']}")
        self.log270.write("自底向上的兄弟哈希路径:")
        for i, (sib, side) in enumerate(mp["path"]):
            self.log270.write(f"  第{i+1}层 [{side}] {sib}")
        self.log270.write(f"重算根哈希: {mp['root']}")
        self.log270.write(f"链上根哈希: {mp['root']} (区块 #{mp['block_height']})")
        self.log270.write(f"验证结果: {'通过 — 记录存在且未被篡改' if mp['verified'] else '失败'}")
        self.log270.write(f"证明开销: 仅 {mp['path_bytes']} 字节, 链上仅存 32 字节根哈希")

    def demo_tamper(self):
        if self._need_run():
            return
        t = self.pipeline.results["audit"]["tamper"]
        self.log270.clear()
        self.log270.write("【篡改检测演示】就地改动一条已锚定记录的内容")
        self.log270.write(f"原始叶子哈希: {t['original_leaf']}")
        self.log270.write(f"篡改后哈希:   {t['tampered_leaf']}")
        self.log270.write(f"链上根哈希:   {t['root']}")
        self.log270.write(f"检出结果: {'成功 — 原 Merkle 路径无法重算出链上根哈希' if t['detected'] else '未检出'}")
        self.log270.write("(演示后记录已自动还原)")

    def demo_zk(self):
        if self._need_run():
            return
        self.log270.clear()
        self.log270.write("【第三方零知识审计】监管方 R 在不接触任何明文的前提下验证加噪合规性")
        for p, (ok, msgs) in self.pipeline.results["audit"]["zk"]:
            self.log270.write("")
            self.log270.write(f"维度 [{p.dimension}]  公开输入: z={p.z_public} (定点), "
                              f"登记 ε_i={p.eps_i:.4f}, Δf̃={p.delta_f:.3e}")
            self.log270.write(f"  秘密输入(证明者持有, 验证方不可见): "
                              f"{p.n_records} 条记录承诺、真实聚合值、噪声随机数")
            for m in msgs:
                self.log270.write("  " + m)
            self.log270.write(f"  综合判定: {'通过' if ok else '失败'} | "
                              f"证明大小 ≈{ZKAuditor.size_bytes(p)} 字节, "
                              f"生成 {p.gen_ms:.0f}ms")
        self.log270.write("")
        self.log270.write("局限说明: 本模块实现加性关系零知识证明(Pedersen 承诺 +")
        self.log270.write("Fiat-Shamir Schnorr NIZK)。完整验证\"噪声服从登记参数标定的拉普拉斯")
        self.log270.write("分布\"还需在 zk-SNARK 电路内实现逆CDF与范围证明, 已预留参数承诺接口。")

    def demo_forge(self):
        if self._need_run():
            return
        import copy
        self.log270.clear()
        self.log270.write("【伪造证明攻击测试】验证审计机制能否抵御四类伪造")
        p, _ = self.pipeline.results["audit"]["zk"][0]
        from .crypto_lite import MODP_P
        attacks = [
            ("篡改公开输出 z (谎报统计结果)", lambda q: setattr(q, "z_public", q.z_public + 10 ** 6)),
            ("替换噪声承诺 (偷工减料少加噪)", lambda q: setattr(q, "c_eta", q.c_eta * 3 % MODP_P)),
            ("替换聚合承诺 (掉包输入数据)", lambda q: setattr(q, "c_sum", q.c_sum * 7 % MODP_P)),
            ("伪造 Schnorr 应答 s", lambda q: q.proof_rel.update(s=q.proof_rel["s"] + 1)),
        ]
        for name, mut in attacks:
            bad = copy.deepcopy(p)
            mut(bad)
            ok, _ = ZKAuditor.verify(bad)
            self.log270.write(f"  {name}: 验证={'通过(存在漏洞!)' if ok else '拒绝 ✓'}")
        ok0, _ = ZKAuditor.verify(p)
        self.log270.write(f"  未经篡改的原始证明: 验证={'通过 ✓' if ok0 else '失败'}")

    # -- 导出 ----------------------------------------------------------------
    def export_report(self):
        if not self.pipeline or not self.pipeline.results:
            messagebox.showinfo("提示", "请先运行案例")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("文本报告", "*.txt")],
            initialfile="ALC运行报告.txt")
        if not path:
            return
        from .report import build_report
        with open(path, "w", encoding="utf-8") as f:
            f.write(build_report(self.pipeline))
        messagebox.showinfo("完成", f"报告已导出:\n{path}")


def main():
    App().mainloop()
