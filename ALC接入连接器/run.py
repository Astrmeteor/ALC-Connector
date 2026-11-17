#!/usr/bin/env python3
"""
ALC 接入连接器 — 启动入口

用法:
    python run.py              启动图形界面 (默认)
    python run.py --cli        命令行模式, 直接运行贯穿案例并打印报告
    python run.py --cli -o 报告.txt      将报告写入文件
    python run.py --selftest   运行自检, 校验各模块数学实现的正确性

依赖: 仅 Python 3.8+ 标准库。图形界面需要 tkinter
      (Windows/macOS 官方安装包自带; Ubuntu/Debian 需 sudo apt install python3-tk)

"""

import argparse
import sys


def main():
    ap = argparse.ArgumentParser(description="车云两级数据可信空间接入连接器")
    ap.add_argument("--cli", action="store_true", help="命令行模式")
    ap.add_argument("--selftest", action="store_true", help="运行数学实现自检")
    ap.add_argument("-o", "--output", help="报告输出文件路径")
    ap.add_argument("--fleet", type=int, default=None, help="车企A车队规模")
    ap.add_argument("--batches", type=int, default=None, help="每车上传批次")
    ap.add_argument("--rounds", type=int, default=None, help="联邦学习轮数")
    args = ap.parse_args()

    if sys.version_info < (3, 8):
        print("需要 Python 3.8 或更高版本")
        return 1

    if args.selftest:
        from alc_connector.selftest import run_selftest
        return 0 if run_selftest() else 1

    if args.cli:
        from alc_connector.pipeline import Config, Pipeline
        from alc_connector.report import build_report
        cfg = Config()
        if args.fleet:
            cfg.fleet_a = args.fleet
        if args.batches:
            cfg.batches = args.batches
        if args.rounds:
            cfg.fl_rounds = args.rounds
        pl = Pipeline(cfg, on_log=print)
        pl.run_all()
        rep = build_report(pl)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(rep)
            print(f"\n报告已写入 {args.output}")
        else:
            print(rep)
        return 0

    try:
        from alc_connector.ui import main as ui_main
    except ImportError as e:
        print("无法加载图形界面:", e)
        print("\ntkinter 未安装。可选方案:")
        print("  Ubuntu/Debian : sudo apt install python3-tk")
        print("  Fedora/RHEL   : sudo dnf install python3-tkinter")
        print("  或改用命令行模式: python run.py --cli")
        return 1
    ui_main()
    return 0


if __name__ == "__main__":
    sys.exit(main())
