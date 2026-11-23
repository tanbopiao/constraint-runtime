#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tamper_demo.py — 篡改发现演示

一分钟看懂「可复算」的底线：台账里任何一条被改过，链校验立刻发现。
运行：python3 examples/tamper_demo.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from fence_rule_engine import FenceEngine
from replay_ledger import ReplayLedger


def main():
    base = os.path.dirname(os.path.abspath(__file__))
    engine = FenceEngine(os.path.join(base, "rules_example.json"))
    ledger = ReplayLedger()  # 演示用内存台账

    ev = {"fields": {"amount": 5000, "category": "餐饮", "receipt_id": "R-002"},
          "text": "客户聚餐"}
    verdict = engine.evaluate(ev)
    ledger.append(ev, verdict)

    ok, detail = ledger.verify_chain()
    print("1) 原始台账链校验：%s（%d 条）" % (ok, detail["entries"]))

    # 模拟有人事后把金额 5000 改成 50，想让这笔报销蒙混过关
    ledger.entries[0]["event"]["fields"]["amount"] = 50
    ok, detail = ledger.verify_chain()
    print("2) 篡改后链校验：%s → %s（%s）"
          % (ok, "已发现" if not ok else "未发现", detail))

    print("\n结论：改了台账任何一条，从那条起哈希全部对不上——")
    print("对账不一致可发现，这就是「可复算」的底线。")


if __name__ == "__main__":
    main()
