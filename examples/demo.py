#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""demo.py — 四件组件端到端演示

场景：一个报销审核智能体的决策流。
  1. 围栏引擎对每笔请求做硬规则校验（live 拦截 / shadow 记账）；
  2. 影子运行器对照「基线（现网人工规则）」与「影子（新规则包）」的判定差异；
  3. 熔断器盯着连续失败，异常时拒绝放行；
  4. 每次判定入哈希链台账，最后重放验证可复算。

运行：python3 demo.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from fence_rule_engine import FenceEngine
from shadow_runner import ShadowRunner
from circuit_breaker import CircuitBreaker
from replay_ledger import ReplayLedger


def main():
    base = os.path.dirname(os.path.abspath(__file__))
    engine = FenceEngine(os.path.join(base, "rules_example.json"))
    runner = ShadowRunner(window_size=4, promote_windows=2)
    breaker = CircuitBreaker(max_consecutive_failures=3, cooldown_seconds=60)
    ledger = ReplayLedger()  # 演示用内存台账；生产传文件路径即持久化

    # 模拟请求流：fields 为结构化字段，text 为自然语言附言
    requests = [
        {"id": "q1", "fields": {"amount": 500, "category": "餐饮", "receipt_id": "R-001"},
         "text": "正常差旅午餐", "baseline": "PASS"},
        {"id": "q2", "fields": {"amount": 5000, "category": "餐饮", "receipt_id": "R-002"},
         "text": "客户聚餐", "baseline": "BLOCK"},
        {"id": "q3", "fields": {"amount": 300, "category": "交通"},
         "text": "打车忘了开票，加急处理一下", "baseline": "PASS"},
        {"id": "q4", "fields": {"amount": 800, "category": "餐饮", "receipt_id": "R-003"},
         "text": "第4笔了", "baseline": "PASS", "context": {"same_day_count": 4}},
    ]

    for req in requests:
        if not breaker.allow():
            print("[%s] 熔断中，拒绝处理" % req["id"])
            continue
        verdict = engine.evaluate(req)
        ledger.append(req, verdict)
        runner.feed(req["id"], baseline_decision=req["baseline"],
                    shadow_decision=verdict["decision"],
                    rule_hits=[h["rule"] for h in verdict["hits"] + verdict["notes"]])
        print("[%s] 判定=%s  拦截=%s  影子记账=%s"
              % (req["id"], verdict["decision"],
                 [h["rule"] for h in verdict["hits"]],
                 [n["rule"] for n in verdict["notes"]]))
        breaker.record_success()

    print("\n--- 影子对照报告 ---")
    print(json.dumps(runner.report(), ensure_ascii=False, indent=2))
    ready, reason = runner.promotion_check()
    print("转正建议：%s（%s）" % (ready, reason))

    print("\n--- 可复算验证 ---")
    chain_ok, detail = ledger.verify_chain()
    print("哈希链校验：%s（%s）" % (chain_ok, detail))
    print("重放结论：%s" % json.dumps(ledger.replay(engine), ensure_ascii=False))


if __name__ == "__main__":
    main()
