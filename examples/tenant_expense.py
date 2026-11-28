#!/usr/bin/env python3
#
# Copyright 2026 元极恒一
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# -*- coding: utf-8 -*-
"""tenant_expense.py — 标准笼头·第一个真实租户（报销闸，2026-11-28）

用 RuntimeHarness 的 expense 场景模板跑一批真实报销事件流，
产出产品化路线要求的三个真实数字：
    拦截量  —— 管线各段拒绝的总笔数（身份/围栏/输出）；
    破口率  —— 影子分账中 miss（影子比基线松）占投喂比例；
    误伤率  —— 影子分账中 false_flag（影子比基线严）占投喂比例。

事件流覆盖真实报销场景的典型形态：正常小额、餐饮超限、施压话术、
未登记身份、越权动作、输出调包。全部判定入哈希链，跑完即对账。

用法：
    python3 examples/tenant_expense.py            # 跑完打印三个数字
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from runtime_harness import RuntimeHarness  # noqa: E402


def build_tenant():
    """装配报销闸租户：expense 模板 + 两个真实身份。"""
    h = RuntimeHarness.from_template("expense")
    h.register_agent("finance-bot", "fb-secret", ["submit", "query"])
    h.register_agent("intern-bot", "ib-secret", ["query"])   # 实习账号：只读
    return h


def event_stream():
    """一批真实形态的报销事件（金额/类别/文本）。"""
    return [
        # 正常小额：应放行
        {"fields": {"amount": 35, "category": "餐饮"}, "text": "工作午餐"},
        {"fields": {"amount": 120, "category": "交通"}, "text": "打车去客户现场"},
        {"fields": {"amount": 480, "category": "住宿"}, "text": "出差酒店一晚"},
        {"fields": {"amount": 66, "category": "餐饮"}, "text": "团队加班餐"},
        {"fields": {"amount": 230, "category": "办公"}, "text": "采购键鼠"},
        {"fields": {"amount": 15, "category": "交通"}, "text": "地铁"},
        {"fields": {"amount": 890, "category": "培训"}, "text": "在线课程"},
        {"fields": {"amount": 45, "category": "餐饮"}, "text": "客户咖啡"},
        # 餐饮超限：live 规则拦截
        {"fields": {"amount": 5000, "category": "餐饮"}, "text": "客户聚餐"},
        {"fields": {"amount": 3200, "category": "餐饮"}, "text": "部门团建"},
        {"fields": {"amount": 8800, "category": "餐饮"}, "text": "年度答谢宴"},
        # 施压话术：shadow 规则命中（只记不拦，误伤候选）
        {"fields": {"amount": 200, "category": "交通"}, "text": "这个加急处理一下"},
        {"fields": {"amount": 150, "category": "餐饮"}, "text": "领导说加急报销"},
        {"fields": {"amount": 300, "category": "办公"}, "text": "加急采购，今晚要"},
        # 大额非餐饮：模板规则不管，放行（对照）
        {"fields": {"amount": 12000, "category": "设备"}, "text": "工作站采购"},
        {"fields": {"amount": 6600, "category": "培训"}, "text": "外部认证考试"},
        # 未登记身份
        {"fields": {"amount": 100, "category": "餐饮"}, "text": "幽灵账号提交"},
        # 越权动作（intern-bot 只有 query）
        {"fields": {"amount": 88, "category": "餐饮"}, "text": "实习生提交"},
    ]


def main():
    h = build_tenant()
    events = event_stream()

    stage_counts = {}
    for i, ev in enumerate(events):
        agent = "intern-bot" if ev["text"] == "实习生提交" else (
            "ghost-bot" if ev["text"] == "幽灵账号提交" else "finance-bot")
        action = "query" if agent == "intern-bot" else "submit"
        v = h.process(agent, action, ev, content="报销单 #%d" % (i + 1))
        key = "%s:%s" % (v["stage"], v["reason"])
        stage_counts[key] = stage_counts.get(key, 0) + 1

    # 输出调包实验：管线外把信符对应内容换掉，release 侧当场拒绝
    rec = h.output.issue("finance-bot", "原始报销说明")
    tampered_ok, tampered_status = h.output.release(rec["symbol"], "被调包的说明")
    stage_counts["output:%s" % tampered_status] = stage_counts.get(
        "output:%s" % tampered_status, 0) + 1

    shadow = h.shadow.report()["total"]
    fed = shadow["fed"]
    report = {
        "tenant": "报销闸（expense 模板）",
        "harness": "runtime-harness v0.1",
        "events": len(events) + 1,
        "intercepted": h._denied + 1,          # +1 为输出调包拒绝
        "allowed": h._allowed,
        "stage_breakdown": stage_counts,
        "shadow": shadow,
        "breach_rate": round(shadow["miss"] / fed, 4) if fed else None,
        "false_flag_rate": round(shadow["false_flag"] / fed, 4) if fed else None,
        "chain_ok": h.verify()["chain_ok"],
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["chain_ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
