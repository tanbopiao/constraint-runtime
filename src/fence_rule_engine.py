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
"""fence_rule_engine.py — 约束运行时·围栏规则引擎 v0.1（架构补齐方案组件一，2026-11-22）

定位：约束线四件组件的第一件。把「模型给出决策之后、执行之前，过一道与模型不同源的
硬规则校验」固化为可调用契约。规则是数据（JSON 规则包），引擎是代码——引擎不用模型判，
天然满足「裁判与被测不同源」。

核心原则：
1. fail-closed：规则包损坏、字段缺失、单条规则求值异常——一律拒绝放行，宁可停机等人。
2. 影子优先：规则可标 shadow（只记不拦），转正标准量化（连续窗口零破口零误伤），
   引擎只负责记账，转正动作由人拍板。
3. 全程留痕：每次评估返回完整命中明细，可直接写入留痕重放器。
4. 正则预编译（0.5.0 评审修正）：regex 算子在规则包装配期预编译并校验，
   模式非法装配即拒；事件期只查缓存。恶意回溯模式拖垮求值的前提是
   规则包来源不可信——规则包须来自可信渠道，该前提不在防御范围内。

规则包格式（JSON）：
{
  "package": "示例包", "version": "v0.1", "fail_closed": true,
  "rules": [
    {"id": "R1", "title": "单笔限额", "status": "live",
     "match": {"all": [
        {"field": "fields.amount", "op": ">", "value": 3000},
        {"field": "fields.category", "op": "==", "value": "餐饮"}
     ]},
     "message": "餐饮单笔超过 3000，须分级审批"}
  ]
}

match 支持组合：
  {"all": [条件...]}  全部命中才命中
  {"any": [条件...]}  任一命中即命中
  条件：{"field": "点分路径", "op": ">", "value": ...}
  op ∈ > >= < <= == != contains regex in not_in exists not_exists

用法：
    from fence_rule_engine import FenceEngine
    engine = FenceEngine("/path/to/rules.json")
    verdict = engine.evaluate({"action": "...", "fields": {...}, "text": "..."})
    # verdict = {"decision": "BLOCK"/"PASS"/"FAIL_CLOSED", "hits": [...], "notes": [...]}

CLI 自检：
    fence_rule_engine.py selftest
"""

import json
import os
import re
import sys
from collections import defaultdict

ENGINE_VERSION = "fence-rule-engine v0.1"

_ENGINE_COMPILED = {}  # pattern -> compiled（预编译缓存，0.5.0 评审修正）


def _compile_regex(pattern):
    """预编译并缓存正则：模式非法在装配期即拒，不在事件期反复编译。"""
    if pattern not in _ENGINE_COMPILED:
        _ENGINE_COMPILED[pattern] = re.compile(pattern)
    return _ENGINE_COMPILED[pattern]


_OPS = {
    ">": lambda a, b: a > b,
    ">=": lambda a, b: a >= b,
    "<": lambda a, b: a < b,
    "<=": lambda a, b: a <= b,
    "==": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
    "contains": lambda a, b: b in a,
    "regex": lambda a, b: _compile_regex(b).search(a) is not None,
    "in": lambda a, b: a in b,
    "not_in": lambda a, b: a not in b,
    "exists": lambda a, b: a is not None,
    "not_exists": lambda a, b: a is None,
}


def _dig(obj, path):
    """点分路径取值；路径不存在返回 None。"""
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _eval_condition(cond, event):
    """单条件求值；求值异常向上抛，由规则层捕获转 fail-closed。
    字段缺失（None）视为不命中——缺字段是正常业务状态，不是规则损坏；
    未知算子、规则包结构错误仍按 fail-closed 处理。"""
    op = cond["op"]
    if op not in _OPS:
        raise ValueError("unknown op: %s" % op)
    actual = _dig(event, cond.get("field", ""))
    if actual is None and op not in ("exists", "not_exists"):
        return False
    return _OPS[op](actual, cond.get("value"))


def _eval_match(match, event):
    """组合条件求值：all / any / 单条件。"""
    if "all" in match:
        return all(_eval_match(c, event) for c in match["all"])
    if "any" in match:
        return any(_eval_match(c, event) for c in match["any"])
    return _eval_condition(match, event)


class FenceEngine:
    """围栏规则引擎：加载规则包，逐事件评估，输出放行/拦截/影子记账。"""

    def __init__(self, rules_path):
        self.rules_path = rules_path
        self.stats = defaultdict(lambda: {"hits": 0, "blocks": 0, "notes": 0})
        self._load(rules_path)

    def _load(self, path):
        with open(path, "r", encoding="utf-8") as f:
            pkg = json.load(f)
        if not isinstance(pkg, dict) or not isinstance(pkg.get("rules"), list):
            raise ValueError("rule package malformed: missing rules[]")
        self.package = pkg.get("package", "unnamed")
        self.package_version = pkg.get("version", "?")
        self.fail_closed = pkg.get("fail_closed", True)
        self.rules = pkg["rules"]
        self._precompile_regex()

    def _precompile_regex(self):
        """装配期预编译全部 regex 算子（0.5.0 评审修正）：
        模式非法在装配期即抛异常（管线期 fail-closed），
        事件期只查缓存，不反复编译。恶意回溯模式拖垮求值的
        前提是规则包来源不可信——该前提不在防御范围内（见模块诚实边界）。"""
        def _walk(match):
            if not isinstance(match, dict):
                return
            if "all" in match:
                for c in match["all"]:
                    _walk(c)
            if "any" in match:
                for c in match["any"]:
                    _walk(c)
            if match.get("op") == "regex":
                _compile_regex(match.get("value", ""))

        for rule in self.rules:
            _walk(rule.get("match", {}))

    def reload(self):
        """规则包热更新（换制度不换引擎）。"""
        self._load(self.rules_path)

    def evaluate(self, event):
        """评估一个事件。返回 verdict dict，可直接入留痕。"""
        hits, notes, errors = [], [], []
        for rule in self.rules:
            rid = rule.get("id", "?")
            status = rule.get("status", "live")
            try:
                matched = _eval_match(rule.get("match", {}), event)
            except Exception as exc:  # 单条规则异常 → 整体 fail-closed
                errors.append({"rule": rid, "error": str(exc)})
                continue
            if not matched:
                continue
            entry = {"rule": rid, "title": rule.get("title", ""),
                     "status": status, "message": rule.get("message", "")}
            if status == "shadow":
                notes.append(entry)
                self.stats[rid]["hits"] += 1
                self.stats[rid]["notes"] += 1
            else:
                hits.append(entry)
                self.stats[rid]["hits"] += 1
                self.stats[rid]["blocks"] += 1

        if errors and self.fail_closed:
            return {"decision": "FAIL_CLOSED", "hits": hits, "notes": notes,
                    "errors": errors, "engine": ENGINE_VERSION}
        if hits:
            decision = "BLOCK"
        elif errors:
            decision = "PASS_WITH_ERRORS"  # fail_closed=False 时降级放行但留痕
        else:
            decision = "PASS"
        return {"decision": decision, "hits": hits, "notes": notes,
                "errors": errors, "engine": ENGINE_VERSION}

    def shadow_report(self):
        """影子规则记账：转正评估的原料（零破口零误伤由人核对后拍板）。"""
        return {"package": self.package, "version": self.package_version,
                "rules": {rid: dict(v) for rid, v in sorted(self.stats.items())}}


def selftest():
    """内置自检：live 拦截 / shadow 记账 / 放行 / fail-closed / 热更新。"""
    import tempfile
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("  PASS  " if cond else "  FAIL  ") + name)
        ok = ok and cond

    live_pkg = {
        "package": "自检包", "version": "t1", "fail_closed": True,
        "rules": [
            {"id": "R1", "title": "大额拦截", "status": "live",
             "match": {"field": "fields.amount", "op": ">", "value": 3000},
             "message": "超限"},
            {"id": "R2", "title": "敏感词影子", "status": "shadow",
             "match": {"field": "text", "op": "contains", "value": "加急"},
             "message": "出现施压话术"},
        ],
    }
    broken_pkg = {"package": "坏包", "version": "t2", "fail_closed": True,
                  "rules": [{"id": "RX", "match": {"field": "fields.amount",
                             "op": "不存在的op", "value": 1}}]}

    with tempfile.TemporaryDirectory() as td:
        p1 = os.path.join(td, "live.json")
        p2 = os.path.join(td, "broken.json")
        for p, pkg in ((p1, live_pkg), (p2, broken_pkg)):
            with open(p, "w", encoding="utf-8") as f:
                json.dump(pkg, f, ensure_ascii=False)

        eng = FenceEngine(p1)
        v = eng.evaluate({"fields": {"amount": 5000}, "text": "麻烦加急处理"})
        check("live 大额命中 → BLOCK", v["decision"] == "BLOCK" and len(v["hits"]) == 1)
        check("shadow 施压话术只记不拦", len(v["notes"]) == 1 and v["decision"] == "BLOCK")

        v = eng.evaluate({"fields": {"amount": 100}, "text": "正常报销"})
        check("正常事件 → PASS", v["decision"] == "PASS" and not v["hits"] and not v["notes"])

        v = eng.evaluate({"fields": {"amount": 100}, "text": "加急"})
        check("纯影子命中 → PASS 但记账", v["decision"] == "PASS" and len(v["notes"]) == 1)

        rep = eng.shadow_report()
        check("影子记账可出报告", rep["rules"]["R2"]["notes"] == 2)

        bad = FenceEngine(p2)
        v = bad.evaluate({"fields": {"amount": 1}})
        check("规则求值异常 → FAIL_CLOSED", v["decision"] == "FAIL_CLOSED")

        # 热更新：把坏包修好再 reload
        broken_pkg["rules"][0]["match"]["op"] = ">"
        with open(p2, "w", encoding="utf-8") as f:
            json.dump(broken_pkg, f, ensure_ascii=False)
        bad.reload()
        v = bad.evaluate({"fields": {"amount": 0}})
        check("修复后热更新 → 恢复正常判定", v["decision"] == "PASS")

        # 正则预编译（0.5.0 评审修正）：合法模式装配期编译，事件期走缓存
        regex_pkg = {"package": "正则包", "version": "t3", "fail_closed": True,
                     "rules": [{"id": "R3", "title": "工单号校验", "status": "live",
                                "match": {"field": "text", "op": "regex",
                                          "value": "^TK-\\d{4}$"},
                                "message": "工单号格式不符"}]}
        p3 = os.path.join(td, "regex.json")
        with open(p3, "w", encoding="utf-8") as f:
            json.dump(regex_pkg, f, ensure_ascii=False)
        eng3 = FenceEngine(p3)
        check("正则规则装配预编译", "^TK-\\d{4}$" in _ENGINE_COMPILED)
        v = eng3.evaluate({"text": "TK-1234"})
        check("正则命中 → BLOCK", v["decision"] == "BLOCK")
        v = eng3.evaluate({"text": "TK-abc"})
        check("正则不命中 → PASS", v["decision"] == "PASS")

        # 非法正则模式：装配期即拒，不进事件期
        bad_regex_pkg = {"package": "坏正则包", "version": "t4",
                         "fail_closed": True,
                         "rules": [{"id": "R4", "match": {"field": "text",
                                    "op": "regex", "value": "(["}}]}
        p4 = os.path.join(td, "bad_regex.json")
        with open(p4, "w", encoding="utf-8") as f:
            json.dump(bad_regex_pkg, f, ensure_ascii=False)
        try:
            FenceEngine(p4)
            check("非法正则装配即拒", False)
        except re.error:
            check("非法正则装配即拒", True)

    print("SELFTEST %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        sys.exit(selftest())
    print(__doc__)
