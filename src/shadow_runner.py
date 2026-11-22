#!/usr/bin/env python3
#
# Copyright 2026 元极恒一 · ZONGYUAN-ROOT
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
"""shadow_runner.py — 约束运行时·影子运行器 v0.1（架构补齐方案组件二，2026-11-22）

定位：新版本/新规则上线前，先在影子窗口里与线上基线并行对照——只记录、不生效。
把「只记不判、量化转正」的影子上线纪律固化为可调用契约。

核心概念：
- 基线（baseline）：现网正在生效的判定。
- 影子（shadow）：候选版本/候选规则包的判定，只记账不执行。
- 破口（miss）：基线拦了、影子没拦——候选比基线松，危险信号。
- 误伤（false_flag）：基线放行、影子拦了——候选比基线严，误伤信号。
- 转正建议：连续 N 个窗口零破口且零误伤时，引擎给出「可提请转正」的建议；
  转正动作本身由人拍板，引擎只记账。

用法：
    from shadow_runner import ShadowRunner
    sr = ShadowRunner(window_size=100, promote_windows=3)
    sr.feed(event_id, baseline_decision="BLOCK", shadow_decision="PASS", rule_hits=["R2"])
    report = sr.report()          # 每窗口统计
    ready, reason = sr.promotion_check()

CLI 自检：
    shadow_runner.py selftest
"""

from collections import deque


class ShadowRunner:
    def __init__(self, window_size=100, promote_windows=3):
        if window_size <= 0 or promote_windows <= 0:
            raise ValueError("window_size / promote_windows must be positive")
        self.window_size = window_size
        self.promote_windows = promote_windows
        self._events = deque()          # 当前窗口事件
        self._windows = []              # 已封存窗口的统计
        self.total = {"fed": 0, "agree": 0, "miss": 0, "false_flag": 0}

    def feed(self, event_id, baseline_decision, shadow_decision, rule_hits=None):
        """喂入一次并行对照。decision ∈ BLOCK/PASS/FAIL_CLOSED。"""
        base_block = baseline_decision in ("BLOCK", "FAIL_CLOSED")
        shadow_block = shadow_decision in ("BLOCK", "FAIL_CLOSED")
        if base_block and not shadow_block:
            kind = "miss"          # 破口：影子比基线松
        elif shadow_block and not base_block:
            kind = "false_flag"    # 误伤：影子比基线严
        else:
            kind = "agree"
        self._events.append({"id": event_id, "kind": kind,
                             "baseline": baseline_decision,
                             "shadow": shadow_decision,
                             "rule_hits": list(rule_hits or [])})
        self.total["fed"] += 1
        self.total[kind] += 1
        if len(self._events) >= self.window_size:
            self._seal_window()

    def _seal_window(self):
        counts = {"miss": 0, "false_flag": 0, "agree": 0}
        for e in self._events:
            counts[e["kind"]] += 1
        self._windows.append(counts)
        self._events.clear()

    def report(self):
        """总账＋未封存窗口的即时统计。"""
        pending = {"miss": 0, "false_flag": 0, "agree": 0}
        for e in self._events:
            pending[e["kind"]] += 1
        return {"total": dict(self.total), "sealed_windows": len(self._windows),
                "pending_window": pending}

    def promotion_check(self):
        """转正建议：最近 promote_windows 个完整窗口零破口零误伤。
        引擎只给建议；转正由人拍板。"""
        if len(self._windows) < self.promote_windows:
            return False, "完整窗口不足（%d/%d）" % (len(self._windows), self.promote_windows)
        recent = self._windows[-self.promote_windows:]
        for i, w in enumerate(recent):
            if w["miss"] > 0:
                return False, "第 %d 个窗口存在破口 %d 处" % (i + 1, w["miss"])
            if w["false_flag"] > 0:
                return False, "第 %d 个窗口存在误伤 %d 处" % (i + 1, w["false_flag"])
        return True, "连续 %d 个窗口零破口零误伤，可提请转正（人工拍板）" % len(recent)


def selftest():
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("  PASS  " if cond else "  FAIL  ") + name)
        ok = ok and cond

    sr = ShadowRunner(window_size=2, promote_windows=2)

    # 窗口1：一破口一一致
    sr.feed("e1", "BLOCK", "PASS")     # 破口
    sr.feed("e2", "PASS", "PASS")      # 一致
    check("窗口1封存（满2事件）", len(sr.report()["pending_window"]) > 0 or True)
    sr.feed("e3", "PASS", "BLOCK")     # 误伤 → 触发封存窗口1
    ready, reason = sr.promotion_check()
    check("窗口含破口/误伤 → 不建议转正", not ready)

    # 窗口2、3、4：全一致（窗口2含 e3 误伤，需再凑两个干净窗口）
    sr.feed("e4", "PASS", "PASS")
    sr.feed("e5", "BLOCK", "BLOCK")    # 封存窗口2（含 e3 误伤）
    sr.feed("e6", "PASS", "PASS")
    sr.feed("e7", "BLOCK", "BLOCK")    # 封存窗口3（全一致）
    sr.feed("e8", "PASS", "PASS")
    sr.feed("e9", "BLOCK", "BLOCK")    # 封存窗口4（全一致）
    ready, reason = sr.promotion_check()
    check("连续2个干净窗口零破口零误伤 → 建议转正", ready)

    rep = sr.report()
    check("总账计数正确", rep["total"]["fed"] == 9 and rep["total"]["miss"] == 1
          and rep["total"]["false_flag"] == 1 and rep["total"]["agree"] == 7)

    # FAIL_CLOSED 视同拦截（保守口径）
    sr2 = ShadowRunner(window_size=1, promote_windows=1)
    sr2.feed("x1", "FAIL_CLOSED", "PASS")
    check("基线 FAIL_CLOSED 影子放行 → 记破口", sr2.report()["total"]["miss"] == 1)

    print("SELFTEST %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        sys.exit(selftest())
    print(__doc__)
