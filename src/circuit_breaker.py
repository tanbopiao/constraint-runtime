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
"""circuit_breaker.py — 约束运行时·熔断停机器 v0.1（架构补齐方案组件三，2026-11-22）

定位：检测到异常（连续失败、失败率越界、显式异常信号）时自主降级或停机，
不带病继续跑。参照写方守卫的 fail-closed 原则：状态不明一律不放行。

状态机：
    CLOSED（正常放行）
      → 连续失败达阈值 / 窗口失败率越界 / 收到显式 trip 信号 → OPEN（熔断，拒绝放行）
    OPEN（冷却中，全部拒绝）
      → 冷却期满 → HALF_OPEN（试探：放行一次探针）
    HALF_OPEN
      → 探针成功 → CLOSED；探针失败 → 回 OPEN（重新冷却）

用法：
    from circuit_breaker import CircuitBreaker
    cb = CircuitBreaker(max_consecutive_failures=3, window_size=10,
                        max_failure_rate=0.5, cooldown_seconds=60)
    if cb.allow():
        ... 执行 ...
        cb.record_success() 或 cb.record_failure("原因")

CLI 自检：
    circuit_breaker.py selftest
"""

import time


class CircuitBreaker:
    def __init__(self, max_consecutive_failures=3, window_size=10,
                 max_failure_rate=0.5, cooldown_seconds=60, clock=time.time):
        if max_consecutive_failures < 1 or window_size < 1:
            raise ValueError("thresholds must be positive")
        if not 0 < max_failure_rate <= 1:
            raise ValueError("max_failure_rate must be in (0, 1]")
        self.max_consecutive_failures = max_consecutive_failures
        self.window_size = window_size
        self.max_failure_rate = max_failure_rate
        self.cooldown_seconds = cooldown_seconds
        self._clock = clock
        self.state = "CLOSED"
        self._consecutive_failures = 0
        self._window = []            # 最近 window_size 次结果（True=成功）
        self._opened_at = None
        self._half_open_probe_used = False
        self._trip_reason = None
        self._trip_count = 0

    # ---- 对外主接口 ----
    def allow(self):
        """是否放行。状态不明/内部异常一律拒绝（fail-closed）。"""
        try:
            if self.state == "OPEN":
                if self._clock() - self._opened_at >= self.cooldown_seconds:
                    self.state = "HALF_OPEN"
                    self._half_open_probe_used = False
                else:
                    return False
            if self.state == "HALF_OPEN":
                if self._half_open_probe_used:
                    return False    # 探针名额已用，其余拒绝
                self._half_open_probe_used = True
                return True
            return True             # CLOSED
        except Exception:
            return False

    def record_success(self):
        self._consecutive_failures = 0
        self._push(True)
        if self.state == "HALF_OPEN":
            self.state = "CLOSED"
            self._trip_reason = None

    def record_failure(self, reason=""):
        self._consecutive_failures += 1
        self._push(False)
        if self.state == "HALF_OPEN":
            self._trip("探针失败：" + reason)
            return
        if self._consecutive_failures >= self.max_consecutive_failures:
            self._trip("连续失败 %d 次：%s" % (self._consecutive_failures, reason))
        elif self._failure_rate() is not None and self._failure_rate() > self.max_failure_rate:
            self._trip("窗口失败率 %.0f%% 越界：%s"
                       % (self._failure_rate() * 100, reason))

    def trip(self, reason="显式熔断信号"):
        """外部显式熔断（如人工发现异常、上游告警联动）。"""
        self._trip(reason)

    # ---- 内部 ----
    def _push(self, success):
        self._window.append(success)
        if len(self._window) > self.window_size:
            self._window.pop(0)

    def _failure_rate(self):
        if len(self._window) < self.window_size:
            return None                 # 窗口未满不评失败率，避免冷启动误熔断
        return 1 - sum(self._window) / float(len(self._window))

    def _trip(self, reason):
        self.state = "OPEN"
        self._opened_at = self._clock()
        self._trip_reason = reason
        self._trip_count += 1
        self._consecutive_failures = 0

    # ---- 观测 ----
    def report(self):
        return {"state": self.state, "trip_count": self._trip_count,
                "trip_reason": self._trip_reason,
                "consecutive_failures": self._consecutive_failures,
                "window_failure_rate": self._failure_rate()}


def selftest():
    ok = True
    now = [1000.0]

    def clock():
        return now[0]

    def check(name, cond):
        nonlocal ok
        print(("  PASS  " if cond else "  FAIL  ") + name)
        ok = ok and cond

    cb = CircuitBreaker(max_consecutive_failures=3, window_size=4,
                        max_failure_rate=0.75, cooldown_seconds=60, clock=clock)

    check("初始 CLOSED 放行", cb.allow())
    cb.record_failure("偶发")
    cb.record_failure("偶发")
    check("未达阈值仍放行", cb.allow())
    cb.record_failure("第三次")
    check("连续失败达阈值 → OPEN 拒绝", cb.state == "OPEN" and not cb.allow())

    now[0] += 61                       # 冷却期满
    check("冷却期满 → HALF_OPEN 放行探针", cb.allow())
    check("探针名额已用 → 其余拒绝", not cb.allow())
    cb.record_success()
    check("探针成功 → 回 CLOSED", cb.state == "CLOSED" and cb.allow())

    # 失败率越界：4 次里 3 次失败 = 75% 不越界（阈值 0.75），第 4 次失败后 4/4 越界
    cb2 = CircuitBreaker(max_consecutive_failures=99, window_size=4,
                         max_failure_rate=0.5, cooldown_seconds=60, clock=clock)
    cb2.record_failure("a"); cb2.record_success(); cb2.record_failure("b")
    check("窗口未满不评失败率", cb2.state == "CLOSED")
    cb2.record_failure("c")
    check("窗口失败率 100% 越界 → OPEN", cb2.state == "OPEN")

    # 显式熔断
    cb3 = CircuitBreaker(clock=clock)
    cb3.trip("人工发现异常")
    check("显式 trip → OPEN", cb3.state == "OPEN" and not cb3.allow())

    print("SELFTEST %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        sys.exit(selftest())
    print(__doc__)
