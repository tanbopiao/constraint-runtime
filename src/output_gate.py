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
"""output_gate.py — 约束运行时·输出闸 v0.1（L3 输出治理，2026-11-28）

定位：对齐《元枢 Agent OS 能力对齐规范 v0.1》第 03/04 章——官方攻关清单
「安全治理」项的输出侧算子。行为闸管「进去之前」，本件管「出来之后」：
智能体的输出在到达外部世界前，先过三道关——信符、限额、灰度。

核心概念：
- 无信符不出闸：每份对外输出必须先签发信符（内容哈希绑定），
  发布时核验信符与内容一致；无信符或内容不符一律拒绝（fail-closed）；
- 信符单次有效：同一信符不能发布两次，防重放；
- 限额即配额：每个身份每日签发配额，超配额拒绝——输出洪水的闸门；
- 灰度即水位：新版本输出按灰度比例放行到稳定通道，其余进影子通道，
  水位账本可查，出问题可回退；
- 事件入哈希链：签发、发布、拒绝、灰度分流全部入链，篡改可发现。

诚实边界：本件管「输出是否被授权发出」，不管「输出内容是否正确」——
内容正确性属于评测准入（L6）的职责；不防能同时改写内存与台账文件的
本地攻击者。

用法：
    from output_gate import OutputGate
    gate = OutputGate(daily_quota=100)
    sym = gate.issue("agent-1", "hello world")     # 签发信符
    ok, why = gate.release(sym["symbol"], "hello world")  # 核验发布
    ok, why = gate.release(sym["symbol"], "hello world")  # 重放 → 拒绝

CLI 自检：
    output_gate.py selftest
"""

import hashlib
import json
import os
import secrets
import time


def _entry_hash(seq, ts, event, detail, prev):
    payload = json.dumps({"seq": seq, "ts": ts, "event": event,
                          "detail": detail, "prev": prev},
                         ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class OutputGate:
    """输出闸：无信符不出闸、信符单次有效、限额即配额、灰度即水位。"""

    def __init__(self, chain_path=None, daily_quota=1000, gray_ratio=0.0):
        self.chain_path = chain_path
        self.daily_quota = daily_quota
        self.gray_ratio = gray_ratio      # 新版本进稳定通道的比例 0.0~1.0
        self.entries = []
        self.symbols = {}                 # symbol -> {"agent","content_hash","used","version"}
        self.issued_today = {}            # agent -> count
        self._day = time.strftime("%Y-%m-%d")
        if chain_path and os.path.exists(chain_path):
            self._load_chain()

    # ---------- 哈希链 ----------

    def _append(self, event, detail):
        seq = len(self.entries) + 1
        ts = time.strftime("%Y-%m-%dT%H:%M:%S+08:00")
        prev = self.entries[-1]["hash"] if self.entries else "GENESIS"
        entry = {"seq": seq, "ts": ts, "event": event,
                 "detail": detail, "prev": prev,
                 "hash": _entry_hash(seq, ts, event, detail, prev)}
        self.entries.append(entry)
        self._flush()
        return entry

    def _flush(self):
        if not self.chain_path:
            return
        os.makedirs(os.path.dirname(self.chain_path) or ".", exist_ok=True)
        with open(self.chain_path, "w", encoding="utf-8") as f:
            for e in self.entries:
                f.write(json.dumps(e, ensure_ascii=False, sort_keys=True) + "\n")

    def _load_chain(self):
        with open(self.chain_path, encoding="utf-8") as f:
            self.entries = [json.loads(line) for line in f if line.strip()]

    def verify_chain(self):
        prev = "GENESIS"
        for e in self.entries:
            expect = _entry_hash(e["seq"], e["ts"], e["event"], e["detail"], prev)
            if e["prev"] != prev or e["hash"] != expect:
                return False, {"broken_at_seq": e["seq"]}
            prev = e["hash"]
        return True, {"entries": len(self.entries)}

    def _roll_day(self):
        today = time.strftime("%Y-%m-%d")
        if today != self._day:
            self._day = today
            self.issued_today = {}

    # ---------- 签发 ----------

    def issue(self, agent_id, content, version="v1"):
        """签发信符：绑定内容哈希与身份，受每日配额约束。"""
        self._roll_day()
        used = self.issued_today.get(agent_id, 0)
        if used >= self.daily_quota:
            self._append("issue_deny", {"agent": agent_id, "reason": "quota"})
            return None
        self.issued_today[agent_id] = used + 1
        symbol = secrets.token_hex(16)
        self.symbols[symbol] = {"agent": agent_id,
                                "content_hash": hashlib.sha256(
                                    content.encode("utf-8")).hexdigest(),
                                "used": False, "version": version}
        self._append("issue", {"agent": agent_id, "version": version})
        return {"symbol": symbol, "version": version}

    # ---------- 发布 ----------

    def release(self, symbol, content):
        """发布核验：信符有效 + 内容一致 + 未用过，缺一即拒绝零副作用。"""
        rec = self.symbols.get(symbol)
        if rec is None:
            return False, "no_symbol"            # 无信符不出闸
        if rec["used"]:
            return False, "symbol_replayed"      # 信符单次有效
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if content_hash != rec["content_hash"]:
            self._append("release_deny", {"reason": "content_mismatch"})
            return False, "content_mismatch"     # 内容被调包
        rec["used"] = True
        roll = secrets.randbelow(10000) / 10000.0
        channel = "stable" if (rec["version"] == "v1"
                               or roll < self.gray_ratio) else "shadow"
        self._append("release", {"channel": channel, "version": rec["version"]})
        return True, channel

    def watermark(self):
        """灰度水位账本：稳定/影子通道各放行了多少。"""
        stable = sum(1 for e in self.entries
                     if e["event"] == "release" and e["detail"]["channel"] == "stable")
        shadow = sum(1 for e in self.entries
                     if e["event"] == "release" and e["detail"]["channel"] == "shadow")
        return {"stable": stable, "shadow": shadow}


# ---------- CLI 自检 ----------

def selftest():
    results = []

    def check(name, cond):
        results.append((name, bool(cond)))

    # 1 无信符不出闸
    g = OutputGate()
    ok, why = g.release("fake-symbol", "hello")
    check("无信符发布拒绝", (not ok) and why == "no_symbol")

    # 2 有效信符发布接受
    g = OutputGate()
    sym = g.issue("a1", "hello world")
    ok, why = g.release(sym["symbol"], "hello world")
    check("有效信符发布接受", ok and why == "stable")

    # 3 信符重放拒绝（单次有效）
    ok, why = g.release(sym["symbol"], "hello world")
    check("信符重放拒绝", (not ok) and why == "symbol_replayed")

    # 4 内容调包拒绝
    g = OutputGate()
    sym = g.issue("a1", "hello world")
    ok, why = g.release(sym["symbol"], "hello world!")
    check("内容调包拒绝", (not ok) and why == "content_mismatch")

    # 5 超配额拒绝
    g = OutputGate(daily_quota=3)
    syms = [g.issue("a1", f"m{i}") for i in range(5)]
    check("配额内签发成功", all(s is not None for s in syms[:3]))
    check("超配额签发拒绝", syms[3] is None and syms[4] is None)

    # 6 灰度水位：比例为 0 时新版本全进影子通道
    g = OutputGate(gray_ratio=0.0)
    for i in range(10):
        sym = g.issue("a1", f"m{i}", version="v2")
        g.release(sym["symbol"], f"m{i}")
    wm = g.watermark()
    check("灰度比例0全进影子", wm["shadow"] == 10 and wm["stable"] == 0)

    # 7 灰度水位：比例为 1 时新版本全进稳定通道
    g = OutputGate(gray_ratio=1.0)
    for i in range(10):
        sym = g.issue("a1", f"m{i}", version="v2")
        g.release(sym["symbol"], f"m{i}")
    wm = g.watermark()
    check("灰度比例1全进稳定", wm["stable"] == 10 and wm["shadow"] == 0)

    # 8 旧版本不受灰度影响
    g = OutputGate(gray_ratio=0.0)
    sym = g.issue("a1", "legacy", version="v1")
    ok, why = g.release(sym["symbol"], "legacy")
    check("旧版本直进稳定", ok and why == "stable")

    # 9 哈希链校验通过
    g = OutputGate()
    sym = g.issue("a1", "x")
    g.release(sym["symbol"], "x")
    ok, detail = g.verify_chain()
    check("哈希链校验通过", ok and detail["entries"] == 2)

    # 10 篡改发现
    g.entries[0]["detail"]["agent"] = "tampered"
    ok, detail = g.verify_chain()
    check("篡改可发现", (not ok) and detail["broken_at_seq"] == 1)

    passed = sum(1 for _, c in results if c)
    for name, cond in results:
        print(("PASS" if cond else "FAIL") + "  " + name)
    print(f"--- selftest: {passed}/{len(results)} passed ---")
    return passed == len(results)


if __name__ == "__main__":
    raise SystemExit(0 if selftest() else 1)
