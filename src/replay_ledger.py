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
"""replay_ledger.py — 约束运行时·留痕重放器 v0.1（架构补齐方案组件四，2026-11-22）

定位：每一次判定都入哈希链台账；第三方可用留存的事件与规则包离线重放，
重算结论与原判一致才算「可复算」。与评测侧证据链同构，覆盖运行时干预。

核心概念：
- 台账：append-only，每条 = 序号 + 时间戳 + 事件 + 原判 + 前链哈希，条目哈希环环相扣。
- 链校验：任何一条被篡改，从该条起哈希对不上（诚实边界：不防能同时改文件与
  台账的本地攻击者，防篡改主张仅限「对账不一致可发现」）。
- 重放：用当前规则包对留存事件重新求值，比对原判——一致率即「可复算」的直接证据。

用法：
    from replay_ledger import ReplayLedger
    led = ReplayLedger("/path/to/ledger.jsonl")
    led.append(event, verdict)
    ok, detail = led.verify_chain()
    mismatches = led.replay(engine)   # engine = fence_rule_engine.FenceEngine

CLI 自检：
    replay_ledger.py selftest
"""

import hashlib
import json
import os
import time


def _entry_hash(seq, ts, event, verdict, prev):
    payload = json.dumps({"seq": seq, "ts": ts, "event": event,
                          "verdict": verdict, "prev": prev},
                         ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ReplayLedger:
    def __init__(self, path=None):
        self.path = path
        self.entries = []
        if path and os.path.exists(path):
            self._load()

    def _load(self):
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    self.entries.append(json.loads(line))

    def append(self, event, verdict, ts=None):
        """追加一条判定留痕；返回条目哈希。"""
        seq = len(self.entries)
        ts = ts if ts is not None else time.time()
        prev = self.entries[-1]["hash"] if self.entries else "GENESIS"
        h = _entry_hash(seq, ts, event, verdict, prev)
        entry = {"seq": seq, "ts": ts, "event": event,
                 "verdict": verdict, "prev": prev, "hash": h}
        self.entries.append(entry)
        if self.path:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return h

    def verify_chain(self):
        """全链校验：逐条重算哈希并核对前链指针。"""
        prev = "GENESIS"
        for e in self.entries:
            expect = _entry_hash(e["seq"], e["ts"], e["event"], e["verdict"], prev)
            if e["prev"] != prev:
                return False, {"broken_at": e["seq"], "reason": "前链指针不符"}
            if e["hash"] != expect:
                return False, {"broken_at": e["seq"], "reason": "条目哈希不符（疑似篡改）"}
            prev = e["hash"]
        return True, {"entries": len(self.entries), "head": prev}

    def replay(self, engine):
        """用当前规则包重放全部留存事件，返回与原判不一致的清单。"""
        mismatches = []
        for e in self.entries:
            try:
                v = engine.evaluate(e["event"])
                if v["decision"] != e["verdict"].get("decision"):
                    mismatches.append({"seq": e["seq"],
                                       "original": e["verdict"].get("decision"),
                                       "replayed": v["decision"]})
            except Exception as exc:
                mismatches.append({"seq": e["seq"], "original": e["verdict"].get("decision"),
                                   "replayed": "ERROR", "error": str(exc)})
        total = len(self.entries)
        return {"total": total, "consistent": total - len(mismatches),
                "mismatches": mismatches,
                "reproducible": (total > 0 and not mismatches)}


def selftest():
    import tempfile
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("  PASS  " if cond else "  FAIL  ") + name)
        ok = ok and cond

    pkg = {"package": "自检", "version": "t1", "fail_closed": True,
           "rules": [{"id": "R1", "title": "大额", "status": "live",
                      "match": {"field": "fields.amount", "op": ">", "value": 3000},
                      "message": "超限"}]}

    with tempfile.TemporaryDirectory() as td:
        rp = os.path.join(td, "rules.json")
        lp = os.path.join(td, "ledger.jsonl")
        with open(rp, "w", encoding="utf-8") as f:
            json.dump(pkg, f, ensure_ascii=False)

        # 引擎与台账（延迟导入避免循环依赖；自检时同目录）
        sys_path = os.path.dirname(os.path.abspath(__file__))
        if sys_path not in __import__("sys").path:
            __import__("sys").path.insert(0, sys_path)
        from fence_rule_engine import FenceEngine
        eng = FenceEngine(rp)

        led = ReplayLedger(lp)
        ev1 = {"fields": {"amount": 5000}}
        ev2 = {"fields": {"amount": 100}}
        led.append(ev1, eng.evaluate(ev1))
        led.append(ev2, eng.evaluate(ev2))

        chain_ok, detail = led.verify_chain()
        check("哈希链校验通过", chain_ok and detail["entries"] == 2)

        rep = led.replay(eng)
        check("重放与原判完全一致（可复算）", rep["reproducible"] and rep["consistent"] == 2)

        # 篡改中间一条的事件内容 → 链校验应发现
        led.entries[0]["event"]["fields"]["amount"] = 1
        chain_ok, detail = led.verify_chain()
        check("篡改条目 → 链校验发现不一致", not chain_ok and detail["broken_at"] == 0)

        # 持久化：新实例从文件恢复后链仍可校验
        led2 = ReplayLedger(lp)
        # 注意：文件里是未篡改的正本
        chain_ok2, _ = led2.verify_chain()
        check("从文件恢复后链校验仍通过", chain_ok2)

    print("SELFTEST %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        sys.exit(selftest())
    print(__doc__)
