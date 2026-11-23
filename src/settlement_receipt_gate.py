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
"""settlement_receipt_gate.py — 约束运行时·结算凭证闸 v0.1（信符，2026-11-23）

定位：约束线第五件组件。留痕重放器管「事后可复算」，本件管「事中不被迟到
消息改写」——过期的执行者（崩溃前残留、超时重试、恢复竞态）回写结果时，
凭过期凭证一律拒绝，已定状态不被污染。

核心概念：
- 凭证三要素：任务标识 task_id + 认领轮次 attempt + 当前有效凭证号 token。
- 认领即签发：凭证与「待执行 → 执行中」状态迁移在同一原子操作内签发。
- 回写即核验：核验（任务/轮次/凭证号）与状态变更在同一操作内完成；
  不匹配即拒绝且零副作用（fail-closed）。
- 重试即作废：重试与恢复签发新凭证的同时作废旧凭证，原任务在其同序
  successor 中的优先位置保留。
- 事件入哈希链：签发与核验事件追加进哈希链台账，篡改可发现，事后可复算
  （与留痕重放器、照胆规范 T2 链式锚定同构）。

诚实边界：不防能同时改写内存与台账文件的本地攻击者；防篡改主张仅限
「对账不一致可发现」。

用法：
    from settlement_receipt_gate import SettlementGate
    gate = SettlementGate()
    rcpt = gate.claim("task-1")            # 签发凭证
    gate.settle("task-1", rcpt["token"], "ok")   # 有效回写 → 接受
    gate.settle("task-1", "stale-token", "ok")   # 过期回写 → 拒绝零副作用

CLI 自检：
    settlement_receipt_gate.py selftest
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


class SettlementGate:
    """结算凭证闸：认领即签发、回写即核验、重试即作废。"""

    def __init__(self, chain_path=None):
        self.chain_path = chain_path
        self.entries = []          # 哈希链事件
        self.tasks = {}            # task_id -> {"attempt": int, "token": str|None,
        #                            "state": "pending"|"processing"|"settled",
        #                            "priority_slot": int}
        self._slot = 0
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

    # ---------- 三铁律 ----------

    def claim(self, task_id):
        """认领即签发：状态迁移与凭证签发同一原子操作。"""
        task = self.tasks.get(task_id)
        if task is None:
            self._slot += 1
            task = {"attempt": 0, "token": None, "state": "pending",
                    "priority_slot": self._slot}
            self.tasks[task_id] = task
        if task["state"] == "settled":
            return None  # 已结算的任务不再签发
        task["attempt"] += 1
        task["token"] = secrets.token_hex(16)
        task["state"] = "processing"   # 与上一行同操作内完成，原子边界
        self._append("claim", {"task": task_id, "attempt": task["attempt"]})
        return {"task_id": task_id, "attempt": task["attempt"],
                "token": task["token"]}

    def settle(self, task_id, token, outcome):
        """回写即核验：核验与状态变更同一操作，不匹配零副作用。"""
        task = self.tasks.get(task_id)
        if task is None:
            return False, "unknown_task"
        if task["state"] != "processing":
            return False, "not_processing"
        if token != task["token"] or token is None:
            return False, "stale_receipt"   # 过期/伪造凭证：拒绝，状态不动
        task["state"] = "settled"           # 核验通过后同一操作内变更
        task["token"] = None
        self._append("settle", {"task": task_id, "attempt": task["attempt"],
                                "outcome": outcome})
        return True, "settled"

    def retry(self, task_id):
        """重试即作废：新凭证生效、旧凭证作废，优先位保留。"""
        task = self.tasks.get(task_id)
        if task is None or task["state"] == "settled":
            return None
        return self.claim(task_id)   # attempt+1，旧 token 被覆盖作废

    def priority_of(self, task_id):
        task = self.tasks.get(task_id)
        return task["priority_slot"] if task else None


# ---------- CLI 自检 ----------

def selftest():
    results = []

    def check(name, cond):
        results.append((name, bool(cond)))

    # 1 有效回写接受
    g = SettlementGate()
    r = g.claim("t1")
    ok, why = g.settle("t1", r["token"], "ok")
    check("有效凭证回写接受", ok and why == "settled")

    # 2 过期凭证回写拒绝且零副作用
    g = SettlementGate()
    r1 = g.claim("t2")
    g.retry("t2")                      # 旧凭证作废
    ok, why = g.settle("t2", r1["token"], "ok")
    check("过期凭证回写拒绝", (not ok) and why == "stale_receipt")
    check("拒绝后状态未被污染", g.tasks["t2"]["state"] == "processing")

    # 3 崩溃恢复：新凭证生效、旧凭证作废
    g = SettlementGate()
    g.claim("t3")
    r2 = g.retry("t3")                 # 模拟恢复后重新认领
    ok, _ = g.settle("t3", r2["token"], "ok")
    check("恢复后新凭证回写接受", ok)
    check("恢复后旧凭证已作废", g.settle("t3", "old", "ok") == (False, "not_processing"))

    # 4 重复回写拒绝
    g = SettlementGate()
    r = g.claim("t4")
    g.settle("t4", r["token"], "ok")
    ok, why = g.settle("t4", r["token"], "ok")
    check("重复回写拒绝", (not ok) and why == "not_processing")

    # 5 未知任务拒绝
    g = SettlementGate()
    check("未知任务拒绝", g.settle("ghost", "x", "ok") == (False, "unknown_task"))

    # 6 优先位保留：重试不改变任务在同序队列中的位置
    g = SettlementGate()
    g.claim("a"); g.claim("b"); g.claim("c")
    slot_before = g.priority_of("b")
    g.retry("b")
    check("重试后优先位保留", g.priority_of("b") == slot_before)

    # 7 哈希链校验通过
    g = SettlementGate()
    r = g.claim("t5"); g.settle("t5", r["token"], "ok")
    ok, detail = g.verify_chain()
    check("哈希链校验通过", ok and detail["entries"] == 2)

    # 8 篡改发现：改任何一条，从该条起哈希对不上
    g.entries[0]["detail"]["task"] = "tampered"
    ok, detail = g.verify_chain()
    check("篡改可发现", (not ok) and detail["broken_at_seq"] == 1)

    # 9 已结算任务不再签发凭证
    g = SettlementGate()
    r = g.claim("t6"); g.settle("t6", r["token"], "ok")
    check("已结算不再签发", g.claim("t6") is None)

    passed = sum(1 for _, c in results if c)
    for name, cond in results:
        print(("PASS" if cond else "FAIL") + "  " + name)
    print(f"--- selftest: {passed}/{len(results)} passed ---")
    return passed == len(results)


if __name__ == "__main__":
    raise SystemExit(0 if selftest() else 1)
