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
"""eval_replay.py — 约束运行时·评测算子 v0.1（L6 评测，2026-11-28）

定位：对齐《元枢 Agent OS 能力对齐规范 v0.1》第 03/04 章——官方攻关清单
「评测指标与技术标准」项的最小运行时算子。身份闸管「谁在说话」，输出闸
管「说出去了什么」，本件管「说的成绩单是真的吗」：评测结论必须可复算，
声称的完成必须有证据。

核心概念：
- 记录即锚定：每个评测案例记录「输入哈希 + 输出哈希 + 配置哈希」
  三元组入哈希链——结论的锚点不是文字描述，是可复算的字节；
- 重放即复算：同一案例用相同输入与配置重放，输出哈希一致 = 可复算；
  输入变、配置变、输出变，任何一项漂移都当场拆穿；
- 声称即对账：智能体声称「任务完成」时必须出示证据哈希，且与台账中
  记录的证据一致——「说做完了」不等于「做完了」，无证据的完成声称
  一律判为假完成（fail-closed）；
- 事件入哈希链：记录、复算、对账全部入链，篡改可发现。

诚实边界：本件验证「结论可复算、声称有证据」，不判断输出内容的
对错——对错需要参考答案，属于具体评测题的职责；不防能同时改写内存
与台账文件的本地攻击者。

用法：
    from eval_replay import EvalReplay
    ev = EvalReplay()
    ev.record("case-1", in_h, out_h, cfg_h)          # 锚定
    ok, why = ev.verify("case-1", in_h, out_h, cfg_h)  # 重放复算
    ev.claim_done("case-1", ev_hash)                 # 声称完成须对账

CLI 自检：
    eval_replay.py selftest
"""

import hashlib
import json
import os
import time


def _entry_hash(seq, ts, event, detail, prev):
    payload = json.dumps({"seq": seq, "ts": ts, "event": event,
                          "detail": detail, "prev": prev},
                         ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def h(text):
    """便捷哈希：把任意输入/输出/配置转成锚定用的哈希值。"""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class EvalReplay:
    """评测算子：记录即锚定、重放即复算、声称即对账。"""

    def __init__(self, chain_path=None):
        self.chain_path = chain_path
        self.entries = []
        self.cases = {}    # case_id -> {"in":hex,"out":hex,"cfg":hex,"evidence":hex|None}
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

    # ---------- 记录与复算 ----------

    def record(self, case_id, in_hash, out_hash, cfg_hash, evidence_hash=None):
        """记录即锚定：三元组（可带证据哈希）入链。"""
        if case_id in self.cases:
            return False, "already_recorded"
        self.cases[case_id] = {"in": in_hash, "out": out_hash,
                               "cfg": cfg_hash, "evidence": evidence_hash}
        self._append("record", {"case": case_id})
        return True, "recorded"

    def verify(self, case_id, in_hash, out_hash, cfg_hash):
        """重放即复算：三元组任一漂移即拆穿。"""
        rec = self.cases.get(case_id)
        if rec is None:
            return False, "unknown_case"
        if in_hash != rec["in"]:
            return False, "input_drift"
        if cfg_hash != rec["cfg"]:
            return False, "config_drift"
        if out_hash != rec["out"]:
            self._append("verify_fail", {"case": case_id, "reason": "output_drift"})
            return False, "output_drift"
        self._append("verify_ok", {"case": case_id})
        return True, "reproducible"

    # ---------- 完成声称对账 ----------

    def claim_done(self, case_id, evidence_hash):
        """声称即对账：无记录、无证据、证据不符，一律判假完成。"""
        rec = self.cases.get(case_id)
        if rec is None:
            self._append("claim_fail", {"case": case_id, "reason": "unknown_case"})
            return False, "fake_completion"       # 没考过试就交卷
        if rec["evidence"] is None:
            self._append("claim_fail", {"case": case_id, "reason": "no_evidence"})
            return False, "fake_completion"       # 声称完成但拿不出证据
        if evidence_hash != rec["evidence"]:
            self._append("claim_fail", {"case": case_id, "reason": "evidence_mismatch"})
            return False, "fake_completion"       # 证据对不上
        self._append("claim_ok", {"case": case_id})
        return True, "verified"

    def attach_evidence(self, case_id, evidence_hash):
        """补交证据：已锚定案例补录证据哈希（评测流程后置对账用）。"""
        rec = self.cases.get(case_id)
        if rec is None:
            return False, "unknown_case"
        if rec["evidence"] is not None:
            return False, "evidence_exists"       # 证据不覆盖，防偷换
        rec["evidence"] = evidence_hash
        self._append("attach_evidence", {"case": case_id})
        return True, "attached"


# ---------- CLI 自检 ----------

def selftest():
    results = []

    def check(name, cond):
        results.append((name, bool(cond)))

    IN, OUT, CFG = h("input-1"), h("output-1"), h("config-v1")

    # 1 重放一致 = 可复算
    ev = EvalReplay()
    ev.record("c1", IN, OUT, CFG)
    ok, why = ev.verify("c1", IN, OUT, CFG)
    check("重放一致可复算", ok and why == "reproducible")

    # 2 输出漂移拆穿
    ok, why = ev.verify("c1", IN, h("output-2"), CFG)
    check("输出漂移拆穿", (not ok) and why == "output_drift")

    # 3 配置漂移拆穿
    ok, why = ev.verify("c1", IN, OUT, h("config-v2"))
    check("配置漂移拆穿", (not ok) and why == "config_drift")

    # 4 输入漂移拆穿（换了考卷）
    ok, why = ev.verify("c1", h("input-2"), OUT, CFG)
    check("输入漂移拆穿", (not ok) and why == "input_drift")

    # 5 没考过试就交卷 = 假完成
    ev = EvalReplay()
    ok, why = ev.claim_done("ghost", h("evidence"))
    check("无记录声称判假完成", (not ok) and why == "fake_completion")

    # 6 声称完成但拿不出证据 = 假完成
    ev = EvalReplay()
    ev.record("c2", IN, OUT, CFG)
    ok, why = ev.claim_done("c2", h("evidence"))
    check("无证据声称判假完成", (not ok) and why == "fake_completion")

    # 7 证据对上 = 声称核验通过
    ev = EvalReplay()
    ev.record("c3", IN, OUT, CFG, evidence_hash=h("evidence-1"))
    ok, why = ev.claim_done("c3", h("evidence-1"))
    check("证据一致声称通过", ok and why == "verified")

    # 8 证据对不上 = 假完成
    ev = EvalReplay()
    ev.record("c4", IN, OUT, CFG, evidence_hash=h("evidence-1"))
    ok, why = ev.claim_done("c4", h("evidence-2"))
    check("证据不符判假完成", (not ok) and why == "fake_completion")

    # 9 证据不覆盖：补交后不可偷换
    ev = EvalReplay()
    ev.record("c5", IN, OUT, CFG)
    ev.attach_evidence("c5", h("evidence-1"))
    ok, why = ev.attach_evidence("c5", h("evidence-2"))
    check("证据不可偷换", (not ok) and why == "evidence_exists")

    # 10 哈希链校验通过
    ev = EvalReplay()
    ev.record("c6", IN, OUT, CFG)
    ev.verify("c6", IN, OUT, CFG)
    ok, detail = ev.verify_chain()
    check("哈希链校验通过", ok and detail["entries"] == 2)

    # 11 篡改发现
    ev.entries[0]["detail"]["case"] = "tampered"
    ok, detail = ev.verify_chain()
    check("篡改可发现", (not ok) and detail["broken_at_seq"] == 1)

    passed = sum(1 for _, c in results if c)
    for name, cond in results:
        print(("PASS" if cond else "FAIL") + "  " + name)
    print(f"--- selftest: {passed}/{len(results)} passed ---")
    return passed == len(results)


if __name__ == "__main__":
    raise SystemExit(0 if selftest() else 1)
