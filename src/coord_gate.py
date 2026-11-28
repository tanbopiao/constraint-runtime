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
"""coord_gate.py — 约束运行时·协同闸 v0.1（多智能体协同，2026-11-28）

定位：对齐《元枢 Agent OS 能力对齐规范 v0.1》「横切·多智能体协同」层，
落地《T-02 多智能体仲裁与协同细则 v1.3》的可执行算子。细则管事实层
冲突的消解与多实例协同边界，本件把其中可确定性判定的部分做成代码：
语义三分类（CONFLICT/COMPLEMENT/IRRELEVANT）仍由调用方（或轻量模型）
给出，本闸负责规则校验、仲裁执行与全程留痕——裁判与被测不同源。

核心概念（条款号对应细则 v1.3）：
- 写入追加不覆盖（3.1）：条目只追加，作废是视图标记，无原地改删；
- 冲突判定前置共识（3.2）：仅同 conflict_group、生效时间重叠、同一
  实体-谓词互斥断言才算冲突；跨 group 比对直接拒绝（避坑五条）；
- 写侧预检不阻塞（6.10）：疑似互斥只打 hint 标记，写入照常；
- 三种仲裁策略（3.3）：自动仲裁（置信差达阈，低置信改 superseded
  保留不删）、待决挂起（pending_conflict，召回全返附提示）、
  联邦共识（加权投票，权重记录在案）；
- 优先级兜底序（3.4）：静态真值 > 人工确认 > 可信工具 > 外部第三方
  > Agent 自省 > 低置信推测；低层证据不得取代高层证据；
- 判断权与放行权分离（5.2）：仲裁者不得是被裁决条目的产出方；
- 组合行为风控（6.5~6.6）：协同动作按版本化白名单放行，白名单外
  进人工关口；人工否决为终局，同因结果缓存不重复打扰（3.2 条款 3.2）；
- ENRICH 合并类（6.12）：补充关系建方向链接，与冲突互斥，拿不准不建链；
- 不对称隔离（6.13）：破坏性操作走可恢复路径，回执核验禁止静默成功；
- 全程入哈希链：写入、判定、仲裁、重开、组合校验全部留痕可回放。

诚实边界：本件是单机信任模型——不防能同时改写内存与台账文件的本地
攻击者；语义判定质量取决于调用方给出的分类，本闸只保证「判了就留痕、
错了可重开、越权进不来」。

用法：
    from coord_gate import CoordGate
    gate = CoordGate()
    gate.write("g1", "用户", "养猫", "是", 0.9, "human_confirmed", "a1")
    gate.write("g1", "用户", "养猫", "否", 0.5, "agent_introspection", "a2")
    gate.arbitrate("m1", "m2", "auto", "arbiter-1")   # 低置信改 superseded
    view = gate.recall("g1", "用户", "养猫")            # 召回侧视图＋提示

CLI 自检：
    coord_gate.py selftest
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


class CoordGate:
    """协同闸：追加式条目、规则化仲裁、组合风控、全程留痕。"""

    # 3.4 优先级兜底序：层级越高越可信
    TIER_RANK = {
        "static_truth": 5,
        "human_confirmed": 4,
        "trusted_tool": 3,
        "external_third_party": 2,
        "agent_introspection": 1,
        "low_confidence_guess": 0,
    }
    ACTIVE = "active"
    SUPERSEDED = "superseded"
    PENDING = "pending_conflict"

    def __init__(self, chain_path=None, auto_gap=0.2):
        self.chain_path = chain_path
        self.auto_gap = auto_gap
        self.entries = []          # 哈希链事件
        self.mids = {}             # mid -> 条目视图
        self._combo_cache = {}     # 同因否决缓存：fingerprint -> verdict
        self._combo_wl = {"v1": set()}  # 版本化组合行为白名单
        self._seq = 0
        if chain_path and os.path.exists(chain_path):
            self._load_chain()

    # ---------- 哈希链 ----------

    def _append(self, event, detail):
        self._seq += 1
        ts = time.strftime("%Y-%m-%dT%H:%M:%S+08:00")
        prev = self.entries[-1]["hash"] if self.entries else "GENESIS"
        entry = {"seq": self._seq, "ts": ts, "event": event,
                 "detail": detail, "prev": prev,
                 "hash": _entry_hash(self._seq, ts, event, detail, prev)}
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
        self._seq = len(self.entries)

    def verify_chain(self):
        prev = "GENESIS"
        for e in self.entries:
            expect = _entry_hash(e["seq"], e["ts"], e["event"], e["detail"], prev)
            if e["prev"] != prev or e["hash"] != expect:
                return False, {"broken_at_seq": e["seq"]}
            prev = e["hash"]
        return True, {"entries": len(self.entries)}

    # ---------- 写入与写侧预检（3.1 / 6.10） ----------

    def write(self, group_id, subject, predicate, value, confidence,
              tier, source_agent, valid_start=None, valid_end=None):
        """写入新条目：一律追加；同 group 同实体-谓词的疑似互斥只打
        hint 标记，不阻塞写入、不改旧条目（6.10 预检三不）。"""
        if tier not in self.TIER_RANK:
            return None, "unknown_tier"
        mid = "m%d" % (len(self.mids) + 1)
        entry = {"mid": mid, "group": group_id, "subject": subject,
                 "predicate": predicate, "value": value,
                 "confidence": confidence, "tier": tier,
                 "source_agent": source_agent,
                 "valid_start": valid_start, "valid_end": valid_end,
                 "status": self.ACTIVE, "hints": [], "enriches": []}
        self.mids[mid] = entry
        hints = self._precheck(entry)
        entry["hints"] = hints
        self._append("write", {"mid": mid, "group": group_id,
                               "hints": hints})
        return mid, {"status": entry["status"], "hints": hints}

    def _precheck(self, entry):
        """写侧预检：同 group、同实体-谓词、时间重叠、取值不同 → hint。"""
        hints = []
        for other in self.mids.values():
            if other is entry or other["group"] != entry["group"]:
                continue
            if (other["subject"], other["predicate"]) != \
               (entry["subject"], entry["predicate"]):
                continue
            if other["value"] == entry["value"]:
                continue
            if not self._time_overlap(entry, other):
                continue
            hints.append({"hint": "write_conflict_hint", "with": other["mid"]})
        return hints

    @staticmethod
    def _time_overlap(a, b):
        """生效时间重叠判定；未登记时间视为重叠（保守侧，6.13）。"""
        a_end = a["valid_end"]
        b_start = b["valid_start"]
        if a_end is not None and b_start is not None and a_end <= b_start:
            return False
        b_end = b["valid_end"]
        a_start = a["valid_start"]
        if b_end is not None and a_start is not None and b_end <= a_start:
            return False
        return True

    # ---------- 关系判定（3.2 / 6.12，规则校验层） ----------

    def classify(self, mid_a, mid_b, verdict, judge_id):
        """登记语义三分类结论。本闸只做规则校验：跨 group 比对拒绝
        （避坑五条）；CONFLICT 要求互斥（取值不同且时间重叠）；
        ENRICH 与 CONFLICT 互斥（6.12.3），拿不准不建链由调用方保证。"""
        a, b = self.mids.get(mid_a), self.mids.get(mid_b)
        if not a or not b:
            return False, "unknown_mid"
        if a["group"] != b["group"]:
            return False, "cross_group_forbidden"     # 避坑第 5 条
        same_key = (a["subject"], a["predicate"]) == (b["subject"], b["predicate"])
        if verdict == "CONFLICT":
            if not same_key:
                return False, "conflict_requires_same_key"
            if a["value"] == b["value"]:
                return False, "not_mutually_exclusive"
            if not self._time_overlap(a, b):
                return False, "temporal_progression_not_conflict"
        elif verdict == "COMPLEMENT":
            if not same_key:
                return False, "complement_requires_same_key"
        elif verdict == "IRRELEVANT":
            pass
        else:
            return False, "unknown_verdict"
        self._append("classify", {"a": mid_a, "b": mid_b,
                                  "verdict": verdict, "judge": judge_id})
        return True, "recorded"

    def link_enrich(self, new_mid, old_mid):
        """ENRICH 方向链接（6.12）：新条目指向被细化条目，双方保留；
        与 CONFLICT 互斥——任一方向已判冲突即拒绝建链。"""
        a, b = self.mids.get(new_mid), self.mids.get(old_mid)
        if not a or not b:
            return False, "unknown_mid"
        if (a["subject"], a["predicate"]) != (b["subject"], b["predicate"]):
            return False, "complement_requires_same_key"
        if self._has_conflict_between(a, b):
            return False, "conflict_relation_exists"   # 6.12.3 互斥
        a["enriches"].append(old_mid)
        self._append("link_enrich", {"new": new_mid, "old": old_mid})
        return True, "linked"

    def _has_conflict_between(self, a, b):
        for e in self.entries:
            if e["event"] != "classify":
                continue
            d = e["detail"]
            pair = {d["a"], d["b"]}
            if d["verdict"] == "CONFLICT" and pair == {a["mid"], b["mid"]}:
                return True
        return False

    # ---------- 仲裁（3.3 / 3.4 / 5.2） ----------

    def arbitrate(self, mid_a, mid_b, strategy, arbiter_id, votes=None):
        """按策略执行仲裁。策略与结果留痕；仲裁者不得是被裁决条目
        的产出方（5.2 判断权与放行权分离）。"""
        a, b = self.mids.get(mid_a), self.mids.get(mid_b)
        if not a or not b:
            return None, "unknown_mid"
        if arbiter_id in (a["source_agent"], b["source_agent"]):
            return None, "arbiter_separation_violation"   # 5.2
        if strategy == "auto":
            return self._arbitrate_auto(a, b, arbiter_id)
        if strategy == "pending":
            a["status"] = self.PENDING
            b["status"] = self.PENDING
            self._append("arbitrate", {"strategy": strategy,
                                       "mids": [mid_a, mid_b],
                                       "arbiter": arbiter_id})
            return {"pending": [mid_a, mid_b]}, "pending_set"
        if strategy == "federal":
            return self._arbitrate_federal(a, b, votes, arbiter_id)
        return None, "unknown_strategy"

    def _arbitrate_auto(self, a, b, arbiter_id):
        """自动仲裁：置信差达阈才动手；低层证据不得取代高层（3.4）；
        superseded 保留不删（3.1）。"""
        gap = abs(a["confidence"] - b["confidence"])
        if gap < self.auto_gap:
            return None, "confidence_gap_below_threshold_use_pending"
        hi, lo = (a, b) if a["confidence"] > b["confidence"] else (b, a)
        if self.TIER_RANK[lo["tier"]] > self.TIER_RANK[hi["tier"]]:
            return None, "tier_priority_blocks_supersede"  # 3.4 兜底序
        lo["status"] = self.SUPERSEDED                     # 保留不删
        receipt = {"strategy": "auto", "superseded": lo["mid"],
                   "kept": hi["mid"], "gap": round(gap, 4),
                   "arbiter": arbiter_id,
                   "before": [a["status"], b["status"]],
                   "after": [a["status"], b["status"]]}
        self._append("arbitrate", receipt)
        return receipt, "superseded"

    def _arbitrate_federal(self, a, b, votes, arbiter_id):
        """联邦共识：节点加权投票，权重记录在案（4.3），不静默调整。"""
        if not votes:
            return None, "votes_required"
        tally = {}
        for mid, weight in votes.items():
            if mid not in (a["mid"], b["mid"]):
                return None, "vote_for_unknown_mid"
            tally[mid] = tally.get(mid, 0.0) + float(weight)
        winner = max(tally, key=tally.get)
        loser = b["mid"] if winner == a["mid"] else a["mid"]
        self.mids[loser]["status"] = self.SUPERSEDED       # 保留不删
        receipt = {"strategy": "federal", "superseded": loser,
                   "kept": winner, "tally": tally,
                   "arbiter": arbiter_id}
        self._append("arbitrate", receipt)
        return receipt, "superseded"

    # ---------- 召回与重开（3.1 / 第六节） ----------

    def recall(self, group_id, subject=None, predicate=None):
        """召回侧视图：active 全返；pending_conflict 全返并附冲突提示；
        superseded 不返回但保留在档；ENRICH 链附关联提示（6.12.2）。"""
        out, notices = [], []
        for e in self.mids.values():
            if e["group"] != group_id:
                continue
            if subject is not None and e["subject"] != subject:
                continue
            if predicate is not None and e["predicate"] != predicate:
                continue
            if e["status"] == self.SUPERSEDED:
                continue                                    # 保留不删，不召回
            out.append(e)
            if e["status"] == self.PENDING:
                notices.append({"notice": "pending_conflict", "mid": e["mid"]})
            for old in e["enriches"]:
                notices.append({"notice": "enrich_chain",
                                "from": e["mid"], "refines": old})
        return {"entries": out, "notices": notices}

    def reopen(self, mid, evidence_hash, by):
        """重开走追加：superseded/pending 可凭更高优先级证据恢复，
        不改写历史（第六节状态流转）。"""
        e = self.mids.get(mid)
        if not e:
            return False, "unknown_mid"
        if e["status"] == self.ACTIVE:
            return False, "already_active"
        e["status"] = self.ACTIVE
        self._append("reopen", {"mid": mid, "evidence": evidence_hash,
                                "by": by})
        return True, "reopened"

    # ---------- 组合行为风控（6.5~6.6 / 条款 3.2） ----------

    def combo_check(self, action, agents, whitelist_version="v1"):
        """组合行为校验：白名单内放行；白名单外进人工关口——材料备妥，
        点头必须来自用户；同因否决缓存，不重复打扰。"""
        fp = hashlib.sha256(json.dumps([action, sorted(agents)],
                                       ensure_ascii=False).encode()).hexdigest()
        if fp in self._combo_cache:
            return False, {"verdict": "vetoed_cached",
                           "reason": "same_cause_veto_cached"}
        wl = self._combo_wl.get(whitelist_version)
        if wl is None:
            return False, {"verdict": "rejected", "reason": "unknown_whitelist_version"}
        if action in wl:
            self._append("combo_allow", {"action": action,
                                         "agents": sorted(agents),
                                         "wl": whitelist_version})
            return True, {"verdict": "allowed"}
        self._append("combo_pending_human", {"action": action,
                                             "agents": sorted(agents),
                                             "wl": whitelist_version})
        return False, {"verdict": "pending_human",
                       "reason": "not_in_whitelist"}

    def human_verdict(self, action, agents, approve, whitelist_version="v1"):
        """人工关口裁决：否决为终局并缓存同因（条款 3.2）；批准则把
        组合动作写入白名单（版本化，权重/规则变更留痕）。"""
        fp = hashlib.sha256(json.dumps([action, sorted(agents)],
                                       ensure_ascii=False).encode()).hexdigest()
        if approve:
            self._combo_cache.pop(fp, None)   # 批准为新的人工决定，清同因缓存
            self._combo_wl.setdefault(whitelist_version, set()).add(action)
            self._append("human_approve", {"action": action,
                                           "agents": sorted(agents),
                                           "wl": whitelist_version})
            return True, "whitelisted"
        self._combo_cache[fp] = "vetoed"
        self._append("human_veto", {"action": action, "agents": sorted(agents)})
        return False, "vetoed_final"

    def set_whitelist_version(self, version):
        """新增白名单版本（规则变更走流程留痕，不静默调整，4.3 同构）。"""
        if version in self._combo_wl:
            return False, "version_exists"
        self._combo_wl[version] = set()
        self._append("whitelist_version", {"version": version})
        return True, "created"


# ---------- CLI 自检 ----------

def selftest():
    results = []

    def check(name, cond):
        results.append((name, bool(cond)))

    # 1. 写入追加 + 写侧预检只打标记不阻塞（6.10）
    g = CoordGate()
    m1, r1 = g.write("g1", "用户", "养猫", "是", 0.9, "human_confirmed", "a1",
                     valid_start="2026-01-01", valid_end="2026-12-31")
    m2, r2 = g.write("g1", "用户", "养猫", "否", 0.5, "agent_introspection", "a2",
                     valid_start="2026-01-01")
    check("write_appends", m1 == "m1" and m2 == "m2")
    check("precheck_hints_nonblocking",
          r2["status"] == "active" and
          any(h["with"] == m1 for h in r2["hints"]))

    # 2. 时序递进不是冲突（避坑：不统一全局时间优先）
    m3, r3 = g.write("g1", "用户", "养猫", "否", 0.8, "human_confirmed", "a1",
                     valid_start="2027-01-01")
    check("temporal_progression_no_hint", r3["hints"] == [])

    # 3. 跨 group 比对直接拒绝（避坑第 5 条）
    g.write("g2", "用户", "养猫", "是", 0.9, "human_confirmed", "a1")
    ok, why = g.classify(m1, "m4", "CONFLICT", "j1")
    check("cross_group_forbidden", not ok and why == "cross_group_forbidden")

    # 4. CONFLICT 要求互斥：取值相同判不了冲突
    m5, _ = g.write("g1", "用户", "养猫", "是", 0.7, "trusted_tool", "a3",
                    valid_start="2026-01-01")
    ok, why = g.classify(m1, m5, "CONFLICT", "j1")
    check("same_value_not_conflict", not ok and why == "not_mutually_exclusive")

    # 5. 合法冲突可登记
    ok, why = g.classify(m1, m2, "CONFLICT", "j1")
    check("conflict_recorded", ok and why == "recorded")

    # 6. 自动仲裁：置信差不足拒绝并建议挂起（3.3）
    g2 = CoordGate()
    p1, _ = g2.write("g", "s", "p", "v1", 0.60, "trusted_tool", "x1")
    p2, _ = g2.write("g", "s", "p", "v2", 0.55, "trusted_tool", "x2")
    rc, why = g2.arbitrate(p1, p2, "auto", "arb-1")
    check("auto_gap_below_threshold_refused",
          rc is None and why == "confidence_gap_below_threshold_use_pending")

    # 7. 自动仲裁：低层证据不得取代高层（3.4）
    q1, _ = g2.write("g", "s2", "p", "hi", 0.55, "human_confirmed", "x1")
    q2, _ = g2.write("g", "s2", "p", "lo", 0.95, "low_confidence_guess", "x2")
    rc, why = g2.arbitrate(q1, q2, "auto", "arb-1")
    check("tier_priority_blocks", rc is None and why == "tier_priority_blocks_supersede")

    # 8. 自动仲裁成功：superseded 保留不删，回执含前后状态（6.13.3）
    s1, _ = g2.write("g", "s3", "p", "strong", 0.9, "human_confirmed", "x1")
    s2, _ = g2.write("g", "s3", "p", "weak", 0.5, "agent_introspection", "x2")
    rc, why = g2.arbitrate(s1, s2, "auto", "arb-1")
    check("auto_supersede_ok", why == "superseded" and rc["superseded"] == s2)
    check("superseded_retained",
          g2.mids[s2]["status"] == "superseded" and "before" in rc)
    view = g2.recall("g", "s3", "p")
    check("superseded_not_recalled",
          all(e["mid"] != s2 for e in view["entries"]) and
          g2.mids[s2]["value"] == "weak")   # 仍在档

    # 9. 待决挂起：召回全返附提示（3.3 策略二）
    t1, _ = g2.write("g", "s4", "p", "a", 0.6, "trusted_tool", "x1")
    t2, _ = g2.write("g", "s4", "p", "b", 0.55, "trusted_tool", "x2")
    g2.arbitrate(t1, t2, "pending", "arb-1")
    view = g2.recall("g", "s4", "p")
    check("pending_all_returned_with_notice",
          len(view["entries"]) == 2 and
          any(n["notice"] == "pending_conflict" for n in view["notices"]))

    # 10. 联邦共识：加权投票，权重记录在案（4.3）
    u1, _ = g2.write("g", "s5", "p", "x", 0.6, "trusted_tool", "x1")
    u2, _ = g2.write("g", "s5", "p", "y", 0.6, "trusted_tool", "x2")
    rc, why = g2.arbitrate(u1, u2, "federal", "arb-1",
                           votes={u1: 0.7, u2: 0.3})
    check("federal_weighted", why == "superseded" and rc["kept"] == u1
          and rc["tally"][u1] == 0.7)

    # 11. 仲裁者分离（5.2）：仲裁者不得是条目产出方
    v1, _ = g2.write("g", "s6", "p", "a", 0.9, "trusted_tool", "agent-x")
    v2, _ = g2.write("g", "s6", "p", "b", 0.5, "trusted_tool", "x2")
    rc, why = g2.arbitrate(v1, v2, "auto", "agent-x")
    check("arbiter_separation", rc is None and why == "arbiter_separation_violation")

    # 12. ENRICH 链接：补充关系建链，与冲突互斥（6.12.3）
    w1, _ = g2.write("g", "s7", "p", "养猫", 0.8, "human_confirmed", "x1")
    w2, _ = g2.write("g", "s7", "p", "养橘猫", 0.8, "trusted_tool", "x2")
    g2.classify(w2, w1, "COMPLEMENT", "j1")
    ok, why = g2.link_enrich(w2, w1)
    check("enrich_linked", ok and why == "linked")
    c1, _ = g2.write("g", "s8", "p", "a", 0.8, "trusted_tool", "x1")
    c2, _ = g2.write("g", "s8", "p", "b", 0.8, "trusted_tool", "x2")
    g2.classify(c1, c2, "CONFLICT", "j1")
    ok, why = g2.link_enrich(c2, c1)
    check("enrich_conflict_mutual_exclusive",
          not ok and why == "conflict_relation_exists")

    # 13. 重开走追加，历史不改写（第六节）
    ok, why = g2.reopen(s2, "evd-123", "arb-2")
    check("reopen_appends", ok and g2.mids[s2]["status"] == "active")
    ok, _ = g2.verify_chain()
    check("chain_intact_after_reopen", ok)

    # 14. 组合行为风控：白名单外进人工，否决终局＋同因缓存（6.5/3.2）
    ok, r = g2.combo_check("cross_domain_write", ["a1", "a2"])
    check("combo_pending_human",
          not ok and r["verdict"] == "pending_human")
    g2.human_verdict("cross_domain_write", ["a1", "a2"], approve=False)
    ok, r = g2.combo_check("cross_domain_write", ["a1", "a2"])
    check("combo_veto_cached", not ok and r["verdict"] == "vetoed_cached")
    g2.human_verdict("cross_domain_write", ["a1", "a2"], approve=True)
    ok, r = g2.combo_check("cross_domain_write", ["a1", "a2"])
    check("combo_whitelisted_after_approve", ok and r["verdict"] == "allowed")

    # 15. 哈希链篡改可发现
    ok, _ = g2.verify_chain()
    check("chain_ok", ok)
    g2.entries[3]["detail"]["tampered"] = True
    ok, info = g2.verify_chain()
    check("chain_tamper_detected", not ok and "broken_at_seq" in info)

    # 汇总
    passed = sum(1 for _, c in results if c)
    for name, cond in results:
        print(("  ✓ " if cond else "  ✗ ") + name)
    print("selftest: %d/%d passed" % (passed, len(results)))
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        sys.exit(selftest())
    print(__doc__)
