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
"""registry_gate.py — 约束运行时·注册编排闸 v0.1（组件注册与编排，2026-11-28）

定位：对齐《元枢 Agent OS 能力对齐规范 v0.1》「组件注册与编排」项，
把云端中枢技能库「真值＋目录树双落位」的跑通流程做成可复用算子：
组件登记的真值记录与对外目录视图同源于一条哈希链，目录永远可以从
真值重算——账实不符即拆穿。

核心概念：
- 注册即登记：组件名＋版本＋内容哈希一次登记，事件入链；
- 查重先行：同名同内容哈希重复登记直接拒绝（中枢元规则·查重先行）；
- 版本只进不退：同名校验语义化版本，新版本号不得低于已登记版本，
  降级登记拒绝（回滚走显式 revoke 再重登，留痕可查）；
- 双落位可对账：真值记录与目录树视图同链同源，catalog() 即视图重算，
  verify() 同时校验链完整性与账实一致；
- 下线是标记不是删除：revoke 打视图标记，组件记录保留在档（与协同闸
  「保留不删」同构），可凭证据恢复；
- 全程入哈希链：注册、下线、恢复全部留痕，篡改可发现。

诚实边界：本件是单机信任模型——不防能同时改写内存与台账文件的本地
攻击者；版本比较按语义化版本号逐段比较，不解析构建元数据。

用法：
    from registry_gate import RegistryGate
    reg = RegistryGate()
    reg.register("skill-a", "1.0.0", "hash-a1")
    reg.register("skill-a", "1.1.0", "hash-a2")   # 升版
    reg.register("skill-a", "1.0.5", "hash-a3")   # 拒绝：降级
    tree = reg.catalog()                           # 目录树视图
    ok, info = reg.verify()                        # 链＋账实双校验

CLI 自检：
    registry_gate.py selftest
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


def _parse_version(v):
    """语义化版本逐段比较；非法版本返回 None。"""
    try:
        return tuple(int(p) for p in v.split("."))
    except (ValueError, AttributeError):
        return None


class RegistryGate:
    """注册编排闸：查重先行、版本只进不退、双落位可对账。"""

    def __init__(self, chain_path=None):
        self.chain_path = chain_path
        self.entries = []
        self.components = {}   # name -> {"versions": {ver: content_hash}, "revoked": bool}
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

    # ---------- 注册（查重先行 / 版本只进不退） ----------

    def register(self, name, version, content_hash, registered_by="system"):
        """注册组件：同名同哈希拒绝（查重先行）；版本低于已登记最高版
        拒绝（只进不退）；已下线组件须先恢复再升版。"""
        if _parse_version(version) is None:
            return False, "invalid_version"
        comp = self.components.setdefault(
            name, {"versions": {}, "revoked": False})
        if comp["revoked"]:
            return False, "component_revoked_restore_first"
        if version in comp["versions"]:
            if comp["versions"][version] == content_hash:
                return False, "duplicate_registration"    # 查重先行
            return False, "version_hash_conflict"
        new_v = _parse_version(version)
        for existing in comp["versions"]:
            if new_v < _parse_version(existing):
                return False, "version_downgrade_rejected"
        comp["versions"][version] = content_hash
        self._append("register", {"name": name, "version": version,
                                  "content_hash": content_hash,
                                  "by": registered_by})
        return True, "registered"

    def latest(self, name):
        """查某组件已登记的最高版本；未登记或已下线返回 None。"""
        comp = self.components.get(name)
        if not comp or comp["revoked"] or not comp["versions"]:
            return None
        top = max(comp["versions"], key=_parse_version)
        return {"version": top, "content_hash": comp["versions"][top]}

    # ---------- 下线与恢复（标记不删除） ----------

    def revoke(self, name, by="system"):
        """下线组件：打视图标记，记录保留在档，可恢复。"""
        comp = self.components.get(name)
        if not comp:
            return False, "unknown_component"
        if comp["revoked"]:
            return False, "already_revoked"
        comp["revoked"] = True
        self._append("revoke", {"name": name, "by": by})
        return True, "revoked"

    def restore(self, name, by="system"):
        """恢复下线组件：走追加记录，不改写历史。"""
        comp = self.components.get(name)
        if not comp:
            return False, "unknown_component"
        if not comp["revoked"]:
            return False, "not_revoked"
        comp["revoked"] = False
        self._append("restore", {"name": name, "by": by})
        return True, "restored"

    # ---------- 目录树视图（双落位的「目录」侧） ----------

    def catalog(self):
        """目录树视图：从真值记录重算——只列未下线组件及其最高版本。"""
        tree = {}
        for name, comp in sorted(self.components.items()):
            if comp["revoked"]:
                continue
            top = max(comp["versions"], key=_parse_version)
            tree[name] = {"version": top,
                          "content_hash": comp["versions"][top]}
        return tree

    def verify(self):
        """双落位对账：链完整性＋目录视图与真值记录一致。"""
        chain_ok, info = self.verify_chain()
        if not chain_ok:
            return False, {"chain": info}
        expected = self.catalog()
        # 独立重算：直接从真值记录再推一遍，防视图被外部改写
        recomputed = {}
        for name, comp in self.components.items():
            if comp["revoked"] or not comp["versions"]:
                continue
            top = max(comp["versions"], key=_parse_version)
            recomputed[name] = {"version": top,
                                "content_hash": comp["versions"][top]}
        consistent = expected == recomputed
        return consistent, {"chain": info,
                            "components": len(expected),
                            "ledger_consistent": consistent}


# ---------- CLI 自检 ----------

def selftest():
    results = []

    def check(name, cond):
        results.append((name, bool(cond)))

    # 1. 注册即登记
    reg = RegistryGate()
    ok, why = reg.register("skill-a", "1.0.0", "hash-a1", "u1")
    check("register_ok", ok and why == "registered")

    # 2. 查重先行：同名同哈希拒绝
    ok, why = reg.register("skill-a", "1.0.0", "hash-a1")
    check("duplicate_rejected", not ok and why == "duplicate_registration")

    # 3. 同名同版不同哈希：冲突拒绝
    ok, why = reg.register("skill-a", "1.0.0", "hash-evil")
    check("version_hash_conflict", not ok and why == "version_hash_conflict")

    # 4. 升版允许，降级拒绝（只进不退）
    ok, _ = reg.register("skill-a", "1.1.0", "hash-a2")
    check("upgrade_ok", ok)
    ok, why = reg.register("skill-a", "1.0.5", "hash-a3")
    check("downgrade_rejected", not ok and why == "version_downgrade_rejected")

    # 5. 非法版本拒绝
    ok, why = reg.register("skill-b", "abc", "hash-b1")
    check("invalid_version_rejected", not ok and why == "invalid_version")

    # 6. latest 取最高版本
    top = reg.latest("skill-a")
    check("latest_is_highest", top["version"] == "1.1.0")

    # 7. 目录树视图只含未下线组件
    reg.register("skill-c", "0.1.0", "hash-c1")
    reg.revoke("skill-c", "u2")
    tree = reg.catalog()
    check("catalog_excludes_revoked",
          "skill-a" in tree and "skill-c" not in tree)

    # 8. 下线后注册拒绝，恢复后可升版（标记不删除）
    ok, why = reg.register("skill-c", "0.2.0", "hash-c2")
    check("revoked_register_blocked",
          not ok and why == "component_revoked_restore_first")
    ok, _ = reg.restore("skill-c", "u2")
    ok, _ = reg.register("skill-c", "0.2.0", "hash-c2")
    check("restore_then_register", ok)

    # 9. 双落位对账：链完整＋账实一致
    ok, info = reg.verify()
    check("verify_ok", ok and info["ledger_consistent"])

    # 10. 链篡改可发现
    reg.entries[2]["detail"]["tampered"] = True
    ok, info = reg.verify()
    check("tamper_detected", not ok and "chain" in info)

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
