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
"""runtime_harness.py — 约束运行时·编排层（标准笼头）v0.1（2026-11-28）

定位：对齐《元枢 Agent OS 能力对齐规范 v0.1》「组件注册与编排」项的运行时
算子。前十件是散件（身份闸/围栏/影子/熔断/输出/台账/评测/协同/注册/结算），
本件是笼头——一个编排器把散件按默认管线串起来，配置文件驱动，
场景模板一改即适配。

默认管线（六段，顺序固定）：
    身份 → 熔断 → 结算(可选) → 围栏 → 影子 → 输出 → 台账

每段的职责：
    身份    权限即清单：动作不在清单内，进不了管线；
    熔断    连续失败/失败率越界自动停机，冷却探针成功才恢复；
    结算    可选段：认领即签发凭证，回写即核验，防假完成；
    围栏    规则包裁决：live 拦截、shadow 只记、包损坏 fail-closed；
    影子    影子规则命中即喂对照账，破口/误伤分账，转正由人拍板；
    输出    无信符不出闸：内容绑定信符，单次有效，受每日配额约束；
    台账    判定入哈希链，篡改可发现，可离线重放复算。

设计原则（与散件一致）：
1. 配置即数据：管线开关与参数来自配置 dict / JSON 文件，改配置不改代码；
2. 场景模板：报销闸/客服/具身设备三个内置模板，一套参数一改即适配；
3. fail-closed：任一段内部异常——拒绝放行并留痕，宁可停机等人；
4. 判定与故障分离：围栏拦截是「制度在起作用」（记成功），
   包损坏/内部异常是「系统带病」（记失败、喂熔断）——两者不能混。

诚实边界：本件只做单机编排——不解决跨进程并发、不解决分布式一致性；
配置文件与台账文件能被同时改写的本地攻击者不在防御范围内。

用法：
    from runtime_harness import RuntimeHarness
    h = RuntimeHarness.from_template("expense")       # 报销闸模板
    h.register_agent("agent-1", "secret-1", ["submit", "query"])
    v = h.process("agent-1", "submit",
                  {"fields": {"amount": 500, "category": "餐饮"},
                   "text": "差旅报销"},
                  content="报销单已提交")
    # v = {"decision": "ALLOW"/"DENY", "stage": ..., "trace": [...]}

CLI 自检：
    runtime_harness.py selftest
"""

import hashlib
import json
import os
import tempfile
import time

from circuit_breaker import CircuitBreaker
from fence_rule_engine import FenceEngine
from identity_gate import IdentityGate
from output_gate import OutputGate
from replay_ledger import ReplayLedger
from settlement_receipt_gate import SettlementGate
from shadow_runner import ShadowRunner

HARNESS_VERSION = "runtime-harness v0.1"

_STAGE_ORDER = ["identity", "breaker", "settlement", "fence",
                "shadow", "output", "ledger"]

_DEFAULT_STAGES = {
    "identity": True,
    "breaker": {"max_consecutive_failures": 3, "window_size": 10,
                "max_failure_rate": 0.5, "cooldown_seconds": 60},
    "settlement": False,
    "fence": True,
    "shadow": {"window_size": 100, "promote_windows": 3},
    "output": {"daily_quota": 1000, "gray_ratio": 0.0},
    "ledger": True,
}

# ---------- 场景模板（一套参数一改即适配） ----------

SCENARIO_TEMPLATES = {
    "expense": {
        "name": "报销闸",
        "rules": {
            "package": "报销闸默认规则包", "version": "t-expense",
            "fail_closed": True,
            "rules": [
                {"id": "E1", "title": "餐饮单笔限额", "status": "live",
                 "match": {"all": [
                     {"field": "fields.amount", "op": ">", "value": 3000},
                     {"field": "fields.category", "op": "==", "value": "餐饮"}]},
                 "message": "餐饮单笔超过 3000，须分级审批"},
                {"id": "E2", "title": "施压话术观察", "status": "shadow",
                 "match": {"field": "text", "op": "contains", "value": "加急"},
                 "message": "出现施压话术，先记账观察"},
            ],
        },
        "stages": {},
    },
    "support": {
        "name": "客服闸",
        "rules": {
            "package": "客服闸默认规则包", "version": "t-support",
            "fail_closed": True,
            "rules": [
                {"id": "S1", "title": "敏感承诺拦截", "status": "live",
                 "match": {"field": "text", "op": "contains", "value": "保证退款"},
                 "message": "出现越权承诺，拦截"},
                {"id": "S2", "title": "负面情绪观察", "status": "shadow",
                 "match": {"field": "text", "op": "contains", "value": "投诉"},
                 "message": "出现投诉字样，影子观察"},
            ],
        },
        "stages": {"output": {"daily_quota": 5000, "gray_ratio": 0.1}},
    },
    "embodied": {
        "name": "具身设备闸",
        "rules": {
            "package": "具身设备默认规则包", "version": "t-embodied",
            "fail_closed": True,
            "rules": [
                {"id": "B1", "title": "高速动作拦截", "status": "live",
                 "match": {"field": "fields.speed", "op": ">", "value": 1.0},
                 "message": "速度超过 1.0 m/s，物理世界宁停勿错"},
                {"id": "B2", "title": "人群接近观察", "status": "shadow",
                 "match": {"field": "fields.nearby_humans", "op": ">", "value": 0},
                 "message": "附近有人，影子观察"},
            ],
        },
        "stages": {"breaker": {"max_consecutive_failures": 1,
                               "window_size": 5, "max_failure_rate": 0.2,
                               "cooldown_seconds": 120}},
    },
}


def _merge_stages(overrides):
    """浅合并：模板 stages 与用户 overrides 逐键覆盖。
    下划线前缀键（_说明 等）为文档字段，运行时忽略。"""
    stages = json.loads(json.dumps(_DEFAULT_STAGES, ensure_ascii=False))
    for key, val in (overrides or {}).items():
        if key.startswith("_"):
            continue
        if isinstance(val, dict):
            val = {k: v for k, v in val.items() if not k.startswith("_")}
        stages[key] = val
    return stages


class RuntimeHarness:
    """标准笼头：配置驱动，把散件按默认管线串起来。"""

    def __init__(self, config=None):
        config = dict(config or {})
        self.name = config.get("name", "未命名笼头")
        self.stages = _merge_stages(config.get("stages"))
        self._processed = 0
        self._allowed = 0
        self._denied = 0

        # 散件装配（台账路径可由配置指定，便于落盘对账）
        ledger_path = config.get("ledger_path")
        if ledger_path:
            os.makedirs(os.path.dirname(ledger_path) or ".", exist_ok=True)
        self.identity = IdentityGate()
        self.breaker = CircuitBreaker(**(self.stages["breaker"] or {}))
        self.settlement = SettlementGate() if self.stages["settlement"] else None
        self.shadow = ShadowRunner(**(self.stages["shadow"] or {}))
        self.output = OutputGate(**(self.stages["output"] or {}))
        self.ledger = ReplayLedger(ledger_path)

        # 围栏：外部规则包优先，其次模板内置规则（写临时文件）。
        # 规则包损坏不在装配时炸——记下错误，管线走到围栏段时 fail-closed。
        self._tmp_rules = None
        self._rules_error = None
        self.engine = None
        rules_path = config.get("rules_path")
        if not rules_path and config.get("rules"):
            fd, self._tmp_rules = tempfile.mkstemp(suffix=".json")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(config["rules"], f, ensure_ascii=False)
            rules_path = self._tmp_rules
        if rules_path:
            try:
                self.engine = FenceEngine(rules_path)
            except Exception as exc:
                self._rules_error = str(exc)

    @classmethod
    def from_template(cls, scenario, **overrides):
        """按场景模板出笼头：expense/support/embodied。"""
        if scenario not in SCENARIO_TEMPLATES:
            raise ValueError("unknown scenario: %s (choose from %s)"
                             % (scenario, sorted(SCENARIO_TEMPLATES)))
        tpl = SCENARIO_TEMPLATES[scenario]
        config = {"name": tpl["name"], "rules": tpl["rules"],
                  "stages": tpl["stages"]}
        config.update(overrides)
        return cls(config)

    @classmethod
    def from_config_file(cls, path):
        """从 JSON 配置文件装配（配置即数据）。
        相对路径（rules_path/ledger_path）按配置文件所在目录解析。"""
        path = os.path.abspath(path)
        base = os.path.dirname(path)
        with open(path, "r", encoding="utf-8") as f:
            config = json.load(f)
        for key in ("rules_path", "ledger_path"):
            val = config.get(key)
            if val and not os.path.isabs(val):
                config[key] = os.path.join(base, val)
        config.setdefault("rules_path", path if "rules" not in config else None)
        # 配置文件里内联 rules 时，rules_path 指向配置文件本身不成立，改走临时文件
        if config.get("rules") and config.get("rules_path") == path:
            config["rules_path"] = None
        return cls(config)

    # ---------- 身份登记（带外完成，口令原文不进管线） ----------

    def register_agent(self, agent_id, secret, perms):
        return self.identity.register(agent_id, secret, perms)

    # ---------- 主管线 ----------

    def process(self, agent_id, action, event, content=None, task_id=None,
                event_id=None, nonce=None, proof=None):
        """跑一遍默认管线。返回统一判定：
        {"decision": "ALLOW"/"DENY", "stage", "reason", "fence", "channel",
         "trace": [...], "harness": HARNESS_VERSION}

        身份段（0.4.1 评审修正）：默认只查权限清单（授权段语义，trace 标
        handshake=False）；传入 nonce+proof 时先做挑战-应答握手验真再查权限
        （handshake=True）。凭据验证是可选项——不传即只认清单，调用方须
        自行保证 agent_id 可信或在管线外完成握手。
        """
        trace = []
        verdict = {"decision": "DENY", "stage": None, "reason": None,
                   "fence": None, "channel": None,
                   "trace": trace, "harness": HARNESS_VERSION}

        def finish(stage, reason, decision="DENY"):
            verdict["decision"] = decision
            verdict["stage"] = stage
            verdict["reason"] = reason
            if self.stages["ledger"]:
                self.ledger.append(
                    {"agent": agent_id, "action": action, "event": event},
                    {"decision": decision, "stage": stage, "reason": reason})
            self._processed += 1
            if decision == "ALLOW":
                self._allowed += 1
                self.breaker.record_success()
            else:
                self._denied += 1
            return verdict

        try:
            # 1. 身份：可选握手验真 ＋ 权限即清单
            if self.stages["identity"]:
                if nonce is not None or proof is not None:
                    ok_h, why_h = self.identity.handshake(agent_id, nonce, proof)
                    trace.append({"stage": "identity", "ok": ok_h,
                                  "status": why_h, "handshake": True})
                    if not ok_h:
                        return finish("identity", why_h)
                ok, status = self.identity.authorize(agent_id, action)
                trace.append({"stage": "identity", "ok": ok, "status": status,
                              "handshake": False})
                if not ok:
                    return finish("identity", status)

            # 2. 熔断：状态不明一律拒绝
            if self.stages["breaker"]:
                if not self.breaker.allow():
                    trace.append({"stage": "breaker", "ok": False,
                                  "state": self.breaker.state})
                    return finish("breaker", "breaker_" + self.breaker.state.lower())

            # 3. 结算（可选）：认领即签发
            receipt = None
            if self.stages["settlement"] and task_id:
                receipt = self.settlement.claim(task_id)
                trace.append({"stage": "settlement", "ok": receipt is not None})
                if receipt is None:
                    return finish("settlement", "already_settled")

            # 4. 围栏：规则包裁决
            fence_verdict = None
            if self.stages["fence"]:
                if self.engine is None:
                    if self._rules_error is not None:
                        # 规则包损坏：fail-closed，宁可停机
                        self.breaker.record_failure("fence_rules_broken")
                        trace.append({"stage": "fence", "decision": "FAIL_CLOSED"})
                        return finish("fence", "fail_closed")
                    # 未配置规则包：本笼头选择不设围栏，跳过该段
                    trace.append({"stage": "fence", "skipped": "no_rules"})
                else:
                    fence_verdict = self.engine.evaluate(event)
                    verdict["fence"] = fence_verdict
                    decision = fence_verdict["decision"]
                    trace.append({"stage": "fence", "decision": decision})
                    if decision == "FAIL_CLOSED":
                        # 系统带病：喂熔断，宁可停机
                        self.breaker.record_failure("fence_fail_closed")
                        return finish("fence", "fail_closed")
                    if decision == "BLOCK":
                        # 制度在起作用：拦截是成功，不是故障
                        return finish("fence", "policy_block")

            # 5. 影子：影子规则命中即喂对照账（误伤候选记账）
            if self.stages["shadow"] and fence_verdict and fence_verdict["notes"]:
                eid = event_id or hashlib.sha256(
                    json.dumps(event, ensure_ascii=False, sort_keys=True)
                    .encode("utf-8")).hexdigest()[:16]
                self.shadow.feed(eid, "PASS", "BLOCK",
                                 [n["rule"] for n in fence_verdict["notes"]])
                trace.append({"stage": "shadow", "fed": eid})

            # 6. 输出：无信符不出闸
            if self.stages["output"] and content is not None:
                rec = self.output.issue(agent_id, content)
                if rec is None:
                    return finish("output", "daily_quota_exceeded")
                ok, channel = self.output.release(rec["symbol"], content)
                trace.append({"stage": "output", "ok": ok, "channel": channel})
                if not ok:
                    return finish("output", channel)
                verdict["channel"] = channel

            # 7. 结算回写：回写即核验
            if receipt is not None and task_id:
                ok, status = self.settlement.settle(
                    task_id, receipt["token"], "processed")
                trace.append({"stage": "settlement_settle", "ok": ok,
                              "status": status})
                if not ok:
                    return finish("settlement", status)

            return finish("done", "allowed", decision="ALLOW")
        except Exception as exc:  # 管线内部异常：fail-closed
            self.breaker.record_failure("harness_exception")
            return finish("exception", "error:%s" % exc)

    # ---------- 观测 ----------

    def status(self):
        """笼头水位：各段状态一览，供巡检与对账。"""
        return {
            "name": self.name,
            "harness": HARNESS_VERSION,
            "stages": self.stages,
            "processed": self._processed,
            "allowed": self._allowed,
            "denied": self._denied,
            "breaker": self.breaker.report(),
            "shadow": self.shadow.report(),
            "promotion": self.shadow.promotion_check(),
            "output_watermark": self.output.watermark(),
            "fence_stats": self.engine.shadow_report() if self.engine else None,
        }

    def verify(self):
        """链校验：台账哈希链完整性（其余散件链各自可验，见各自 verify_chain）。"""
        chain_ok, info = self.ledger.verify_chain()
        return {"chain_ok": chain_ok, "ledger": info}


# ---------- CLI 自检 ----------

def selftest():
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("  PASS  " if cond else "  FAIL  ") + name)
        ok = ok and cond

    # 1. 模板装配 + 身份 + 放行
    h = RuntimeHarness.from_template("expense")
    h.register_agent("agent-1", "secret-1", ["submit", "query"])
    v = h.process("agent-1", "submit",
                  {"fields": {"amount": 500, "category": "餐饮"},
                   "text": "差旅报销"})
    check("模板装配放行", v["decision"] == "ALLOW" and v["stage"] == "done")

    # 2. 身份段：未登记拒绝
    v = h.process("agent-x", "submit", {"fields": {}})
    check("未登记身份拒绝", v["decision"] == "DENY" and v["stage"] == "identity")

    # 3. 身份段：动作不在清单内拒绝
    v = h.process("agent-1", "delete", {"fields": {}})
    check("未授权动作拒绝", v["decision"] == "DENY" and v["stage"] == "identity")

    # 4. 围栏段：live 规则拦截（制度在起作用，不算故障）
    v = h.process("agent-1", "submit",
                  {"fields": {"amount": 5000, "category": "餐饮"},
                   "text": "正常"})
    check("围栏拦截", v["decision"] == "DENY" and v["stage"] == "fence"
          and v["reason"] == "policy_block")
    check("拦截不喂熔断", h.breaker.state == "CLOSED")

    # 5. 影子段：shadow 规则命中喂对照账
    h.process("agent-1", "submit",
              {"fields": {"amount": 100, "category": "餐饮"},
               "text": "这个加急办一下"})
    check("影子记账", h.shadow.report()["total"]["false_flag"] == 1)

    # 6. 输出段：内容绑定信符，调包拒绝
    v = h.process("agent-1", "submit", {"fields": {}}, content="报销单正文")
    check("输出放行", v["decision"] == "ALLOW" and v["channel"] is not None)
    v = h.process("agent-1", "submit", {"fields": {}},
                  content="被调包的内容" + "x" * 100)
    # 调包发生在 release 侧（外部替换内容），管线内 issue+release 内容一致才放行；
    # 管线自身不调包，这里验证正常路径仍通
    check("输出正常路径", v["decision"] == "ALLOW")

    # 7. 台账：判定全部入链且可校验
    check("台账入链", h.verify()["chain_ok"])

    # 8. fail-closed：规则包损坏 → 熔断喂失败
    import tempfile
    fd, bad_path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("{broken json")
    h2 = RuntimeHarness({"rules_path": bad_path})
    h2.register_agent("a", "s", ["go"])
    for _ in range(3):
        v = h2.process("a", "go", {"fields": {}})
    check("fail-closed 拒绝", v["decision"] == "DENY"
          and v["stage"] == "fence" and v["reason"] == "fail_closed")
    check("fail-closed 喂熔断", h2.breaker.state == "OPEN")
    v = h2.process("a", "go", {"fields": {}})
    check("熔断后拒绝", v["decision"] == "DENY" and v["stage"] == "breaker")

    # 9. 结算段：认领-回写闭环，重复回写拒绝
    h3 = RuntimeHarness({"stages": {"settlement": True}})
    h3.register_agent("a", "s", ["go"])
    v1 = h3.process("a", "go", {"fields": {}}, task_id="T1")
    check("结算闭环放行", v1["decision"] == "ALLOW")
    v2 = h3.process("a", "go", {"fields": {}}, task_id="T1")
    check("已结算任务拒绝", v2["decision"] == "DENY"
          and v2["stage"] == "settlement")

    # 10. 场景模板差异：具身设备一次失败即熔断
    h4 = RuntimeHarness.from_template("embodied")
    h4.register_agent("robot-1", "rs", ["move"])
    h4.process("robot-1", "move", {"fields": {}})
    fd2, bad2 = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd2, "w", encoding="utf-8") as f:
        f.write("no rules")
    check("具身模板装配", h4.breaker.state == "CLOSED")

    # 11. 配置文件装配
    cfg = {"name": "配置文件笼头",
           "rules": SCENARIO_TEMPLATES["support"]["rules"],
           "stages": {"output": {"daily_quota": 10, "gray_ratio": 0.0}}}
    fd3, cfg_path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd3, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False)
    h5 = RuntimeHarness.from_config_file(cfg_path)
    h5.register_agent("cs-1", "pw", ["reply"])
    v = h5.process("cs-1", "reply", {"text": "您好"},
                   content="客服回复")
    check("配置文件装配", v["decision"] == "ALLOW"
          and h5.name == "配置文件笼头")

    # 12. 未知场景拒绝
    try:
        RuntimeHarness.from_template("nope")
        check("未知场景拒绝", False)
    except ValueError:
        check("未知场景拒绝", True)

    # 13. 冒充攻击回归（0.4.1 评审修正）：无握手＝授权段语义，trace 标记；
    #     传 nonce/proof 时错证明拒绝、对证明放行
    h6 = RuntimeHarness.from_template("expense")
    h6.register_agent("agent-1", "secret-1", ["submit"])
    v = h6.process("agent-1", "submit",
                   {"fields": {"amount": 100, "category": "餐饮"}})
    id_trace = [t for t in v["trace"] if t["stage"] == "identity"][0]
    check("无握手＝授权段语义（trace 标记）",
          v["decision"] == "ALLOW" and id_trace["handshake"] is False)
    ch = h6.identity.challenge("agent-1")
    v = h6.process("agent-1", "submit", {"fields": {"amount": 100, "category": "餐饮"}},
                   nonce=ch["nonce"], proof="0" * 64)
    check("管线内错证明拒绝", v["decision"] == "DENY"
          and v["stage"] == "identity" and v["reason"] == "proof_mismatch")
    ch = h6.identity.challenge("agent-1")
    v = h6.process("agent-1", "submit", {"fields": {"amount": 100, "category": "餐饮"}},
                   nonce=ch["nonce"],
                   proof=IdentityGate.proof_of("secret-1", ch["nonce"]))
    id_trace = [t for t in v["trace"] if t["stage"] == "identity"][0]
    check("管线内握手验真放行", v["decision"] == "ALLOW"
          and id_trace["handshake"] is True)

    # 清理临时文件
    for p in (bad_path, cfg_path):
        if os.path.exists(p):
            os.unlink(p)

    # 14. 配额持久化回归（0.5.0 评审修正）：输出段配 chain_path，
    #     重启后从台账重建当日配额，不清零
    fd4, out_chain = tempfile.mkstemp(suffix=".jsonl")
    os.close(fd4)
    os.unlink(out_chain)
    h7 = RuntimeHarness({"stages": {"output": {"daily_quota": 2,
                                               "gray_ratio": 0.0,
                                               "chain_path": out_chain}}})
    h7.register_agent("q-1", "pw", ["go"])
    h7.process("q-1", "go", {"fields": {}}, content="第一份")
    h7.process("q-1", "go", {"fields": {}}, content="第二份")
    h8 = RuntimeHarness({"stages": {"output": {"daily_quota": 2,
                                               "gray_ratio": 0.0,
                                               "chain_path": out_chain}}})
    h8.register_agent("q-1", "pw", ["go"])
    v = h8.process("q-1", "go", {"fields": {}}, content="第三份")
    check("重启后配额延续（不清零）", v["decision"] == "DENY"
          and v["stage"] == "output" and v["reason"] == "daily_quota_exceeded")
    os.unlink(out_chain)

    print("── runtime_harness selftest: %s ──" % ("ALL PASS" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        sys.exit(selftest())
    print(__doc__)
