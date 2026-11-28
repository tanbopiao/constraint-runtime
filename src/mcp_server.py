#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""constraint-runtime MCP 服务壳

把八个约束组件（围栏规则引擎/影子运行器/熔断停机器/留痕重放器/结算凭证闸/
身份闸/输出闸/评测算子）以 MCP 工具形式对外暴露，供任意 MCP 客户端
（Claude、Cursor 等）调用。组件本体零依赖纯标准库；本壳仅依赖 mcp 包。

启动配置（stdio）：
    {
      "mcpServers": {
        "constraint-runtime": {
          "command": "python3",
          "args": ["-m", "mcp_server"],
          "env": {
            "CONSTRAINT_RULES_PATH": "/path/to/rules.json",
            "CONSTRAINT_LEDGER_PATH": "/path/to/ledger.jsonl"
          }
        }
      }
    }

工具一览（十七个，按治理链分四组）：
    fence_evaluate        围栏判定：事件过规则包，live 拦截 / shadow 只记
    fence_reload          规则热更：重新加载规则包（规则是数据）
    shadow_feed           影子投喂：基线判定 vs 影子判定，破口/误伤分账
    shadow_report         影子报告：分账统计 + 转正建议（人工拍板）
    breaker               熔断控制：status/success/failure/trip 四个动作
    identity_register     注册即登记：盐化指纹入链（生产环境注册应在带外完成）
    identity_challenge    发起握手挑战：签发一次性 nonce
    identity_handshake    挑战-应答核验：nonce 单次有效，防重放
    identity_authorize    权限即清单：动作不在清单内一律拒绝
    output_issue          签发输出信符：绑定内容哈希，受每日配额约束
    output_release        无信符不出闸：信符单次有效 + 内容一致才放行
    output_watermark      灰度水位账本：稳定/影子通道各放行多少
    ledger_append         台账入链：判定写入哈希链，篡改可发现
    ledger_verify         校验重放：链校验 + 用当前规则包离线重放比对
    eval_record           评测记录锚定：输入/输出/配置三元组入链
    eval_verify           重放即复算：三元组任一漂移即拆穿
    eval_claim            声称即对账：无证据完成声称判假完成
"""
import json
import os
import sys

from mcp.server.fastmcp import FastMCP

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from circuit_breaker import CircuitBreaker            # noqa: E402
from eval_replay import EvalReplay                    # noqa: E402
from fence_rule_engine import FenceEngine             # noqa: E402
from identity_gate import IdentityGate                # noqa: E402
from output_gate import OutputGate                    # noqa: E402
from replay_ledger import ReplayLedger                # noqa: E402
from shadow_runner import ShadowRunner                # noqa: E402

RULES_PATH = os.environ.get("CONSTRAINT_RULES_PATH")
LEDGER_PATH = os.environ.get("CONSTRAINT_LEDGER_PATH") or None

mcp = FastMCP("constraint-runtime")

_engine = FenceEngine(RULES_PATH) if RULES_PATH else None
_shadow = ShadowRunner()
_breaker = CircuitBreaker()
_ledger = ReplayLedger(LEDGER_PATH)
_identity = IdentityGate()
_output = OutputGate()
_eval = EvalReplay()


def _need_engine():
    if _engine is None:
        raise RuntimeError("未配置 CONSTRAINT_RULES_PATH，无法使用围栏工具")
    return _engine


@mcp.tool()
def fence_evaluate(event: dict) -> str:
    """围栏判定：把一个事件交给规则包裁决。live 规则命中即拦截（fail-closed），
    shadow 规则命中只记不拦。event 示例：
    {"fields": {"amount": 5000, "category": "餐饮"}, "text": "加急"}"""
    eng = _need_engine()
    verdict = eng.evaluate(event)
    return json.dumps(verdict, ensure_ascii=False)


@mcp.tool()
def fence_reload() -> str:
    """规则热更：重新从 CONSTRAINT_RULES_PATH 加载规则包，规则是数据，改规则不用改代码。"""
    eng = _need_engine()
    eng.reload()
    version = json.load(open(eng.rules_path, encoding="utf-8")).get("version", "?")
    return json.dumps({"ok": True, "version": version}, ensure_ascii=False)


@mcp.tool()
def shadow_feed(event_id: str, baseline_decision: str, shadow_decision: str,
                rule_hits: list = None) -> str:
    """影子投喂：记录一次基线判定与影子判定对照。影子比基线松=破口，比基线严=误伤，
    分账累计，连续 N 窗口零破口零误伤才给转正建议。"""
    _shadow.feed(event_id, baseline_decision, shadow_decision, rule_hits)
    return json.dumps({"ok": True, "total_fed": _shadow.total["fed"]}, ensure_ascii=False)


@mcp.tool()
def shadow_report() -> str:
    """影子报告：当前分账统计 + 是否达到转正建议条件（转正仍需人工拍板）。"""
    return json.dumps({"report": _shadow.report(),
                       "promotion": _shadow.promotion_check()}, ensure_ascii=False)


@mcp.tool()
def breaker(action: str, reason: str = "") -> str:
    """熔断控制。action 取值：
    status=查看状态；success=记录一次成功；failure=记录一次失败（连续失败或失败率越界自动熔断）；
    trip=显式熔断。熔断后冷却期放行探针，探针成功才恢复。"""
    actions = {"status", "success", "failure", "trip"}
    if action not in actions:
        return json.dumps({"error": f"action 须为 {sorted(actions)}"}, ensure_ascii=False)
    if action == "success":
        _breaker.record_success()
    elif action == "failure":
        _breaker.record_failure(reason)
    elif action == "trip":
        _breaker.trip(reason or "显式熔断信号")
    return json.dumps({"action": action, "report": _breaker.report()}, ensure_ascii=False)


@mcp.tool()
def ledger_append(event: dict, verdict: dict) -> str:
    """台账入链：把一次判定写入哈希链台账，任何篡改都会被链校验发现。"""
    h = _ledger.append(event, verdict)
    return json.dumps({"ok": True, "hash": h}, ensure_ascii=False)


@mcp.tool()
def ledger_verify() -> str:
    """校验重放：先验哈希链完整性，再用当前规则包离线重放全部台账，
    重算结论与原判一致 = 可复算。"""
    chain_ok = _ledger.verify_chain()
    replay = _ledger.replay(_engine) if _engine else {"skipped": "未配置规则包"}
    return json.dumps({"chain_ok": chain_ok, "replay": replay}, ensure_ascii=False)


# ---------- 身份闸（L1） ----------

@mcp.tool()
def identity_register(agent_id: str, secret: str, perms: list) -> str:
    """注册即登记：把智能体身份以盐化指纹形式入链，口令原文不落盘。
    perms 为动作清单（权限即清单，未列入的动作一律拒绝）。
    注意：secret 经由本工具传输仅适用于本地/受信环境，生产环境的注册
    应在带外完成，不要把口令明文放进对话或日志。"""
    ok, status = _identity.register(agent_id, secret, perms)
    return json.dumps({"ok": ok, "status": status}, ensure_ascii=False)


@mcp.tool()
def identity_challenge(agent_id: str) -> str:
    """发起握手挑战：为已登记且未吊销的身份签发一次性 nonce。"""
    ch = _identity.challenge(agent_id)
    if ch is None:
        return json.dumps({"ok": False, "error": "unknown_or_revoked"},
                          ensure_ascii=False)
    return json.dumps({"ok": True, "nonce": ch["nonce"]}, ensure_ascii=False)


@mcp.tool()
def identity_handshake(agent_id: str, nonce: str, proof: str) -> str:
    """挑战-应答核验：proof = sha256(口令指纹 + nonce)，由调用方侧计算，
    口令原文不出本机。nonce 单次有效，重放即拒绝。"""
    ok, status = _identity.handshake(agent_id, nonce, proof)
    return json.dumps({"ok": ok, "status": status}, ensure_ascii=False)


@mcp.tool()
def identity_authorize(agent_id: str, action: str) -> str:
    """权限即清单：未登记、已吊销、动作不在清单内，一律拒绝。"""
    ok, status = _identity.authorize(agent_id, action)
    return json.dumps({"ok": ok, "status": status}, ensure_ascii=False)


# ---------- 输出闸（L3） ----------

@mcp.tool()
def output_issue(agent_id: str, content: str, version: str = "v1") -> str:
    """签发输出信符：信符绑定内容哈希与身份，受每日配额约束。
    version=v1 走稳定通道，其他版本按灰度比例分流。"""
    rec = _output.issue(agent_id, content, version)
    if rec is None:
        return json.dumps({"ok": False, "error": "daily_quota_exceeded"},
                          ensure_ascii=False)
    return json.dumps({"ok": True, "symbol": rec["symbol"],
                       "version": rec["version"]}, ensure_ascii=False)


@mcp.tool()
def output_release(symbol: str, content: str) -> str:
    """发布核验：无信符不出闸。信符有效 + 内容一致 + 未用过才放行；
    放行后按灰度比例返回 stable 或 shadow 通道。"""
    ok, status = _output.release(symbol, content)
    return json.dumps({"ok": ok, "status": status}, ensure_ascii=False)


@mcp.tool()
def output_watermark() -> str:
    """灰度水位账本：稳定/影子通道各放行了多少次。"""
    return json.dumps(_output.watermark(), ensure_ascii=False)


# ---------- 评测算子（L6） ----------

@mcp.tool()
def eval_record(case_id: str, in_hash: str, out_hash: str, cfg_hash: str,
                evidence_hash: str = None) -> str:
    """记录即锚定：把评测案例的输入/输出/配置三元组（可带证据哈希）入链，
    事后不可篡改。哈希由调用方对原文计算后传入。"""
    ok, status = _eval.record(case_id, in_hash, out_hash, cfg_hash, evidence_hash)
    return json.dumps({"ok": ok, "status": status}, ensure_ascii=False)


@mcp.tool()
def eval_verify(case_id: str, in_hash: str, out_hash: str, cfg_hash: str) -> str:
    """重放即复算：用新算出的三元组哈希与链上锚定比对，任一漂移即拆穿。"""
    ok, status = _eval.verify(case_id, in_hash, out_hash, cfg_hash)
    return json.dumps({"ok": ok, "status": status}, ensure_ascii=False)


@mcp.tool()
def eval_claim(case_id: str, evidence_hash: str) -> str:
    """声称即对账：无记录、无证据、证据不符，一律判假完成（fake_completion）。"""
    ok, status = _eval.claim_done(case_id, evidence_hash)
    return json.dumps({"ok": ok, "status": status}, ensure_ascii=False)


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
