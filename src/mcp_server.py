#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""constraint-runtime MCP 服务壳

把五个约束组件（围栏规则引擎/影子运行器/熔断停机器/留痕重放器/结算凭证闸）
以 MCP 工具形式对外暴露，供任意 MCP 客户端（Claude、Cursor 等）调用。
组件本体零依赖纯标准库；本壳仅依赖 mcp 包。

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

工具一览：
    fence_evaluate   围栏判定：事件过规则包，live 拦截 / shadow 只记
    fence_reload     规则热更：重新加载规则包（规则是数据）
    shadow_feed      影子投喂：基线判定 vs 影子判定，破口/误伤分账
    shadow_report    影子报告：分账统计 + 转正建议（人工拍板）
    breaker          熔断控制：status/success/failure/trip 四个动作
    ledger_append    台账入链：判定写入哈希链，篡改可发现
    ledger_verify    校验重放：链校验 + 用当前规则包离线重放比对
"""
import json
import os
import sys

from mcp.server.fastmcp import FastMCP

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from circuit_breaker import CircuitBreaker            # noqa: E402
from fence_rule_engine import FenceEngine             # noqa: E402
from replay_ledger import ReplayLedger                # noqa: E402
from shadow_runner import ShadowRunner                # noqa: E402

RULES_PATH = os.environ.get("CONSTRAINT_RULES_PATH")
LEDGER_PATH = os.environ.get("CONSTRAINT_LEDGER_PATH") or None

mcp = FastMCP("constraint-runtime")

_engine = FenceEngine(RULES_PATH) if RULES_PATH else None
_shadow = ShadowRunner()
_breaker = CircuitBreaker()
_ledger = ReplayLedger(LEDGER_PATH)


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


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
