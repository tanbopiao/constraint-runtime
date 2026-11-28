#!/usr/bin/env bash
# quickstart.sh — 一条命令跑完：组件自检 → 端到端演示 → 篡改发现实验
# 用法：bash quickstart.sh
set -e
cd "$(dirname "$0")"

start=$(date +%s)

echo "════ 第 1 步 · 十一件自检（十件组件＋编排层） ════"
for m in fence_rule_engine shadow_runner circuit_breaker replay_ledger settlement_receipt_gate identity_gate output_gate eval_replay coord_gate registry_gate runtime_harness; do
  echo "--- $m ---"
  python3 "src/$m.py" selftest
done

echo ""
echo "════ 第 2 步 · 端到端演示（拦截/影子/熔断/重放） ════"
python3 examples/demo.py

echo ""
echo "════ 第 3 步 · 篡改发现实验 ════"
python3 examples/tamper_demo.py

elapsed=$(( $(date +%s) - start ))
echo ""
echo "════ 全部完成，用时 ${elapsed} 秒 ════"
echo "下一步：把 src/ 下任一单文件拷进你的项目即可用（零依赖，Python 3.8+）。"
