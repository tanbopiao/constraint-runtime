# 部署手册 — constraint-runtime 企业接入

> 适用版本：0.4.0 及以上。面向企业运维与后端工程师，从零到生产约 30 分钟。

## 1. 前置条件

- Python ≥ 3.10（仅标准库即可运行组件本体；MCP 服务壳需 `pip install constraint-runtime`）；
- 一个可写的数据目录（放哈希链台账与规则包）；
- 无需数据库、无需外部服务——台账是 JSONL 文件，规则是 JSON 文件。

## 2. 安装

```bash
pip install constraint-runtime          # 含 MCP 服务壳
# 或源码方式
git clone https://github.com/tanbopiao/constraint-runtime.git
cd constraint-runtime && bash quickstart.sh   # 一条命令自检全部组件
```

## 3. 选场景、改配置

1. 从 `deliver/templates/` 复制最接近的场景配置（报销闸/客服/具身设备）；
2. 改 `rules_path` 指向你的规则包（规则是数据，改规则不改代码）；
3. 改 `ledger_path` 指向你的台账目录（生产环境务必落盘，否则重启即失）；
4. 按业务容忍度调熔断参数：普通业务 `max_consecutive_failures=3`，物理世界 `=1`。

## 4. 登记身份（带外完成）

口令原文不进配置文件、不进对话、不进日志。两种方式：

```python
# 方式一：Python 内嵌
from runtime_harness import RuntimeHarness
h = RuntimeHarness.from_config_file("expense.config.json")
h.register_agent("svc-001", "<口令>", ["submit", "query"])
```

```json
// 方式二：MCP 工具（Claude/Cursor 等客户端内）
// harness_register_agent(agent_id="svc-001", secret="<口令>", perms=["submit","query"])
```

登记后立即验证：`harness_process` 用该身份跑一笔测试事件，预期 ALLOW。

## 5. 接入决策流

在业务代码里把敏感动作交给管线：

```python
verdict = h.process("svc-001", "submit",
                    {"fields": {"amount": 500, "category": "餐饮"},
                     "text": "工作午餐"},
                    content="报销单已提交")
if verdict["decision"] != "ALLOW":
    # 拒绝原因在 verdict["stage"] / verdict["reason"]
    ...
```

或经 MCP 工具 `harness_process` 从任意客户端调用——返回统一判定＋全程 trace。

## 6. 日常运维三件事

| 事项 | 命令/工具 | 频率 |
| --- | --- | --- |
| 对账（链校验） | `harness_verify` / `ledger_verify` | 每日 |
| 看水位 | `harness_status`（处理量/熔断/影子分账/灰度水位） | 每日 |
| 规则热更 | 改规则包 JSON 后 `fence_reload` | 按需 |

影子转正流程：`harness_status` 里 `promotion` 为真 → 人工核对该窗口样本 → 拍板后把规则 `status` 从 `shadow` 改 `live` → `fence_reload`。引擎只给建议，转正永远由人拍板。

## 7. 升级

- 版本遵循语义化版本：补丁版直接升；次版本先看 CHANGELOG 与规则包兼容性；
- 台账文件向后兼容：升级前备份 `ledger_path` 文件即可回滚；
- 升级后跑 `quickstart.sh`（或各组件 `selftest`）确认全绿再切流量。

## 8. 验收清单（对齐企业可维护交付物）

- [ ] 三场景配置模板可用，注释字段齐全；
- [ ] 规则包热更生效（改 JSON → reload → 新规则命中）；
- [ ] 身份带外登记，口令原文不出本机；
- [ ] 台账落盘且每日对账通过；
- [ ] 熔断演练：人为注入连续失败，确认自动停机与探针恢复；
- [ ] 调包演练：信符签发后替换内容，确认 release 拒绝；
- [ ] 影子转正演练：观察窗满后人工拍板转 live。
