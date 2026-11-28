# 回归用例沉淀 — constraint-runtime

> 红蓝对抗常态化：发布前后自攻，修复过的缺陷固化为回归用例，防复发。
> 本文件登记已沉淀进自检的回归用例；全部用例随各组件 selftest 运行（`python3 src/<组件>.py selftest`）。

## 已沉淀回归用例

| 日期 | 缺陷 | 固化位置 | 用例 |
| --- | --- | --- | --- |
| 2026-11-28 | 协同闸：人工批准后未清除同因否决缓存，同组合重复动作被旧缓存误拦 | src/coord_gate.py selftest | 人工批准清除同因缓存（`_combo_cache.pop`） |
| 2026-11-28 | 协同闸：时序递进用例缺 valid_end 导致分类误拒 | src/coord_gate.py selftest | 时序递进不算冲突（给 m1 补 valid_end） |
| 2026-11-28 | 编排层：规则包损坏在装配期抛异常而非管线期 fail-closed | src/runtime_harness.py selftest | fail-closed 拒绝／喂熔断／熔断后拒绝 三连 |
| 2026-11-28 | 编排层：模板说明字段（下划线前缀）漏进熔断参数 | src/runtime_harness.py selftest | selftest 全量重跑（17/17） |
| 2026-11-28 | 编排层：配置文件相对路径按进程 CWD 误解析 | deliver/ 三模板冒烟 | 三模板冒烟全通 |
| 2026-11-22 | 台账篡改：改任一条目后链校验必报不一致 | examples/tamper_demo.py | 篡改发现实验（quickstart 第 3 步） |

## 约定

- 修复缺陷时，先在对应 selftest 加用例再改代码，用例名说清缺陷场景；
- 发布前全量 selftest 必须全绿；红一条即停发；
- 本文件与提交记录互为证据：每条用例能对应到修复提交。
