# Changelog

## 0.8.0

- proof lane 现在要求 verifier-side trusted challenge 与 Candidate source 分离，identity 由 Lean 类型检查而非字符串命中建立。
- 明确 native `leanchecker --fresh` 是 same-domain replay；未审查 AI proof 必须等待 sandboxed Comparator 与 external checker route。
- 本版源码为 `implementation_complete_validation_deferred`，未提升任何数学结论或 verifier 准入状态。

## 0.7.0

- proof lane 从规划开始维护 formalization target、定义映射和 expected declaration。
- AI 生成 proof 的 terminal admission 新增 toolchain freshness 与 sandbox 外 proof replay 硬门。

## 0.6.0

- 继承 Verified Discovery Loop D04–D09；proof/refutation 默认隔离为 candidate 并绑定 root obligation。
- 加入成立/反驳独立 typed evidence 晋升边界和冲突冻结规则。

## 0.5.0

- 增加 reuse-first 定理门：固定 package/version/commit/declaration/import，并要求陈述比较、前提证明和双审计。

## 0.4.0

- proof obligation 按持久 worker 的有界小步推进；路线 blocker 追加记录后换路，stalled 不等于 Claim 完成。

## 0.3.0

- 候选来源状态和 candidate formal file 不得触发研究证明或 Result 晋升。
- 研究库任务必须先绑定明确请求或 active ProblemContract。

## 0.2.0 - 2026-08-26

- 增加 proof-obligation DAG 的唯一节点、依赖存在、无环和开放义务 fail-closed 契约。
- 分离 route status 与原 Claim status，阻止“辅助引理失败即原命题被反驳”的错误升级。
- 接入固定 commit 的 ProofFlow 与 Lean 官方 Skills 证据谱系，并以源码缺陷生成反例压力测试。

## 0.1.0 - 2026-08-13

- 建立定理陈述、证明义务、依赖图、反例攻击和状态分层契约。
