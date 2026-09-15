# Changelog

## 0.7.0

- 每个 active Problem 首次规划必须产生 formalization readiness、target/profile 或精确 obstruction。
- 形式验证不可绕过不等于每步执行 Lean；反例和探索继续使用适配的独立 typed route。

## 0.6.0

- 继承 Verified AI Mathematical Research Foundation；按 D01–D11 路由最短可验证义务。
- 禁止由 Job、会话、PR、CI 或 verifier 状态自动晋升 Result。

## 0.5.0

- 新增 `outcome-space-search` 路由：active ProblemContract 已冻结但攻击目标空间/frontier 不清时，先生成 candidate-only OSPS plan。
- 明确并行 frontier 不启动并发 worker、不授权预算、不创建 Job/Evidence/Result。

## 0.4.0

- 接入数学知识 source/operator registry；命中既有定理、包或数据库时先生成 ReusePlan/Candidate，再路由到唯一 owner。

## 0.3.0

- 增加单问题单 worker 的 persistent_research 路由；无限循环由 checkpoint 驱动，不启动并行工厂或无界命令。

## 0.2.0

- CandidateObservation 或缺少 active ProblemContract 时强制路由到 discovery。
- 来源状态、形式 build 和 surveyed/source_locked 工具不再触发越级研究或验证路线。

## 0.1.0 - 2026-08-13

- 建立按当前瓶颈单路由的 Vibe Mathing 项目入口。
