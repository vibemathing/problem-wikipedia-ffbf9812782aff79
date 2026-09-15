# Project Skills

这里记录中央项目 active skills；问题仓库 builder 会按 Web profile 生成不同的固定 Skill 集合。每个目录只有一个稳定 owner；上游方法先进入受控 source snapshot，经过 owner mapping、依赖适配和压力测试后才能分发。

| Skill | 单一职责 |
|---|---|
| `vibe-mathing-router` | 根据当前瓶颈选择一个主流程 |
| `math-discovery` | 研究问题、检索、来源和证据图 |
| `math-derivation` | 公式推导与假设/近似边界 |
| `math-computation` | 符号、数值与反例计算 |
| `math-proof` | 自然语言证明与证明义务审计 |
| `math-formalization` | proof assistant 形式化与 kernel 验证 |
| `nvidia-private-compute` | 数学客户端白名单内的固定私密 GPU canary |

问题库中的 CandidateObservation 只归 `math-discovery`，且始终 `research_eligible=false`。工具调研按 `surveyed → source_locked → installed → smoke_checked → evidence_capable → verifier_admitted` 逐层准入；只有项目 runtime probe 支持的能力才能进入 owner 路由。

对已准入开放问题，skills 在 `persistent_research` 下按“一题一个 worker、一个有界 step、一个 checkpoint”工作。skills 负责数学路线，Harness 负责 session/scope/配额；路线失败追加 failed-route 后换路，checkpoint 进展摘要和 Goal 文案都不能升级为 Result。

数学定理、形式包、序列、对象数据库、公式与算法复用统一读取 `governance/control-plane/math-knowledge-source.v1.json` 和 `math-knowledge-operators.v1.json`。所有命中先形成 `KnowledgeHit`/`ReusePlan`/Candidate，不直接创建 EvidenceLink、Result 或 Solution。

Web 问题仓库固有集合为 8 个：router/discovery/derivation/proof/solve 为 active，computation/formalization/math-toolchain 为 constrained。`solve` 固定 0.3.0 并按需加载 477 条算子中的少量相关项；`math-toolchain` 固定 0.2.0，只生成 ToolPlan。`nvidia-private-compute`、`auto-goal`、`auto-tmux` 不进入问题仓库或通用 Suite。
所有 owner 共同继承 `governance/standards/VERIFIED_AI_MATHEMATICAL_RESEARCH_FOUNDATION.md` 的 D01–D11 闭环和十四条不变量。Skill 是阶段 owner，不是数学真相源；生成、验证、准入、Result 必须使用不同对象与门禁。
| `outcome-space-search` | PLFB F04：构造 candidate-only Outcome plan、去重并选择可解释 frontier |
对已准入开放问题，`outcome-space-search` 可先把根目标展开为少量 `OutcomeNode × Route × Method` frontier lanes；每条 lane 只交给一个数学执行 owner。skills 在 `persistent_research` 下仍按“一题一个 worker、一个有界 step、一个 checkpoint”工作；所谓并行 frontier 不授权并发 worker。skills 负责数学路线，Harness 负责 session/scope/配额；路线失败追加 failed-route 后换路，checkpoint 进展摘要和 Goal 文案都不能升级为 Result。
当前已发布的 Web Harness 1.2.4 fleet 仍固定原 8 个 Skills：router/discovery/derivation/proof/solve 为 active，computation/formalization/math-toolchain 为 constrained。private internal builder 1.7.0 已把 `outcome-space-search` 0.3.0 作为第 9 个物理副本纳入 synthetic snapshot 并按 constrained candidate-planning 激活；向模板和既有问题仓激活/rollout 必须另行通过 candidate-write/identity/privacy 回归，不能把目录存在解释为已激活或已 rollout。Router/Proof/Formalization 当前为 0.7.0，并继承 Formal Verification Infrastructure；`solve` 固定 0.3.0；`math-toolchain` 固定 0.2.0 且只生成 ToolPlan。`nvidia-private-compute`、`auto-goal`、`auto-tmux` 不进入 Web 问题仓。
