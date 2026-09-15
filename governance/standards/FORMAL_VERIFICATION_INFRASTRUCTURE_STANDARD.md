---
id: FORMAL-VERIFICATION-INFRASTRUCTURE-STANDARD-V1
type: normative-standard
status: active
owner: research
last_reviewed: 2026-09-08
---

# AI for Math 形式验证基础设施标准

- Policy ID：`FORMAL_VERIFICATION_INFRASTRUCTURE_V1`
- 上位约束：`VERIFIED_AI_MATH_RESEARCH_FOUNDATION_V1`
- 唯一概念根：PLFB
- 状态：Normative

<!-- FORMAL_VERIFICATION_INFRASTRUCTURE_V1 -->

## 1. 架构结论

形式验证已经是 VibeMathing AI for Math 的**不可绕过跨面基础设施**；Lean 4/Mathlib 是当前默认 reference kernel、可执行验证基线和所有 proof-based terminal Result 的必经兼容通道。这个结论必须按以下限定理解：

1. 不要求每次 discovery、推导或计算都启动 Lean；所有 active Problem 必须具有明确的形式化就绪状态、statement/domain/quantifier 身份和可执行的形式化计划或阻塞原因。
2. 自然语言证明、论文式 proof draft、模型自评和人工“看起来正确”不能直接产生 `established`。
3. 以完整证明进入 `established` 的 Result 必须通过已准入 proof kernel；在当前项目基线中必须通过 Lean 通道。其他 proof assistant 只有在获得等价 typed verifier admission 后才能替代，名称、社区声誉或构建成功不构成等价性。
4. 精确反例可经独立 `counterexample_check` 进入 `refuted`，不强制执行 Lean；但 statement identity、statement faithfulness、定义域适用性和 root closure 仍不可绕过。
5. “Lean 不适用、尚未形式化、工具链缺失或验证超时”只产生 `blocked/undetermined`，绝不产生数学反驳。

因此，**形式验证不可绕过，Lean 是当前 proof terminal path 不可绕过的实现基线，但 Lean 不是 PLFB 之外的第二真相源，也不是所有研究活动必须实时调用的单一工具。**

## 2. 为什么仅有 `lake build` 不足

Lean 官方验证指南明确区分“形式定理是否有有效证明”与“定理陈述是什么意思”，并将未审查 AI 生成证明归入需要按潜在恶意输入处理的场景。`lake build` 或编辑器蓝色双勾说明：当前 imports、定义、公理与 elaboration 环境下，Lean kernel 接受了给定形式陈述的 proof term。它不证明：

- 自然语言题面被忠实表达；
- 定义域、量词、边界条件与原题一致；
- imports 和自定义 axiom 符合项目准入；
- 构建过程没有利用扩展、runtime 或文件格式攻击；
- 结果新颖、有价值或闭合 canonical root obligation。

`#print axioms` 用于识别 `sorryAx`、`Lean.trustCompiler` 和自定义公理；`lean4checker --fresh` 可从 `.olean` 重放声明，但仍信任 `.olean` 结构和同一实现族。面向未审查 AI proof、高额奖励或开放问题，官方指南给出的高风险路径是：在可信 challenge 文件中固定 statement，在 sandbox 中构建，通过 `comparator` 导出并在 sandbox 外由 Lean kernel 和独立 external checker（例如 nanoda）重放，同时核对 challenge statement。

即使如此，外部 checker 也不是绝对真理。2026-08-24 Lean kernel soundness bug-hunt postmortem 记录了部分错误同时被官方 kernel 与 nanoda 接受，并指出 Lean runtime、引用计数和 GMP 也属于可信计算基。结论是组合不同能力轴并管理失效，而不是按 checker 数量投票。

## 3. 三个 assurance profile

### 3.1 Candidate formalization

用途：D06 形式陈述、定义映射、引理图和 proof object 候选。

最低条件：

- 绑定冻结 ProblemContract、statement digest、scope digest 和 obligation；
- 明示 domain、quantifiers、definitions、assumptions；
- 固定拟用 proof assistant/toolchain，或记录无法形式化的精确 obstruction；
- 输出仍是 CandidateArtifact。

证据上限：`candidate_only`。

### 3.2 Native kernel

用途：开发期编译、proof repair、回归和普通 kernel evidence。

最低能力：

- `kernel_check`；
- `axiom_escape_audit`；
- `statement_identity`；
- 独立 `statement_faithfulness`；
- `toolchain_freshness`。

控制要求：exact Lean/Mathlib pair、`lean-toolchain`、固定 Mathlib commit、`lake-manifest.json`、Candidate 之外由 verifier 固定摘要的 trusted challenge、真实 fresh build、native `leanchecker --fresh`、占位/escape 扫描和独立语义审查。statement identity 必须由 Candidate theorem 经 Lean 类型检查实际 inhabit trusted proposition；源码字符串包含、同文件自报 challenge 或只比较 theorem 名称均不成立。非 sandbox native runner 当前只接受 registry 授权的 `trusted_fixture_native` generator，且 challenge digest 必须命中该 generator 的 `trusted_challenge_allowlist`；request 自报 profile 或“已人工复核”没有执行权限。

Lean Reference 使用 `lean4checker` 这一名称；具体发行版实际命令必须来自 central lock。当前 Lean 4.33.1 Linux 分发使用 `leanchecker`。无论名称为何，该步骤仍复用 Lean kernel 与 `.olean` 结构假设，只属于 `lean-kernel` trust domain。

证据上限：`supported`。单一 native kernel route 不足以签发 AI 生成开放问题的 terminal proof Result，也不得把 native fresh replay 改名为 `proof_replay_check`。

### 3.3 Adversarial high assurance

用途：AI 生成 proof、开放问题、赏金问题及其他 terminal `established` 候选。

除 native kernel 全部条件外，还必须有：

- 可信侧固定 challenge statement；
- sandboxed build；
- proof export 和格式校验；
- sandbox 外 `proof_replay_check`；
- 至少一个经能力与版本准入的 external checker；
- root obligation closure；
- 无有效 proof/counterexample 冲突。

证据上限：满足全部 Result gate 后可进入 `terminal_result`。当前 comparator/external-checker 运行通道尚未准入，因此本标准生效并不意味着当前系统已经具备签发该等级 Result 的能力。

## 4. Lean/Mathlib 版本基线

唯一机器锁为 `governance/control-plane/lean-toolchain-lock.v1.json`。代码、fixture、Compute bootstrap、Suite 和模板不得各自维护相互独立的版本事实。

当前迁移目标：

- Lean：`leanprover/lean4:v4.33.1`，tag commit `819816b2e0a3bf405af45ae5c7af2491d8f5bee6`；
- Mathlib：tag `v4.33.1`，commit `0df444a360eaa60ab8c11dca51a86af692955474`；
- fixture：`fixtures/lean-proof/`；
- lock files：`lean-toolchain`、`lakefile.toml`、`lake-manifest.json`。

v4.33.0 的历史 proof term 不被自动判假；但其 adversarial/high-assurance receipt 已失去 freshness，必须 replay 或显式 invalidation。迁移到 v4.33.1 只能恢复 native qualification 的必要条件，不能自动补出 comparator/external-checker 证据。

## 5. 强制对象绑定

每个形式验证请求必须绑定：

- canonical `problem_id` 与 ProblemContract digest；
- `attempt_id`、`graph_id`、`obligation_id`、`candidate_id`；
- statement/scope digest；
- Candidate 之外的 verifier-side trusted challenge、challenge digest 与 trusted proposition constant；
- source files 及逐文件 digest；
- Lean release、commit、Mathlib commit、manifest/toolchain fingerprint；
- build、axiom audit、replay command、exit code、native status；
- verifier principal、trust domain、capability、independence；
- checked_at、freshness policy 和 invalidation lineage。

缺任一必要绑定时，回执不得用于 terminal admission。

## 6. Prompt、Skill 与 Agent 继承

所有研究提示词和 Agent surface 必须表达以下次序：

1. 先冻结语义身份，后自动形式化；
2. 先生成 Candidate，再由独立 verifier 产生 typed receipt；
3. `lake build`、`#print axioms`、`lean4checker`、`comparator` 和 statement-faithfulness 是不同能力，禁止互相冒充；
4. 形式化失败触发缩小 obligation、修订定义映射或登记 obstruction，禁止弱化 theorem 以换取编译；
5. Web GPT 只能提交 Lean source/proof draft/formalization packet 候选，不能签发 kernel、replay、freshness 或 Result；
6. 每个 proof lane 在最初计划时就给出 formalization target、expected declaration 和 verification profile，而不是在自然语言证明“完成”后才附加 Lean。

`governance/tasks/millennium-goals/` 是仓库拆分策略保护的标准化长 Goal 路径，canonical `main` 不得为本次工程集成直接改写。上述要求先由本政策、Agent、Skill 和 Harness 强制继承；六个 Millennium Goal 的正文传播必须作为独立、显式授权的 `research/millennium-*` 分支任务执行，并在下一次 Goal replacement 前验证。未完成该分支级传播时，状态保持 `blocked_pending_explicit_research_branch_rollout`，不得宣称 Goal fleet 已更新。

## 7. 版本、公告与失效

以下事件必须触发 freshness 重新判断：

- Lean/kernel/runtime/GMP soundness 或 security advisory；
- Lean、Mathlib、Lake、dependency manifest 或 external checker 版本变化；
- challenge statement、imports、axiom allowlist 或 build flags 变化；
- sandbox、export format、checker runner semantics 或 trust domain 变化；
- statement-faithfulness 审查被撤销；
- 新反例或 proof/counterexample conflict。

触发后不得只修改版本字符串。必须更新 lock、重建 fixture、重跑正负 canary、重放受影响 receipt，并按 lineage 显式失效旧 capability。

## 8. 非目标

本标准不：

- 声称 Lean 证明了自然语言原题；
- 声称所有数学研究都能或应立即完全形式化；
- 排斥未来 Isabelle、Rocq、Metamath 等经过等价准入的 verifier；
- 把形式库规模、benchmark 分数、CI、PR 或模型成功率当数学 Result；
- 因缺少 high-assurance runtime 而停止 discovery、推导、计算或候选证明；这些活动继续运行，但证据上限必须正确。

## 9. 一手来源

- [Lean Reference — Validating a Lean Proof](https://lean-lang.org/doc/reference/latest/ValidatingProofs/)：区分 proof validity 与 statement meaning，说明 axiom audit、`lean4checker`、`comparator` 和 external checker 的保证与剩余假设。
- [Lean 4.33.1 release](https://github.com/leanprover/lean4/releases/tag/v4.33.1)：当前迁移固定 release。
- [Postmortem for the kernel soundness bug hunt, 2026-08-24](https://leodemoura.github.io/blog/2026-8-24-postmortem-for-the-kernel-soundness-bug-hunt/)：记录 v4.33.1 修复、runtime/GMP 风险和 checker 多样性的边界。
- [Mathlib Lean projects](https://leanprover-community.github.io/install/project.html) 与 [Lean GitHub ecosystem](https://leanprover-community.github.io/contribute/tags_and_branches.html)：Lean/Mathlib 配对、`lean-toolchain`、Lake 和 release/nightly 分支策略。

<!-- FORMAL_VERIFICATION_INFRASTRUCTURE_V1 -->
