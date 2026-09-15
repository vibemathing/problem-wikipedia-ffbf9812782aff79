---
name: math-formalization
description: "数学形式化与 proof-assistant 验证。用户要求 Lean 4/Mathlib、formal proof、kernel check、无 sorry 编译，或需要把自然语言定理切成可形式化定义和引理时使用。缺少 Lean 工具链时必须 fail-closed。"
---

# Math Formalization

把数学主张转成可由 proof assistant 内核检查的最小切片；当前环境缺工具时只产出计划，不伪造验证。

## When to Use This Skill

- 用户明确要求 Lean 4、Mathlib 或机器检查证明。
- 自然语言证明已经稳定，需要验证关键引理或高风险步骤。
- 需要建立 definitions/imports/lemmas/theorem 的形式化依赖结构。

## Not For / Boundaries

- CandidateObservation 或 formal-conjectures 条目只有在明确用户形式化请求或 active ProblemContract 下才能进入形式化；benchmark statement/build 不创建数学 Result。
- formal-conjectures 只使用 vendor lock 固定 commit/immutable benchmark snapshot；其上游也明确要求人工审查 misformalization，固定或编译成功不替代 statement faithfulness。
- 每次任务开始时运行时探测 `lean`、`elan` 和 `lake`；所需工具缺失时才 fail-closed 为 `calibration/blocked`，不得把主机安装状态缓存为 skill 事实。
- 含 `sorry`、`admit`、未授权 axiom 或编译失败的文件不得标记 kernel-checked。
- 不采用归档 skill 中未经验证的 `lean_agent` Python API。
- 形式化成功证明 Lean 陈述成立，不自动证明它忠实表达原自然语言命题；必须做 faithfulness audit。
- `verified=false`、timeout、unsupported、编译错误和基础设施错误都不是数学反例；必须保留失败类别。
- 调用者自报的 `verified`、历史 PASS 或只存在的 receipt 文件没有通过权；证据必须绑定当前输入、工具链和真实产物。
- 持久研究的每个 Lean/SMT step 必须可中断、可重跑并写 checkpoint；超时/编译失败只关闭当前路线。不要为了让循环继续而放宽 theorem、增加未声明 axiom 或把 `sorry` 留在产物里。

## Quick Reference

```bash
command -v lean
command -v lake
lean --version
lake env lean Path/To/File.lean
rg -n '\b(sorry|admit)\b' .
```

形式化包必须包含：原命题、Lean 陈述、定义映射、imports、证明义务、实际命令、退出码、Lean/Mathlib 版本、axiom/sorry 审计和 faithfulness 状态。

验证 receipt 至少记录：当前请求/输入 digest、形式化产物或 theorem digest、checker 与 toolchain、请求和实际建立的 claim strength、未闭合义务、assurance mode、结构化结果状态与错误类别。`claimEstablished` 不得强于真实证据，也不得强于 `claimRequested`。

只有命令真实返回成功、无占位证明且陈述忠实审计完成，才能写 `kernel-checked`。

## Exact-version package resolver

- 从 `math-knowledge-source.v1.json` 读取已准入 source profile；Mathlib 声明解析必须固定 Lean 版本、Mathlib commit、manifest digest、declaration 与 imports。
- 本地 exact-version declaration index 是首选；Reservoir 和 docs/Loogle/LeanSearch 仅用于发现，不能冒充内核验证。
- AFP/MathComp 属于不同 proof assistant 生态；没有已安装且 smoke-checked 的 consumer/verifier 时只能生成 ReusePlan，禁止跨内核继承保证。
- 当前 Lean 工具链若处于 quarantine，build 结果至多为 Candidate；只有重新准入的工具链 allowlist、独立 kernel replay、axiom/escape audit 与 statement faithfulness receipt 才能闭合形式化义务。

## Examples

### Example 1：工具缺失
- 输入：“把这个引理用 Lean 验证。”
- 动作：运行预检，发现 `lean` 缺失；输出安装前置和形式化切片。
- 验收：状态是 blocked，不创建伪编译日志。

### Example 2：含 sorry
- 输入：一个能够编译但包含 `sorry` 的 Lean 文件。
- 动作：扫描占位符并阻止通过。
- 验收：不能标记 kernel-checked，报告具体文件/位置。

### Example 3：陈述失真
- 输入：Lean 证明了比原命题更弱的结论。
- 动作：proof check 与 faithfulness audit 分开裁决。
- 验收：内核检查可 PASS，但总体状态仍因表达不忠实而 BLOCK。

### Example 4：验证超时
- 输入：proof assistant adapter 超时并返回 `verified=false`。
- 动作：记录 timeout、预算、工具链和未闭合义务。
- 验收：状态为 blocked/timeout，不把原命题标记 refuted。

## References

- `references/source-map.md`：Lean Skill、receipt、adapter 与 faithfulness checker 的来源和限制。
- `references/pressure-tests.md`：占位证明、证据新鲜度、claim strength、失败分类与陈述忠实性压力场景。

## Maintenance

- Sources：`wentor-research-plugins`、`leanprover-skills`、`mathevidence`、`itpeval`、`atp-checkers`；只吸收方法、不变量和反例，不直接激活上游代码。
- Last updated：2026-09-05。
- Verification：安装后必须用当前 Lean/Mathlib 官方工具运行最小无 `sorry` vertical slice。
<!-- VERIFIED_AI_MATH_RESEARCH_FOUNDATION_V1 -->
继承 `governance/standards/VERIFIED_AI_MATHEMATICAL_RESEARCH_FOUNDATION.md` 的 D06–D09：kernel acceptance 只覆盖固定形式陈述和 proof term；`statement_identity`、`statement_faithfulness`、axiom/escape audit、独立复放与 root closure 必须分别闭合，编译成功不得自动生成 Result。
<!-- FORMAL_VERIFICATION_INFRASTRUCTURE_V1 -->
继承 `governance/standards/FORMAL_VERIFICATION_INFRASTRUCTURE_STANDARD.md`，并从 `governance/control-plane/lean-toolchain-lock.v1.json` 读取唯一 Lean/Mathlib 基线。区分 candidate、native kernel、adversarial high-assurance 三档；`lake build`/`#print axioms`/statement identity/semantic faithfulness/toolchain freshness/`proof_replay_check` 必须分轴，native profile 的证据上限是 `supported`。
lake build
# 名称从 central lock 读取；当前 Lean 4.33.1 分发命令为 leanchecker
lake env leanchecker --fresh Module.Name
rg -n '\b(sorry|admit|axiom|unsafe|native_decide)\b' .
形式化包必须包含：原命题、verifier 侧 trusted challenge、Candidate Lean 陈述、定义映射、imports、证明义务、逐输入 digest、实际命令、退出码、Lean/Mathlib 版本、native fresh replay、axiom/sorry 审计和 faithfulness 状态。Candidate source 不得同时充当 trusted challenge。
未审查 AI Lean source 按 potentially malicious 处理，禁止直接送入非 sandbox 的 Lake/native runner；当前 native request 只接受 `trusted_fixture_native`，尚未实现可机器核验的 reviewed-candidate 例外。只有命令真实返回成功、所有输入执行前后 digest 稳定、无占位证明、`leanchecker --fresh` 成功，且 Candidate theorem 经 Lean 类型检查实际 inhabit trusted proposition，才能记录对应 native `kernel_check` 与 `statement_identity`；字符串包含关系没有通过权。native profile 上限仍为 `supported`。AI 生成 proof 的 terminal admission 还必须由已准入 sandbox/external-checker route 签发 `proof_replay_check`，不得由本 Skill 或 native rechecker 自报。
- Last updated：2026-09-09。
- Implementation status：trusted challenge 与 native fresh replay 已进入源码；按操作者要求未重复执行既有 fixture，新增层保持 `implementation_complete_validation_deferred`。
- Verification：只有收到新的明确复验要求后，才运行当前 Lean/Mathlib 的最小无 `sorry` vertical slice。
