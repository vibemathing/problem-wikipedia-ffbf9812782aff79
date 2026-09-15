# Source Map

- `wentor-research-plugins`：`lean-theorem-proving-guide` 的 Lean 4/Mathlib/内核验证方向。
- 上游示例中的 `lean_agent` API 未被采用，因为当前供应链与本机没有证明该 API 可安装或可运行。
- `leanprover-skills`：官方 `lean-proof` 的工作期占位、逐个错误修复与最终无 `sorry`/error 门禁；`scripts/check-validation` 提供测试结果新鲜度思路。固定 commit 的 `lean-proof/tests/example.yaml` 仍是占位样例，因此不把其仓库状态视为充分评测证据。
- `mathevidence`：`schemas/checker-receipt.schema.json` 的 request/bundle/theorem/axiom digest、checker/toolchain、claim strength、unresolved obligations、assurance mode 与 result status 不变量。上游处于 experimental preview，只作 schema donor，不是本项目证明权威或第二真相源。
- `itpeval`：Lean/Rocq/Isabelle/HOL Light 原生 adapter 和 timeout/error 捕获边界。其记录主要压成 `verified: bool`，因此只吸收 adapter 形状，不复用结果 schema。
- `atp-checkers`：除零、自然数截断、空洞假设、未用 binder、`sorry`/axiom 等机械预检，以及 `proven`/`maybe` confidence。其 `LIMITATIONS.md` 明确不能裁决形式化是否表达正确数学，因此 finding 只能辅助 faithfulness audit。
- [Lean Reference — Validating a Lean Proof](https://lean-lang.org/doc/reference/latest/ValidatingProofs/)：把未审查 AI proof 视为可能恶意输入；明确区分 statement meaning、普通 build、`#print axioms`、native `lean4checker --fresh` 与 comparator/external checker 的保证层级。
- [Lean kernel soundness bug-hunt postmortem](https://leodemoura.github.io/blog/2026-8-24-postmortem-for-the-kernel-soundness-bug-hunt/)：确认 v4.33.1 修复 kernel/runtime/GMP 问题，同时说明单一 checker 与共享实现族不能提供绝对保证。
- [Lean projects](https://leanprover-community.github.io/install/project.html)：项目必须由 Lake、`lean-toolchain`、dependency manifest 与 Mathlib cache 共同固定，单文件编译不是可靠项目复现边界。
- `leanprover/comparator`：官方 gold-standard orchestration；当前供应链仍为 reference-only，尚未安装或准入 runner。
- `ammkrn/nanoda_lib`：Apache-2.0 Rust external checker；当前只锁定来源，不授予 `proof_replay_check`。
- `nomeata/lean-inductive-models`：补充 inductive-model correspondence 风险轴，不是完整独立 kernel。
- Lean 与 Mathlib 本身作为正式工具链依赖，使用时以官方文档、central lock 和真实执行产物为准。本轮新增代码按操作者要求不重复执行，不能引用既有 PASS 冒充新层验证。
