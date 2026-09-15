# Lean Proof Fixture

<!-- MATHEMATICAL_REASONING_DISCIPLINE_V1 -->

This fixture inherits `governance/standards/MATHEMATICAL_REASONING_DISCIPLINE.md`: the formal statement must match frozen definitions and quantifiers, induction/contraposition must be logically valid, and kernel success still requires axiom/escape and statement-faithfulness audits.

<!-- FORMAL_VERIFICATION_INFRASTRUCTURE_V1 -->

The sole version truth is `governance/control-plane/lean-toolchain-lock.v1.json`. This fixture emits native kernel, axiom, declaration-identity and freshness evidence only; it does not emit semantic faithfulness, sandbox-external replay, or a terminal Result.

本目录用固定 Lean/Mathlib 构建一个无逃逸的最小定理，并输出 `#print axioms` 供证据层审计。

```text
lean-proof/
├── AGENTS.md
├── README.md
├── lean-toolchain
├── lakefile.toml
├── lake-manifest.json
├── VibeMathingFixture.lean
├── VibeMathingFixture/
│   ├── TrustedChallenge.lean
│   └── StatementIdentity.lean
└── AxiomAudit.lean
```

- `lean-toolchain` 固定 Lean 版本；`lakefile.toml` 固定直接依赖，`lake-manifest.json` 锁定全部传递依赖。
- `TrustedChallenge.lean` 是 verifier 侧固定命题；Candidate 不能定义或改写它。它只负责 formal identity，ProblemContract 仍是自然语言语义真相源。
- `StatementIdentity.lean` 要求 Candidate theorem 实际 inhabit 可信命题，禁止以注释或无关字符串命中冒充 identity。
- `VibeMathingFixture.lean` 是候选 proof module，不再同时充当可信 challenge。
- `AxiomAudit.lean` 只导入已构建模块并执行 `#print axioms`，避免为公理审计重复解释顶层 Mathlib 源文件。
- `leanchecker --fresh` 属官方 Lean kernel 的 native replay，不得冒充外部 checker 或 `proof_replay_check`。
- `.lake/` 是可重建缓存，不属于 fixture 事实。
