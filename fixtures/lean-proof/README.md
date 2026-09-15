# Lean/Mathlib 最小验证样例

该 fixture 已在固定 Lean 4.33.1 / Mathlib v4.33.1 下通过有界构建、trusted challenge 构建、definitionally-typed statement identity、`#print axioms` 和 native fresh replay calibration，并通过 evidence-path 回归。它只准入 native `supported` 证据，不证明任何开放数学问题，也不替代陈述忠实性审查或 external replay。

项目 adapter 优先从 `PATH` 查找 `lake`，并兼容 elan 官方默认安装目录 `~/.elan/bin`；所有 Lean 命令均通过 `lake env lean` 运行，以服从 fixture 的固定 toolchain。两处都不存在时 fail-closed。

```bash
lake update
lake exe cache get
lake --quiet build
lake --quiet build VibeMathingFixture.TrustedChallenge
lake env lean VibeMathingFixture/StatementIdentity.lean
lake env leanchecker --fresh VibeMathingFixture
lake env lean AxiomAudit.lean
```

Lean 官方手册称该工具为 `lean4checker`；当前锁定的 Lean 4.33.1 Linux 分发暴露的实际命令名是 `leanchecker`，唯一命令事实由 central lock 管理。该 replay 与 native kernel 属同一 trust domain，不能签发外部独立重放能力。
