# Result Library Agent Guide

本目录是已结构化研究成果的真相源。`records/results.jsonl` 保存 `outcome × evidence` 二维状态；`indexes/solutions.json` 只是完整解的派生索引。

## 目录结构

```text
result-library/
├── AGENTS.md
├── README.md
├── cases/                    # 结案卷宗系统（叙事层，见 cases/AGENTS.md）
├── schema/result.schema.json
├── records/results.jsonl
└── indexes/solutions.json
```

## 可验证 Result 晋升基石

<!-- VERIFIED_AI_MATH_RESEARCH_FOUNDATION_V1 -->

本真相源继承 `governance/standards/VERIFIED_AI_MATHEMATICAL_RESEARCH_FOUNDATION.md`。`established` 必须满足独立 kernel、axiom/escape、statement identity 与 faithfulness 能力；`refuted` 必须满足独立域内 counterexample、identity 与 faithfulness；两者均须绑定 root closure 且无有效冲突。CI、PR、会话、工具退出和 Candidate acceptance 永不替代这些能力。

<!-- FORMAL_VERIFICATION_INFRASTRUCTURE_V1 -->
按 `governance/standards/FORMAL_VERIFICATION_INFRASTRUCTURE_STANDARD.md`，AI 生成 proof 的 `established` 还必须具有有效 `toolchain_freshness` 与 sandbox 外 `proof_replay_check`；verifier-side trusted challenge、typed statement identity、native Lean build 或 `leanchecker --fresh` 均不可单独替代 external replay 与 semantic faithfulness。精确反例路径不强制 Lean，但仍要求 typed counterexample、identity、faithfulness 和 root closure。

## Result 验收数学推理纪律

<!-- MATHEMATICAL_REASONING_DISCIPLINE_V1 -->

Result gate 必须按 `governance/standards/MATHEMATICAL_REASONING_DISCIPLINE.md` 复核定义/量词冻结、完整依赖链、显式 witness、反例攻击、不变量、单调量与终止、极值/对称/概率方法前提、尺度/边界以及证据能力。有限样本不得冒充归纳；逆否必须保持 `P → Q` 与 `¬Q → ¬P`；kernel check 必须与 statement-faithfulness、axiom/escape audit 分离。任一必要义务未闭合时拒绝 `established/refuted`。

## 职责与依赖

- 上游：每个结果必须引用一个 canonical `Problem` 和一个 `Attempt`。
- 下游：完整解查询只消费 `indexes/solutions.json`，但详情必须回到 `records/results.jsonl`。
- 数值证据、符号证据、局部结果和失败路径不能使用 `established` 或 `refuted` 闭合原问题。
- `proof` 的完整解验证接受独立人工审查，或同时具备 proof assistant 内核检查与公理/逃逸审计；反例接受独立反例检查、人工审查，或内核检查与公理/逃逸审计；两者都要求陈述忠实性证据。
- `prior_art_review` 记录归因和新颖性，不替代数学正确性的直接验证。
- 证据账本只追加；失效记录只能引用更早的 `evidence_id`，当前结论由未失效证据派生。
- Result 与 Attempt 必须引用同一个 Problem；独立证据的 verifier 必须不同于 Attempt.generator，并绑定可复查摘要。
- 不手工制造不在 `results.jsonl` 中的解库条目。
- 同一 Problem 的 proof 与 counterexample 不得同时满足完整解准入；冲突必须阻止写入与 ResearchBundle 导出。
- 新增、删除或移动文件时同步维护本文件与 README。

## 结案卷宗系统

`cases/` 是三层复盘结构的叙事层（事实层=`research/records/*.jsonl`，结构层=0038 case-dag-catalog）：把问题从开放到闭合的完整过程以时间线+证据链固化。硬规则见 `cases/AGENTS.md`：正式卷宗只能从已准入 Result 派生；未准入过程档案只能放 `cases/dossiers/historical/` 并显式标记 `candidate_only`；注册表 `cases/catalog.json` 只增，由 `cases/tools/validate_catalog.py` 校验。

## 验证

```bash
python3 scripts/validate_research_spaces.py
python3 result-library/cases/tools/validate_catalog.py
```
