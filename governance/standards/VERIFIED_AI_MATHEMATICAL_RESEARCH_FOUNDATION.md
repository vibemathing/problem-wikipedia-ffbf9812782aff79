---
id: VERIFIED-AI-MATHEMATICAL-RESEARCH-FOUNDATION-V1
type: normative-standard
status: active
owner: research
last_reviewed: 2026-09-08
---

# 可验证 AI 数学研究基础原则 v1

`VERIFIED_AI_MATH_RESEARCH_FOUNDATION_V1`

本文是 Agent、Harness、单问题仓和 Math Codex Suite 共同继承的基础契约。它把 AI 数学研究定义为一个**可恢复的候选生成—验证—准入—知识反馈循环**，而不是一次回答、一次编译或一次搜索。PLFB 仍是唯一概念元模型根；本文只是它的跨面行为约束，不建立第二套顶层本体。

## 1. 终级目标

在固定 ProblemContract 下，以可审计、可反驳、可复放的方式缩小未决义务，并只把满足精确证据能力、陈述忠实性和独立准入条件的主张写入 Result 真相源：

```text
问题发现 → 身份解析与合同冻结 → 建模/猜想 → 结果空间规划 → 有界探索
→ 自动形式化 → 证明或反证 → 专业验证 → 独立准入 → 知识沉淀 → 下一轮研究
```

循环可以无限持续，但每一步必须有界、可 checkpoint、可换路线。`stalled`、预算耗尽或会话结束不是问题完成。

## 2. 十四条核心不变量

### FND-01：PLFB 单一概念根

Point、Line、F01–F13 Face、Cross-face Binding 和 B0–B4 Body 是概念身份的唯一根。PWTSJ 只解释 F05 过程编排，OSPS 只解释 F04 结果空间；Agent、工具、工作流或知识图不得另造竞争真相源。

### FND-02：先身份与题面，后研究

来源标题、URL、状态、Award、聊天摘要和形式化文件都不是 Problem 身份。研究前必须完成来源 provenance、去重、定义域、量词、定义、假设、公理与预算冻结；未准入 CandidateObservation 不得创建数学 Result。

### FND-03：陈述绑定不可漂移

ProblemContract、Obligation、CandidateArtifact、verification receipt、EvidenceLink 和 Result 必须通过稳定 ID 与 SHA-256 绑定同一陈述快照。任何语义修改都产生新版本或新义务，不得覆盖旧绑定后沿用旧证据。

### FND-04：生成、验证、准入、结论四层分离

生成器只能产生候选；verifier 只能声明其能力覆盖范围内的 verdict；admission gate 决定证据能否进入真相链；Result 的 `outcome` 才表达当前数学结论。四层对象和状态不得合并。

### FND-05：候选默认隔离

模型回复、自然语言 proof、自动形式化、CAS/SMT/ATP 输出、数值搜索、代码运行和 Web PR 默认都是 `undetermined / candidate_only`。它们只能进入候选 allowlist，不能直接写 Evidence、Result 或 Solution。

### FND-06：证据能力不可替换

`numeric_check`、`symbolic_check`、`counterexample_check`、`kernel_check`、`axiom_escape_audit`、`statement_identity`、`statement_faithfulness`、`toolchain_freshness`、`proof_replay_check`、`prior_art_review` 和 `human_review` 是正交能力。一个能力成功不得冒充另一个能力；尤其是 kernel check 不替代 statement-faithfulness，native build 不替代独立 proof replay。

### FND-07：形式证明须同时闭合 kernel 与语义

Lean 或其他 proof kernel 只检查固定形式陈述及 proof term。`kernel_check=accept` 不能推出自然语言题面忠实、新颖、价值、工具链新鲜或无不允许公理；AI 生成 proof 的成立型 Result 至少要求独立的 `kernel_check`、`axiom_escape_audit`、`statement_identity`、`statement_faithfulness`、`toolchain_freshness` 与 sandbox 外 `proof_replay_check` 接受记录。具体基础设施等级与当前 Lean 基线由 `governance/standards/FORMAL_VERIFICATION_INFRASTRUCTURE_STANDARD.md` 定义。

### FND-08：反证与证明对称受控

一般命题的反驳必须给出落在精确域内、可独立复放的 witness，并通过 `counterexample_check`、`statement_identity` 与 `statement_faithfulness`。有限枚举没有找到反例不能证明一般命题；找到域外反例也不能反驳原命题。

### FND-09：独立复放与 provenance

高强度结论的关键 receipt 必须固定输入、工具链、命令、输出、哈希、时间和 verifier 身份，并由不同于候选生成动作的独立检查路径复放。模型自评、同一输出的文字改写和退出码 0 不构成独立性。

### FND-10：有界持久研究

持久研究是“有界小步 → receipt/checkpoint → 更新 best verified result 与 next obligation → 继续或换路”的循环，不是无 timeout 进程。失败路线必须追加登记；重复已知死路需要新的反驳证据或明确差异。

### FND-11：冲突冻结

同一陈述的 proof 与 counterexample 同时声称闭合、receipt 相互矛盾、statement hash 不一致或 freshness 不明时，根状态必须冻结为 `undetermined/inconclusive`，先建立 Conflict/Invalidation，不得择一自动晋升。

### FND-12：知识反馈不自动晋升

已准入 Result、失败路线、反例、形式定义和文献关系可生成新的 Point/Line、候选问题和下一轮 obligation；派生对象必须保留来源与证据上限。知识图、摘要、索引和 Solution View 都不能反向改写 Result 真相源。

### FND-13：运行与运输不是数学证据

`Job succeeded`、`Step accepted`、`generationActive`、会话回复完成、commit、PR、merge、CI 通过、仓库创建、worker 退出和项目卡关闭均不等于 Obligation 或 OutcomeNode 闭合，更不等于 Result admitted 或 Project solved。

### FND-14：可撤回、非单调真相

证据记录只追加但可被后续记录显式 invalidation；当前结论须从仍有效的证据重新派生。新鲜证据可以降级、撤回或分裂旧结论，系统不得为了保持“进展率”隐藏反例或失败。

## 3. Verified Discovery Loop

| 阶段 | PLFB 主面 | 必需输入 | 允许输出 | 阶段门禁 |
|---|---|---|---|---|
| D01 discover | F01/F02 | 可定位来源 | SourceObservation / CandidateObservation | provenance 与来源状态分离 |
| D02 identify | F01/F03 | 来源观察 | canonical ProblemContract | 去重、题面忠实、准入 |
| D03 model | F03/F06/F08 | 冻结合同 | 定义、表示、可检验不变量 | 类型/域/假设显式 |
| D04 plan | F04/F05 | ProblemContract、既有失败路线 | Obligation DAG / Outcome Graph / bounded Step | 根映射、预算、停止条件 |
| D05 explore | F05/F07/F09 | 有界义务 | CandidateArtifact、失败路线、checkpoint | 候选隔离、范围标注 |
| D06 formalize | F08/F09/F11 | 候选陈述/证明 | 固定形式陈述、proof object 候选 | identity + faithfulness 待审 |
| D07 prove_refute | F08/F09 | 固定 obligation | proof 或 counterexample candidate | 不允许由自评闭合 |
| D08 verify | F09/F10 | immutable candidate | typed receipt | 工具成熟度、复放、能力上限 |
| D09 admit | F10/F11 | receipt + semantic review | EvidenceLink / Result 或 freeze | 独立性、冲突、证据覆盖 |
| D10 synthesize | F11/F12 | admitted Result 与失败记录 | Solution View、知识关系、复盘 | 派生只读，不反写真相 |
| D11 feedback | F02/F04/F05/F12/F13 | 新知识与未决义务 | 新候选问题/路线/工具需求 | 保留 lineage，重新走 D02/D04 |

阶段可以回退和循环，不能跳过。D08 verifier 成功不自动触发 D09；D10 只消费已准入状态；D11 产生的新对象重新进入准入或规划门禁。

## 4. 最小结果晋升矩阵

| 目标 outcome | 最小正向能力 | 仍需满足 |
|---|---|---|
| `supported` | 适用范围内的 numeric/symbolic/human receipt | 精确 scope、statement identity、不得写成一般定理 |
| `established`（proof） | 独立 `kernel_check=accept` + `proof_replay_check=accept` | 独立 axiom audit、statement identity、statement faithfulness、toolchain freshness、闭合 root obligation、无有效冲突 |
| `refuted`（counterexample） | 独立 `counterexample_check=accept` | witness 在域内、statement identity、statement faithfulness、闭合 root obligation、无有效冲突 |
| `inconclusive` | 有效冲突、资源/工具边界或证据不足 | 明确 remaining obligation，不伪装完成 |
| `withdrawn` | 有效 invalidation 或陈述漂移 | 保留历史 lineage 与撤回理由 |

具体 schema 可以比本表更严格，不能更宽松。

## 5. 禁止替代

以下推理恒为非法：

- 聊天回答很长或模型自信 → proof；
- 代码运行成功、CI 绿色、PR 合并 → mathematical evidence；
- 有限样本通过或随机搜索无反例 → 一般命题 established；
- CAS 化简或 SMT `sat/unsat` → 超出编码范围的定理；
- Lean 编译成功 → 自然语言题面 faithful 或 terminal Result；
- `lean4checker --fresh` 成功 → 独立 external checker 或 adversarial high assurance；
- `#print axioms` 可接受 → theorem statement faithful 或 novel；
- 来源写 `solved/answered` → 本项目 Result；
- candidate PR 被接受 → EvidenceLink 或 Result；
- worker/session/project 完成 → root obligation closed；
- 索引、Wiki、知识图或 Solution View → Result 真相源。

## 6. Agent 与工具职责

- **Router/Harness**：冻结对象身份、选择 owner、执行门禁、保存 checkpoint；不能凭编排状态授予数学结论。
- **Discovery/Derivation/Computation/Proof/Formalization**：只在各自能力内生成候选与可复放材料；默认无 Result 写权限。
- **Verifier**：输出 typed receipt，声明 toolchain、输入、范围、native status 和失败；不能扩张题面。
- **Admission**：检查 statement identity/faithfulness、独立性、冲突、证据能力和 freshness；fail closed。
- **Knowledge layer**：只从已验证快照派生，并把失败与 invalidation 作为一等知识。

## 7. 来源与证据边界

本标准的边界与下列一手/固定研究材料一致：

1. [Lean 官方 About](https://lean-lang.org/about/) 与 [Theorem Proving in Lean 4](https://lean-lang.org/theorem_proving_in_lean4/)：Lean 基于依赖类型论，proof term 由小型 kernel 检查；这支持 kernel 与 tactic/生成器分层，不支持题意忠实性的自动推论。
2. [Mathlib 文档](https://leanprover-community.github.io/mathlib4_docs/)：大型可复用形式库支撑组合式证明；库规模或 import 成功不等于某个研究陈述已忠实形式化。
3. [DeepMind AlphaProof 公告](https://deepmind.google/discover/blog/ai-solves-imo-problems-at-silver-medal-level/)：强化学习、形式语言和 verifier feedback 可以提升竞赛题求解；该公开结果不证明开放式自主数学研究已闭合。
4. [AlphaProof Nexus, arXiv:2605.22763](https://arxiv.org/abs/2605.22763)：长期 proof search 仍显式需要 SafeVerify、结果包和专家 statement-fidelity 检查，并记录误形式化。
5. [ProofNet, arXiv:2302.12433](https://arxiv.org/abs/2302.12433) 与 [Rethinking Autoformalization](https://github.com/Purewhite2019/rethinking_autoformalization)：自然语言陈述、形式陈述与 proof object 必须分列审计，编译率不能代替语义忠实性。
6. [LeanMarathon, arXiv:2606.05400](https://arxiv.org/abs/2606.05400) 与 [Theo, arXiv:2606.31134](https://arxiv.org/abs/2606.31134)：长程研究依赖共享 blueprint/DAG、compiler feedback、局部失败和人工 validation；“无 sorry”不能跨类升级为新数学 Result。

这些材料是设计依据，不是本项目数学结论，也不授予任何外部系统本地 verifier 成熟度。

## 8. 机器继承

机器真相源为 `governance/control-plane/verified-ai-math-research-foundation.v1.json`，schema 为同目录 `.schema.json`，由 `scripts/validate_verified_ai_math_research_foundation.py` fail closed 校验。所有列入 policy 的 Agent surface 必须同时包含 marker 和本标准路径。

`VERIFIED_AI_MATH_RESEARCH_FOUNDATION_V1`
