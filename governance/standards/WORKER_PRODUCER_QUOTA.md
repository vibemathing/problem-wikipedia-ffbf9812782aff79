# Persistent Worker Producer Quota Policy

来源：`research/artifacts/README.md` 的本地追加内容（2026-09 合并时自冻结私有路径迁移至本文件；`research/artifacts/` 在 main 上自 compute baseline 起冻结）。

持久 worker 的探索性大输出必须写到 run-local 的 producer 目录，不进 Git worktree，也不直接当证据。每个 producer 由 Harness manifest 声明 `max_bytes`、`max_files`、`high_watermark_bytes` 和 `high_watermark_files`；到 high-watermark 只暂停当前 producer，超额停止当前 producer，先压缩/轮换/复用并在 checkpoint 留下计量。真正的数学证据仍需小而可复核的 artifact、SHA-256 和独立 verifier 回执。

机器语义见 `governance/control-plane/harness-manifest.v1.json` 与 `research/schema/persistent-worker-checkpoint.schema.json`。