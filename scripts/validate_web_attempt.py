#!/usr/bin/env python3
"""Validate candidate-only packets produced by the Web GPT GitHub channel."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from vibe_mathing.web_channel import admission_pending, packet_files, validate_packet
from vibe_mathing.web_channel import packet_files, validate_packet


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Web GPT candidate packets without admitting them.")
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--packet", type=Path)
    group.add_argument("--all-inbox", action="store_true")
    parser.add_argument("--allow-pending", action="store_true",
                        help="admission_pending 放行（GATE-CUT-LOG Batch 8）：records 缺预准入但声明一致时通过 inbox 校验")

    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    root = args.project_root.resolve()
    paths = packet_files(root) if args.all_inbox else [args.packet if args.packet.is_absolute() else root / args.packet]
    errors: list[str] = []
    pending_count = 0
    candidate_ids: dict[str, Path] = {}

    for path in paths:
        packet, packet_errors = validate_packet(root, path)
        if packet_errors and args.allow_pending and admission_pending(root, packet, packet_errors):
            pending_count += 1
            print(f"PENDING-ADMISSION: {path.relative_to(root) if path.is_relative_to(root) else path}", file=sys.stderr)
            packet_errors = []
        errors.extend(f"{path.relative_to(root) if path.is_relative_to(root) else path}: {error}" for error in packet_errors)
        if packet is None:
            continue
        # Multiple immutable packets may refine the same admitted route/obligation
        # across bounded Web turns. Candidate identity remains globally unique; the
        # trusted importer and verifier receipts, not one-packet-per-route, govern
        # admission and supersession.
        for candidate in packet.get("candidate_artifacts", []):
            if not isinstance(candidate, dict):
                continue
            candidate_id = str(candidate.get("candidate_id", ""))
            prior_candidate = candidate_ids.get(candidate_id)
            if prior_candidate is not None and prior_candidate != path:
                errors.append(f"duplicate candidate_id in {prior_candidate} and {path}: {candidate_id}")
            candidate_ids[candidate_id] = path

    decision = "PASS" if not errors else "BLOCK"
    report = {"decision": decision, "packets": len(paths), "errors": errors}
    if args.json:
        print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
    else:
        print(f"web attempt validation: {decision} packets={len(paths)}")
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
