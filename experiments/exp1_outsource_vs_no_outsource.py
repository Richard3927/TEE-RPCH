#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from common import HRPCH_DIR, app_path, build_all, needs_curve, read_json, run


def copy_with_thread_metadata(src: Path, dst: Path, threads: int) -> None:
    data = read_json(src)
    data.setdefault("params", {})["threads"] = int(threads)
    dst.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def run_cost(curve: str, out_dir: Path, mode: str, policy: int, tasks: int, threads: int, force: bool) -> Path:
    out = out_dir / f"hrpch_cost_{mode}_p{policy}_tasks{tasks}_t{threads}.json"
    if force or needs_curve(out, curve):
        run(
            [
                app_path(),
                "--curve",
                curve,
                "--bench",
                "cost",
                "--mode",
                mode,
                "--rsa-bits",
                "3072",
                "--attrs",
                "60",
                "--policy-attrs",
                str(policy),
                "--user-count",
                "1024",
                "--threads",
                str(threads),
                "--tasks",
                str(tasks),
                "--do-id",
                "do1",
                "--out",
                str(out),
            ],
            cwd=HRPCH_DIR,
        )
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare the outsourced TEE-RPCH path with the no-outsource path.")
    parser.add_argument("--curve", default="mnt224")
    parser.add_argument("--out-dir", default="out/exp1_outsource_vs_no_outsource")
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--policy", type=int, default=20)
    parser.add_argument("--tasks", type=int, default=200)
    args = parser.parse_args()

    if args.build:
        build_all()

    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    run_cost(args.curve, out_dir, "hrpch", args.policy, args.tasks, 1, args.force)
    run_cost(args.curve, out_dir, "no_outsource", args.policy, args.tasks, 1, args.force)
    print(f"Wrote JSON to: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
