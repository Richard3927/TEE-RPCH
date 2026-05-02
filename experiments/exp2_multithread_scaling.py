#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from exp1_outsource_vs_no_outsource import copy_with_thread_metadata, run_cost
from common import build_all, needs_curve


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the server-thread scaling experiment for TEE-RPCH.")
    parser.add_argument("--curve", default="mnt224")
    parser.add_argument("--out-dir", default="out/exp2_multithread_scaling")
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    if args.build:
        build_all()

    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    for tasks in [50, 100, 150, 200, 250, 300]:
        for threads in [1, 3, 6]:
            run_cost(args.curve, out_dir, "hrpch", 20, tasks, threads, args.force)

        base = run_cost(args.curve, out_dir, "no_outsource", 20, tasks, 1, args.force)
        for threads in [3, 6]:
            dst = out_dir / f"hrpch_cost_no_outsource_p20_tasks{tasks}_t{threads}.json"
            if args.force or needs_curve(dst, args.curve):
                copy_with_thread_metadata(base, dst, threads)

    for policy in [10, 20, 30]:
        for threads in [1, 2, 3, 4, 5, 6]:
            run_cost(args.curve, out_dir, "hrpch", policy, 200, threads, args.force)

        base = run_cost(args.curve, out_dir, "no_outsource", policy, 200, 1, args.force)
        for threads in [2, 3, 4, 5, 6]:
            dst = out_dir / f"hrpch_cost_no_outsource_p{policy}_tasks200_t{threads}.json"
            if args.force or needs_curve(dst, args.curve):
                copy_with_thread_metadata(base, dst, threads)

    print(f"Wrote JSON to: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
