#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from common import build_all, PROJECT_ROOT, run


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the organized TEE-RPCH experiment suite.")
    parser.add_argument("--curve", default="mnt224")
    parser.add_argument("--out-dir", default="out/organized_suite")
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    if args.build:
        build_all()

    root = Path(args.out_dir).resolve()
    common = ["--curve", args.curve]
    force = ["--force"] if args.force else []
    python = sys.executable
    run([python, "experiments/exp0_basic_construction.py", *common, "--out", str(root / "exp0_basic_construction" / "results.json")], cwd=PROJECT_ROOT)
    run([python, "experiments/exp1_outsource_vs_no_outsource.py", *common, "--out-dir", str(root / "exp1_outsource_vs_no_outsource"), *force], cwd=PROJECT_ROOT)
    run([python, "experiments/exp2_multithread_scaling.py", *common, "--out-dir", str(root / "exp2_multithread_scaling"), *force], cwd=PROJECT_ROOT)
    run([python, "experiments/exp4_revocation_benchmark.py", *common, "--out-dir", str(root / "exp4_revocation_benchmark"), *force], cwd=PROJECT_ROOT)
    print(f"Wrote organized experiment outputs under: {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
