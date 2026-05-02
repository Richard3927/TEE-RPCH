#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from common import HRPCH_DIR, RPCH_BENCH_DIR, app_path, build_all, needs_curve, rpch_bench_path, run


def main() -> int:
    parser = argparse.ArgumentParser(description="Run revocation benchmarks for TEE-RPCH, EHR-RPCH, and TAR-PCH.")
    parser.add_argument("--curve", default="mnt224")
    parser.add_argument("--out-dir", default="out/exp4_revocation_benchmark")
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    if args.build:
        build_all()

    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    for exp in range(10, 19):
        users = 2**exp
        tee_out = out_dir / f"hrpch_state_{users}.json"
        rpch_out = out_dir / f"rpch_rev_{users}.json"

        if args.force or needs_curve(tee_out, args.curve):
            run([app_path(), "--curve", args.curve, "--bench", "state", "--user-count", str(users), "--do-id", "do1", "--out", str(tee_out)], cwd=HRPCH_DIR)

        if args.force or needs_curve(rpch_out, args.curve):
            run(
                [
                    rpch_bench_path(),
                    "--curve",
                    args.curve,
                    "--rsa-bits",
                    "3072",
                    "--users",
                    str(users),
                    "--attrs",
                    "60",
                    "--policy-attrs",
                    "20",
                    "--mode",
                    "revocation",
                    "--out",
                    str(rpch_out),
                ],
                cwd=RPCH_BENCH_DIR,
            )

    print(f"Wrote JSON to: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
