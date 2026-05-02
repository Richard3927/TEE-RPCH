#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from common import HRPCH_DIR, app_path, build_all, run


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the basic TEE-RPCH construction once and write one JSON report.")
    parser.add_argument("--curve", default="mnt224")
    parser.add_argument("--out", default="out/basic_construction/results.json")
    parser.add_argument("--build", action="store_true")
    args = parser.parse_args()

    if args.build:
        build_all()

    out = Path(args.out).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    run([app_path(), "--curve", args.curve, "--out", str(out)], cwd=HRPCH_DIR)
    print(f"Wrote JSON to: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
