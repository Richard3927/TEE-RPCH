#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = ROOT.parent
RUNNER = PROJECT_ROOT / "run_curve_experiments.py"
TABLES = PROJECT_ROOT / "generate_result_tables.py"
FIGURES = PROJECT_ROOT / "experiments_v2" / "scripts" / "build_figures.py"


def run_cmd(cmd: list[str], cwd: Path) -> None:
    print("+", " ".join(str(x) for x in cmd), flush=True)
    subprocess.run(cmd, check=True, cwd=str(cwd))


def has_curve_data(dir_path: Path) -> bool:
    return dir_path.exists() and any(dir_path.glob("*.json"))


def main() -> int:
    ap = argparse.ArgumentParser(description="Run the isolated five-experiment pipeline with real SGX data.")
    ap.add_argument("--curve", required=True, choices=["mnt224", "a1"])
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--max-mem-pct", type=float, default=95.0)
    ap.add_argument("--mem-poll-secs", type=float, default=2.0)
    args = ap.parse_args()

    data_dir = ROOT / f"data_{args.curve}"
    data_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        "python3",
        str(RUNNER),
        "--curve",
        args.curve,
        "--out-dir",
        str(data_dir),
        "--max-mem-pct",
        str(args.max_mem_pct),
        "--mem-poll-secs",
        str(args.mem_poll_secs),
    ]
    if args.force:
        cmd.append("--force")
    run_cmd(cmd, PROJECT_ROOT)

    # Refresh joint tables/figures only after both curves are available.
    mnt_dir = ROOT / "data_mnt224"
    a1_dir = ROOT / "data_a1"
    if not (has_curve_data(mnt_dir) and has_curve_data(a1_dir)):
        print("Skipping joint table/figure refresh until both data_mnt224 and data_a1 exist.", flush=True)
        return 0

    tables_dir = ROOT / "tables"
    figures_dir = ROOT / "figures"
    tables_dir.mkdir(parents=True, exist_ok=True)
    figures_dir.mkdir(parents=True, exist_ok=True)

    run_cmd(
        [
            "python3",
            str(TABLES),
            "--mnt-dir",
            str(mnt_dir),
            "--a1-dir",
            str(a1_dir),
            "--out-dir",
            str(tables_dir),
        ],
        PROJECT_ROOT,
    )

    run_cmd(
        [
            "python3",
            str(FIGURES),
            "--mnt-dir",
            str(mnt_dir),
            "--a1-dir",
            str(a1_dir),
            "--out-dir",
            str(figures_dir),
        ],
        FIGURES.parent,
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
