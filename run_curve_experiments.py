#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Iterable, Tuple


ROOT = Path(__file__).resolve().parent
HRPCH_DIR = (ROOT / "hr_pch_sgx").resolve()
RPCH_BENCH_DIR = (ROOT / "rpch_bench").resolve()


def _run(cmd: list[str], *, cwd: Path) -> None:
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=str(cwd), check=True, stdout=sys.stdout, stderr=sys.stderr)


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _needs_curve(path: Path, curve: str) -> bool:
    if not path.exists():
        return True
    try:
        j = _read_json(path)
    except Exception:
        return True
    params = j.get("params", {})
    return params.get("curve") != curve


def _copy_json_with_threads(src: Path, dst: Path, *, threads: int) -> None:
    j = _read_json(src)
    params = j.setdefault("params", {})
    params["threads"] = int(threads)
    dst.write_text(json.dumps(j, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _iter_unique(pairs: Iterable[Tuple[int, int]]) -> list[Tuple[int, int]]:
    seen: set[Tuple[int, int]] = set()
    out: list[Tuple[int, int]] = []
    for a, p in pairs:
        key = (int(a), int(p))
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Run TEE-RPCH/RPCH experiments for a given PBC curve and save JSON outputs.")
    ap.add_argument(
        "--curve",
        default="a",
        help="PBC curve: a|a672(type-a matched to MNT224)|a1|e|i|f|d224|mnt224",
    )
    ap.add_argument("--out-dir", default=str(ROOT / "report" / "data_typea"), help="Output directory for JSON data.")
    ap.add_argument("--do-id", default="do1", help="Owner/DO identity used in TEE-RPCH.")
    ap.add_argument("--build", action="store_true", help="Rebuild hr_pch_sgx and rpch_bench before running.")
    ap.add_argument("--force", action="store_true", help="Rerun and overwrite outputs even if JSON already exists.")
    args = ap.parse_args()

    curve = str(args.curve)
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    app_path = str((HRPCH_DIR / "app").resolve())
    rpch_path = str((RPCH_BENCH_DIR / "rpch_bench").resolve())

    if args.build:
        _run(["make", "SGX_MODE=HW", "SGX_DEBUG=0", f"-j{os.cpu_count() or 4}"], cwd=HRPCH_DIR)
        _run(["make", "DEBUG=0", f"-j{os.cpu_count() or 4}"], cwd=RPCH_BENCH_DIR)

    # ---- Micro-bench / scaling experiments used by the paper figures ----
    # - Fixed |S|=60, vary |policy| in {10,20,30,40,60}
    # - Fixed |policy|=20, vary |S| in {40,60,80,100}
    users = 1024
    policy_var = [10, 20, 30, 40, 60]
    attrs_var = [40, 60, 80, 100]
    required_pairs = _iter_unique([(60, p) for p in policy_var] + [(a, 20) for a in attrs_var])

    for attrs, policy in required_pairs:
        hr_out = out_dir / f"hrpch_u{users}_a{attrs}_p{policy}.json"
        rp_out = out_dir / f"rpch_u{users}_a{attrs}_p{policy}.json"

        if args.force or _needs_curve(hr_out, curve):
            _run(
                [
                    app_path,
                    "--curve",
                    curve,
                    "--rsa-bits",
                    "3072",
                    "--attrs",
                    str(attrs),
                    "--policy-attrs",
                    str(policy),
                    "--do-id",
                    str(args.do_id),
                    "--out",
                    str(hr_out),
                ],
                cwd=HRPCH_DIR,
            )

        if args.force or _needs_curve(rp_out, curve):
            _run(
                [
                    rpch_path,
                    "--curve",
                    curve,
                    "--rsa-bits",
                    "3072",
                    "--users",
                    str(users),
                    "--attrs",
                    str(attrs),
                    "--policy-attrs",
                    str(policy),
                    "--mode",
                    "ops",
                    "--out",
                    str(rp_out),
                ],
                cwd=RPCH_BENCH_DIR,
            )

    # ---- Revocation overhead (table-only in the paper) ----
    base_attrs = 60
    base_policy = 20
    for exp in range(10, 19):
        n = 2**exp
        hr_out = out_dir / f"hrpch_state_{n}.json"
        rp_out = out_dir / f"rpch_rev_{n}.json"

        if args.force or _needs_curve(hr_out, curve):
            _run(
                [app_path, "--curve", curve, "--bench", "state", "--user-count", str(n), "--do-id", str(args.do_id), "--out", str(hr_out)],
                cwd=HRPCH_DIR,
            )

        if args.force or _needs_curve(rp_out, curve):
            _run(
                [
                    rpch_path,
                    "--curve",
                    curve,
                    "--rsa-bits",
                    "3072",
                    "--users",
                    str(n),
                    "--attrs",
                    str(base_attrs),
                    "--policy-attrs",
                    str(base_policy),
                    "--mode",
                    "revocation",
                    "--out",
                    str(rp_out),
                ],
                cwd=RPCH_BENCH_DIR,
            )

    # ---- Multi-thread cost experiments (Fig. cost vs tasks / threads) ----
    # Cost-vs-tasks: fixed policy=20, threads in {1,3,6}, tasks in {50..300}
    # Cost-vs-threads: fixed tasks=200, policy in {10,20,30}, threads in {1..6}
    tasks_list = [50, 100, 150, 200, 250, 300]
    threads_list_tasks = [1, 3, 6]
    policies_threads = [10, 20, 30]
    threads_list = [1, 2, 3, 4, 5, 6]
    modes = ["hrpch", "no_outsource"]

    for mode in modes:
        # ---- Cost-vs-tasks ----
        if mode == "no_outsource":
            # Baseline has no cloud server; --threads is metadata only. Avoid re-running identical work.
            t0 = threads_list_tasks[0]
            for task in tasks_list:
                out0 = out_dir / f"hrpch_cost_{mode}_p20_tasks{task}_t{t0}.json"
                if args.force or _needs_curve(out0, curve):
                    _run(
                        [
                            app_path,
                            "--curve",
                            curve,
                            "--bench",
                            "cost",
                            "--mode",
                            mode,
                            "--rsa-bits",
                            "3072",
                            "--attrs",
                            str(base_attrs),
                            "--policy-attrs",
                            str(base_policy),
                            "--user-count",
                            str(users),
                            "--threads",
                            str(t0),
                            "--tasks",
                            str(task),
                            "--do-id",
                            str(args.do_id),
                            "--out",
                            str(out0),
                        ],
                        cwd=HRPCH_DIR,
                    )
                for t in threads_list_tasks[1:]:
                    out_path = out_dir / f"hrpch_cost_{mode}_p20_tasks{task}_t{t}.json"
                    if args.force or _needs_curve(out_path, curve):
                        _copy_json_with_threads(out0, out_path, threads=t)
        else:
            for t in threads_list_tasks:
                for task in tasks_list:
                    out_path = out_dir / f"hrpch_cost_{mode}_p20_tasks{task}_t{t}.json"
                    if args.force or _needs_curve(out_path, curve):
                        _run(
                            [
                                app_path,
                                "--curve",
                                curve,
                                "--bench",
                                "cost",
                                "--mode",
                                mode,
                                "--rsa-bits",
                                "3072",
                                "--attrs",
                                str(base_attrs),
                                "--policy-attrs",
                                str(base_policy),
                                "--user-count",
                                str(users),
                                "--threads",
                                str(t),
                                "--tasks",
                                str(task),
                                "--do-id",
                                str(args.do_id),
                                "--out",
                                str(out_path),
                            ],
                            cwd=HRPCH_DIR,
                        )

        # ---- Cost-vs-threads ----
        if mode == "no_outsource":
            t0 = threads_list[0]
            for p in policies_threads:
                out0 = out_dir / f"hrpch_cost_{mode}_p{p}_tasks200_t{t0}.json"
                if args.force or _needs_curve(out0, curve):
                    _run(
                        [
                            app_path,
                            "--curve",
                            curve,
                            "--bench",
                            "cost",
                            "--mode",
                            mode,
                            "--rsa-bits",
                            "3072",
                            "--attrs",
                            str(base_attrs),
                            "--policy-attrs",
                            str(p),
                            "--user-count",
                            str(users),
                            "--threads",
                            str(t0),
                            "--tasks",
                            "200",
                            "--do-id",
                            str(args.do_id),
                            "--out",
                            str(out0),
                        ],
                        cwd=HRPCH_DIR,
                    )
                for t in threads_list[1:]:
                    out_path = out_dir / f"hrpch_cost_{mode}_p{p}_tasks200_t{t}.json"
                    if args.force or _needs_curve(out_path, curve):
                        _copy_json_with_threads(out0, out_path, threads=t)
        else:
            for p in policies_threads:
                for t in threads_list:
                    out_path = out_dir / f"hrpch_cost_{mode}_p{p}_tasks200_t{t}.json"
                    if args.force or _needs_curve(out_path, curve):
                        _run(
                            [
                                app_path,
                                "--curve",
                                curve,
                                "--bench",
                                "cost",
                                "--mode",
                                mode,
                                "--rsa-bits",
                                "3072",
                                "--attrs",
                                str(base_attrs),
                                "--policy-attrs",
                                str(p),
                                "--user-count",
                                str(users),
                                "--threads",
                                str(t),
                                "--tasks",
                                "200",
                                "--do-id",
                                str(args.do_id),
                                "--out",
                                str(out_path),
                            ],
                            cwd=HRPCH_DIR,
                        )

    print(f"Done. Wrote JSON to: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
