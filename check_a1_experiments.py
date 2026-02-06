#!/usr/bin/env python3
"""
Check completeness of A1 (ss1024) curve experiments.

This script verifies that `run_curve_experiments.py --curve a1` has produced all JSON outputs
needed by `generate_paper_assets.py`.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    ap = argparse.ArgumentParser(description="Check completeness of A1 (ss1024) experiment JSON outputs.")
    ap.add_argument("--data-dir", default=str(ROOT / "report" / "data_a1"), help="Directory containing A1 JSON data.")
    args = ap.parse_args()

    data_dir = Path(args.data_dir).resolve()

    print("=" * 80)
    print("A1 (ss1024) EXPERIMENT COMPLETENESS CHECK")
    print("=" * 80)
    print(f"Data dir: {data_dir}")

    # 1. Micro-benchmarks
    print("\n1. Micro-benchmark Experiments (hrpch_u1024_a*_p*.json, rpch_u1024_a*_p*.json):")
    required_pairs = [
        (60, 10), (60, 20), (60, 30), (60, 40), (60, 60),  # Fixed attrs=60, vary policy
        (40, 20), (60, 20), (80, 20), (100, 20)            # Fixed policy=20, vary attrs
    ]
    required_pairs = list(set(required_pairs))  # Remove duplicates

    missing = []
    for attrs, policy in sorted(required_pairs):
        hr_file = data_dir / f"hrpch_u1024_a{attrs}_p{policy}.json"
        rp_file = data_dir / f"rpch_u1024_a{attrs}_p{policy}.json"
        hr_exists = hr_file.exists()
        rp_exists = rp_file.exists()
        status = "✓" if (hr_exists and rp_exists) else "✗"
        print(f"   {status} attrs={attrs:3d}, policy={policy:2d}: HR={'✓' if hr_exists else '✗'} RPCH={'✓' if rp_exists else '✗'}")
        if not (hr_exists and rp_exists):
            missing.append(("micro", attrs, policy))

    # 2. Revocation experiments
    print("\n2. Revocation Experiments (hrpch_state_*.json, rpch_rev_*.json):")
    revocation_counts = []
    for exp in range(10, 19):
        n = 2 ** exp
        revocation_counts.append(n)
        hr_file = data_dir / f"hrpch_state_{n}.json"
        rp_file = data_dir / f"rpch_rev_{n}.json"
        hr_exists = hr_file.exists()
        rp_exists = rp_file.exists()
        status = "✓" if (hr_exists and rp_exists) else "✗"
        print(f"   {status} n=2^{exp:2d} ({n:6d}): HR={'✓' if hr_exists else '✗'} RPCH={'✓' if rp_exists else '✗'}")
        if not (hr_exists and rp_exists):
            missing.append(("revocation", n, exp))

    # 3. Threading/Cost experiments
    print("\n3. Threading/Cost Experiments:")

    # Cost vs tasks (policy=20, threads in {1,3,6}, tasks in {50,100,150,200,250,300})
    print("\n   a) Cost vs Tasks (policy=20, threads={1,3,6}):")
    tasks_list = [50, 100, 150, 200, 250, 300]
    threads_list = [1, 3, 6]
    modes = ["hrpch", "no_outsource"]

    for mode in modes:
        print(f"\n      Mode: {mode}")
        for t in threads_list:
            for task in tasks_list:
                file = data_dir / f"hrpch_cost_{mode}_p20_tasks{task}_t{t}.json"
                exists = file.exists()
                status = "✓" if exists else "✗"
                print(f"         {status} threads={t}, tasks={task:3d}")
                if not exists:
                    missing.append(("cost_tasks", mode, t, task))

    # Cost vs threads (tasks=200, policy in {10,20,30}, threads in {1,2,3,4,5,6})
    print("\n   b) Cost vs Threads (tasks=200, policy={10,20,30}):")
    policies = [10, 20, 30]
    all_threads = [1, 2, 3, 4, 5, 6]

    for mode in modes:
        print(f"\n      Mode: {mode}")
        for p in policies:
            print(f"         policy={p}:")
            for t in all_threads:
                file = data_dir / f"hrpch_cost_{mode}_p{p}_tasks200_t{t}.json"
                exists = file.exists()
                status = "✓" if exists else "✗"
                print(f"            {status} threads={t}")
                if not exists:
                    missing.append(("cost_threads", mode, p, t))

    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY:")
    print("=" * 80)
    if not missing:
        print("\n✓ All experiments are complete!")
    else:
        print(f"\n✗ Missing {len(missing)} experiment(s)")
        print("\nMissing experiments by category:")
        from collections import Counter
        by_type = Counter(m[0] for m in missing)
        for exp_type, count in by_type.items():
            print(f"   - {exp_type}: {count} missing")

    # Optional quick sanity on threading trend (p20, tasks=200)
    print("\n" + "=" * 80)
    print("THREADING SANITY (p20, tasks=200)")
    print("=" * 80)
    try:
        base = float(_read_json(data_dir / "hrpch_cost_no_outsource_p20_tasks200_t1.json")["results"]["elapsed_ms"])
        hr_t1 = float(_read_json(data_dir / "hrpch_cost_hrpch_p20_tasks200_t1.json")["results"]["elapsed_ms"])
        hr_t6 = float(_read_json(data_dir / "hrpch_cost_hrpch_p20_tasks200_t6.json")["results"]["elapsed_ms"])
        print(f"Baseline (no-outsourcing, t=1): {base/1000.0:.2f}s total ({base/200.0:.2f}ms/task)")
        print(f"TEE-RPCH (t=1):              {hr_t1/1000.0:.2f}s total ({hr_t1/200.0:.2f}ms/task)")
        print(f"TEE-RPCH (t=6):              {hr_t6/1000.0:.2f}s total ({hr_t6/200.0:.2f}ms/task)")
        if base > 0:
            print(f"t=1 overhead vs baseline:    {(hr_t1/base - 1.0)*100.0:+.2f}%")
            print(f"t=6 speedup vs baseline:     {base/hr_t6:.2f}x")
        if hr_t1 > 0:
            print(f"t=6 speedup vs t=1 (TEE-RPCH): {hr_t1/hr_t6:.2f}x")
    except Exception as exc:  # pragma: no cover - optional
        print(f"(Skipped threading sanity: {exc})")

if __name__ == "__main__":
    main()
