#!/usr/bin/env python3
"""Analyze TEE-RPCH threading performance to identify bottlenecks."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

def main():
    root = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(description="Analyze TEE-RPCH threading results (cost benchmark JSON).")
    ap.add_argument("--data-dir", default=str(root / "report" / "data_a1"), help="Directory containing curve JSON data.")
    ap.add_argument("--tasks", type=int, default=200, help="Task count used in the cost-vs-threads experiment.")
    ap.add_argument("--policy", type=int, default=20, help="Policy size used in the cost-vs-threads experiment.")
    args = ap.parse_args()

    data_dir = Path(args.data_dir).resolve()

    print("=" * 80)
    print(f"TEE-RPCH Threading Performance Analysis (data={data_dir})")
    print("=" * 80)

    # Collect data
    hrpch_data = {}
    for t in [1, 2, 3, 4, 5, 6]:
        f = data_dir / f"hrpch_cost_hrpch_p{args.policy}_tasks{args.tasks}_t{t}.json"
        if f.exists():
            d = json.loads(f.read_text())
            hrpch_data[t] = d["results"]["elapsed_ms"]

    baseline_file = data_dir / f"hrpch_cost_no_outsource_p{args.policy}_tasks{args.tasks}_t1.json"
    baseline_ms = 0
    if baseline_file.exists():
        d = json.loads(baseline_file.read_text())
        baseline_ms = d["results"]["elapsed_ms"]

    tasks = float(args.tasks)
    print(f"\nBaseline (no_outsource, threads=1): {baseline_ms:.1f}ms total, {baseline_ms/tasks:.2f}ms/task")
    print()

    print("TEE-RPCH Performance:")
    print(f"{'Threads':<10} {'Total (ms)':<15} {'Per Task (ms)':<18} {'Speedup vs t=1':<20} {'Speedup vs baseline'}")
    print("-" * 95)

    hrpch_t1 = hrpch_data.get(1, 0)
    for t in sorted(hrpch_data.keys()):
        total_ms = hrpch_data[t]
        per_task = total_ms / tasks
        speedup_vs_t1 = hrpch_t1 / total_ms if total_ms > 0 else 0
        speedup_vs_base = baseline_ms / total_ms if total_ms > 0 else 0
        print(f"{t:<10} {total_ms:<15.1f} {per_task:<18.2f} {speedup_vs_t1:<20.3f}x {speedup_vs_base:.3f}x")

    print("\n" + "=" * 80)
    print("ANALYSIS:")
    print("=" * 80)

    # Issue 1: threads=1 performance
    if hrpch_t1 > 0 and baseline_ms > 0:
        diff_pct = ((hrpch_t1 - baseline_ms) / baseline_ms) * 100
        print(f"\n1. threads=1 Comparison:")
        print(f"   - TEE-RPCH: {hrpch_t1:.1f}ms")
        print(f"   - Baseline: {baseline_ms:.1f}ms")
        print(f"   - Difference: {hrpch_t1 - baseline_ms:+.1f}ms ({diff_pct:+.2f}%)")
        if diff_pct <= 0:
            print("   ⚠️  Unexpected: TEE-RPCH is not slower at threads=1; check benchmark configuration.")
        else:
            print("   ✓ Expected: TEE-RPCH is slower at threads=1 (outsourcing + checks).")

    # Issue 2: Threading scaling
    print(f"\n2. Threading Scaling:")
    print(f"   {'Threads':<10} {'Speedup':<12} {'Efficiency':<15} {'Status'}")
    print(f"   {'-'*50}")
    for t in sorted(hrpch_data.keys()):
        if t == 1:
            continue
        speedup = hrpch_t1 / hrpch_data[t]
        efficiency = (speedup / t) * 100
        status = "✓ Good" if efficiency > 50 else "⚠️  Poor"
        print(f"   {t:<10} {speedup:<12.2f}x {efficiency:<15.1f}% {status}")

    # Issue 3: Bottleneck identification
    print(f"\n3. Bottleneck Analysis:")
    max_threads = max(hrpch_data.keys())
    max_speedup = hrpch_t1 / hrpch_data[max_threads]
    print(f"   - Maximum speedup (threads={max_threads}): {max_speedup:.2f}x")
    print(f"   - Theoretical maximum (if fully parallel): {max_threads}x")
    print(f"   - Parallel efficiency: {(max_speedup/max_threads)*100:.1f}%")

    # Check for plateau
    plateau_detected = False
    for i, t in enumerate(sorted(hrpch_data.keys())[:-1]):
        next_t = sorted(hrpch_data.keys())[i+1]
        improvement = (hrpch_data[t] - hrpch_data[next_t]) / hrpch_data[t] * 100
        if improvement < 2:  # Less than 2% improvement
            if not plateau_detected:
                print(f"\n   ⚠️  PLATEAU DETECTED at threads={t}!")
                plateau_detected = True
                print(f"   - Going from {t} to {next_t} threads: only {improvement:.2f}% improvement")

    if plateau_detected:
        print(f"\n   ROOT CAUSE: TEE or User stage is the bottleneck (single-threaded)")
        print(f"   - Server stage can be parallelized (multiple threads)")
        print(f"   - TEE stage: single-threaded enclave calls (IBE decrypt, RSA ops)")
        print(f"   - User stage: single-threaded ABE decrypt + RSA exp")

    # Calculate estimated stage times
    print(f"\n4. Estimated Pipeline Stage Times:")
    if 6 in hrpch_data and hrpch_t1 > 0:
        # At threads=6, assume server stage is negligible due to parallelism
        # The bottleneck time is approximately the per-task time
        bottleneck_time = hrpch_data[6] / tasks
        # At threads=1, total time = server + tee + user (with some pipeline overlap)
        # Approximate: server_time ≈ (time_t1 - time_t6) / tasks
        server_time = (hrpch_t1 - hrpch_data[6]) / tasks
        print(f"   - Estimated Server stage (parallelizable): ~{server_time:.1f}ms/task")
        print(f"   - Estimated TEE+User stage (bottleneck): ~{bottleneck_time:.1f}ms/task")
        print(f"   - Server accounts for: {(server_time/hrpch_t1*100):.1f}% of total time at threads=1")

    print("\n" + "=" * 80)
    print("RECOMMENDATIONS:")
    print("=" * 80)
    print("""
1. If scaling plateaus at higher thread counts:
   - The TEE + user stages are inherently sequential (security / protocol requirement).
   - Document that server-side parallelism helps until the enclave/user becomes the bottleneck.

2. For paper narrative:
   - Emphasize the expected behavior: TEE-RPCH is slower at threads=1, but improves with server concurrency.
""")

if __name__ == "__main__":
    main()
