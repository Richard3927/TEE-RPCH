# TEE-RPCH Threading Performance Analysis and Notes

## Executive Summary

This note explains the multi-thread cost behavior in the TEE-RPCH (outsourcing) benchmark, and why early plots could look like “threads don’t help”.

- ✅ TEE-RPCH *does* benefit from increasing the **server thread count**.
- ✅ The no-outsourcing baseline is **not thread-parameterized** (there is no cloud server), so its cost is constant across “threads”.
- ✅ Any plateau/diminishing returns are explained by the sequential stages (TEE + user) becoming the bottleneck (Amdahl’s law / pipeline bound).

## Performance Analysis Results

### Current Performance (A1/ss1024, |S|=60, |policy|=20, tasks=200)

| Threads | Time/Task | Speedup vs t=1 | Efficiency |
|---------|-----------|----------------|------------|
| No-outsourcing baseline | 1975.53 ms | N/A | N/A |
| TEE-RPCH t=1 | 2062.35 ms | 1.00x | 100% |
| TEE-RPCH t=2 | 1032.65 ms | 2.00x | 100% |
| TEE-RPCH t=3 | 691.35 ms | 2.98x | 99% |
| TEE-RPCH t=4 | 517.84 ms | 3.98x | 99% |
| TEE-RPCH t=5 | 413.91 ms | 4.98x | 100% |
| TEE-RPCH t=6 | 352.21 ms | 5.86x | 98% |

### Issue Analysis

#### 1) Why early plots could look like “threads don’t help”

There are two practical reasons:

1. **Plot compression / shared y-axis**: when two curves are close (especially at Threads=1), using shared axes (or very wide y-ranges / log-y) can visually “flatten” the gap.
2. **Baseline interpretation**: the *no-outsourcing* baseline has no cloud server, so it should not change with “server threads”. In our runner, we only measure it once (t=1) and copy the JSON while changing the metadata field `threads`, so the baseline line is intentionally constant.

#### 2) Why scaling can plateau (when it does)

As threads increase, the server stage gets faster, until the total time is dominated by the sequential stages (TEE + user).

This is expected: even with many server threads, you cannot go below the per-task time of the non-parallelizable work.

In MNT224, we see diminishing returns around Threads=5..6 (server is no longer the bottleneck), while in A1 the server stage is still heavy enough that scaling continues to be visible up to 6 threads.

## Where the numbers come from

The table is computed from these JSON outputs:
- A1: `report/data_a1/hrpch_cost_{hrpch,no_outsource}_p20_tasks200_t{1..6}.json`
- MNT224: `report/data/hrpch_cost_{hrpch,no_outsource}_p20_tasks200_t{1..6}.json`
