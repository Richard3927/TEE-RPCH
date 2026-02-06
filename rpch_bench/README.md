# Baseline Benchmarks (RPCH-XNM'21 / RPCH-TMM'22)

This directory builds a small benchmark tool that generates baseline timing data for prior work
(XNM'21 / TMM'22), which is used by the TEE-RPCH plotting scripts.

## Build

The Makefile expects the pairing/ABE helper library under `../CH_PBC_example-main/` (sources + headers).
If that dependency is missing in your snapshot, rebuilding will fail until you restore it.

```bash
cd rpch_bench
make clean
make -j"$(nproc)"
```

## Run

Example (users = 2^10):

```bash
./rpch_bench --curve a --users 1024 --attrs 40 --policy-attrs 40 --out artifacts/rpch_1024.json
```

Options:
- `--curve`: `a|a1|e|i|f|d224` (paper uses `mnt224` and `a1` / ss1024)
- `--users`: number of users (power of two, >= 2)
- `--attrs`: attribute set size
- `--policy-attrs`: number of attributes used in the access policy (<= attrs)
- `--out`: output JSON path

Output:
- A JSON file containing per-operation timings. This is later aggregated by `run_curve_experiments.py`
  and plotted via `generate_paper_assets.py`.
