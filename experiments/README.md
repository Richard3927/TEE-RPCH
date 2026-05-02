# Experiment Entry Points

The experiment scripts are split by the question they answer.

- `exp0_basic_construction.py`: runs one full TEE-RPCH workflow and writes a single JSON report.
- `exp1_outsource_vs_no_outsource.py`: compares the outsourced TEE-RPCH path with the no-outsource path.
- `exp2_multithread_scaling.py`: measures server-side thread scaling for the outsourced path.
- `exp3_hashcheck_efficiency.py`: regenerates the targeted hash-check comparison and revocation tables.
- `exp4_revocation_benchmark.py`: runs TEE-RPCH, EHR-RPCH, and TAR-PCH revocation measurements.
- `run_all.py`: runs the organized suite except the targeted table/PDF builder.

Use `--build` on the first run if `hr_pch_sgx/app` or `rpch_bench/rpch_bench` has not been built.

## Measuring A1 / ss1024 Data

All organized scripts except `exp3_hashcheck_efficiency.py` accept `--curve a1`:

```bash
python3 experiments/run_all.py --curve a1 --out-dir out/a1_suite --build --force
python3 experiments/exp0_basic_construction.py --curve a1 --out out/a1/basic/results.json --build
python3 experiments/exp1_outsource_vs_no_outsource.py --curve a1 --out-dir out/a1/exp1 --build --force
python3 experiments/exp2_multithread_scaling.py --curve a1 --out-dir out/a1/exp2 --build --force
python3 experiments/exp4_revocation_benchmark.py --curve a1 --out-dir out/a1/exp4 --build --force
```

`exp3_hashcheck_efficiency.py` runs both `mnt224` and `a1` internally and writes raw A1 JSON files to `out/targeted_hashcheck_revocation/raw/a1/`:

```bash
python3 experiments/exp3_hashcheck_efficiency.py --force
```

For every generated JSON file, confirm `params.curve` is `a1` before using it as A1 curve data.
