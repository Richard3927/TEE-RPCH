# Revocation Baseline Benchmark

This directory contains the baseline benchmark used by the revocation experiment.

Implemented benchmark targets:

- `EHR_RPCH`
- `TAR_PCH`
- `JMC_KH_2024_Lattice_RPCH`

The public experiment scripts currently use EHR-RPCH and TAR-PCH for the revocation comparison against TEE-RPCH.

## Build

```bash
cd rpch_bench
make clean
make -j"$(nproc)"
```

The Makefile expects `../CH_PBC_example-main/` to contain the required pairing, ABE, RSA, and helper sources.

## Run

Revocation benchmark:

```bash
./rpch_bench --curve mnt224 --users 1024 --attrs 60 --policy-attrs 20 --mode revocation --out artifacts/rpch_rev_1024.json
```

Operation benchmark:

```bash
./rpch_bench --curve mnt224 --users 1024 --attrs 60 --policy-attrs 20 --mode ops --out artifacts/rpch_ops_1024.json
```

Important output fields:

- `params.bench_version`: should be `rpch-baselines-v10-ehr-tar-full-revocation-split`.
- `schemes.EHR_RPCH.times_ms`: EHR-RPCH timing breakdown.
- `schemes.TAR_PCH.times_ms`: TAR-PCH timing breakdown.

The organized experiment entry point is `../experiments/exp4_revocation_benchmark.py`.
