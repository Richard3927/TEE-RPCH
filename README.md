# TEE-RPCH (Intel SGX) Implementation

This repository contains the public implementation of **TEE-RPCH**, an Intel SGX assisted revocable policy-based chameleon hash system for blockchain redaction.

## Repository Structure

- `hr_pch_sgx/`: main TEE-RPCH prototype, including the host application and SGX enclave
- `rpch_bench/`: benchmark implementation for the revocation baselines used in the comparison experiments
- `CH_PBC_example-main/`: pairing / ABE / RSA helper library used by both `hr_pch_sgx/` and `rpch_bench/`
- `run_curve_experiments.py`: unified driver for the main paper-style experiment runs
- `five_experiments_20260429/run_targeted_tables.py`: targeted experiment script for the hash-check comparison and the revocation benchmark table

## Build TEE-RPCH

The main implementation is in `hr_pch_sgx/`.

Prerequisites:

1. Intel SGX driver, PSW, and SDK
2. SGXSSL if you build the enclave with in-enclave crypto
3. `gmp`, `pbc`, `openssl`
4. The helper library under `CH_PBC_example-main/`

Build the SGX prototype:

```bash
cd hr_pch_sgx
make clean
make SGX_MODE=HW SGX_DEBUG=0 -j"$(nproc)"
```

Build the revocation benchmark:

```bash
cd rpch_bench
make clean
make -j"$(nproc)"
```

## Basic TEE-RPCH Run

The basic TEE-RPCH construction is executed by `hr_pch_sgx/app`. A normal run evaluates the full workflow:

- setup
- key generation
- hash / verify
- server-side outsourced adaptation
- enclave-side checking
- user-side final adaptation

Example:

```bash
cd hr_pch_sgx
./app --curve mnt224 --out artifacts/results.json
```

Important implementation split in the current code:

- the server performs the first outsourced stage
- the enclave performs state checking, helper-key decryption, and protected checks
- the user performs the final adaptation step

## Experiment 1: Outsource vs Non-Outsource

Purpose:

- compare the deployed TEE-RPCH outsourced path with the no-outsource baseline inside the same implementation framework

Driver:

- `run_curve_experiments.py`

How it works:

- it runs `hr_pch_sgx/app --bench cost`
- it generates JSON files with mode `hrpch` and `no_outsource`
- it varies policy size and task count to compare the outsourced design against the non-outsourced path

Example:

```bash
python3 run_curve_experiments.py --curve mnt224 --out-dir out/mnt224 --build --force
```

Key outputs:

- `hrpch_u1024_a*_p*.json`: main TEE-RPCH runs
- `hrpch_cost_hrpch_*.json`: outsourced cost measurements
- `hrpch_cost_no_outsource_*.json`: non-outsourced cost measurements

## Experiment 2: Multi-Thread Experiment

Purpose:

- measure how the server-side outsourced path scales with different thread counts and task counts

Driver:

- `run_curve_experiments.py`

How it works:

- cost-vs-tasks: fixed policy size, vary tasks and server thread counts
- cost-vs-threads: fixed task count, vary policy sizes and server thread counts

The relevant outputs are the `hrpch_cost_*` JSON files written by `run_curve_experiments.py`.

## Experiment 3: Hash-Check Efficiency Experiment

Purpose:

- show the efficiency gain from replacing the old user-side full re-encryption consistency check with the current hash-check finalization

Driver:

- `five_experiments_20260429/run_targeted_tables.py`

How it works:

- it validates that the TEE-RPCH run uses the expected full implementation version
- it compares:
  - the full re-encryption based final user check
  - the hash-check based final user check
- it focuses on modifier-side finalization cost

Example:

```bash
python3 five_experiments_20260429/run_targeted_tables.py --force
```

This script is the retained targeted code path for the hash-check proof experiment.

## Experiment 4: Benchmark / Revocation Experiment

Purpose:

- compare **TEE-RPCH**, **EHR-RPCH**, and **TAR-PCH** on revocation-related costs
- especially separate KGC-side and server / CSP-side work instead of reporting only coarse totals

Relevant code:

- `rpch_bench/main.cpp`
- `rpch_bench/jmc_kh_lattice.cpp`
- `rpch_bench/jmc_kh_lattice.h`
- `five_experiments_20260429/run_targeted_tables.py`

How it works:

- `rpch_bench` runs the baseline revocation schemes
- `run_curve_experiments.py` can generate the baseline revocation JSON files
- `run_targeted_tables.py` checks that the benchmark version is the expected split revocation implementation and then builds the benchmark comparison table inputs

Example baseline-only benchmark run:

```bash
cd rpch_bench
./rpch_bench --curve mnt224 --users 1024 --attrs 60 --policy-attrs 20 --mode revocation --out artifacts/rpch_rev_1024.json
```

Example unified experiment run:

```bash
python3 run_curve_experiments.py --curve mnt224 --out-dir out/mnt224 --force
```

## Recommended Reproduction Order

1. Build `hr_pch_sgx/`
2. Build `rpch_bench/`
3. Run `run_curve_experiments.py` for `mnt224`
4. Run `run_curve_experiments.py` for `a1`
5. Run `five_experiments_20260429/run_targeted_tables.py` if you want the targeted hash-check and revocation benchmark experiment

## Notes

- Measure performance in **SGX HW mode**, not SIM mode.
- Some directory names are legacy, but the scheme implemented here is **TEE-RPCH**.

## License

See `LICENSE`.
