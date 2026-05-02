# TEE-RPCH (Intel SGX) Implementation

This repository contains the public implementation of **TEE-RPCH**, an Intel SGX assisted revocable policy-based chameleon hash system for blockchain redaction.

## Repository Structure

- `hr_pch_sgx/`: TEE-RPCH implementation, including the host application and SGX enclave.
- `rpch_bench/`: EHR-RPCH and TAR-PCH revocation benchmark implementation.
- `CH_PBC_example-main/`: pairing, ABE, RSA, and helper code used by the prototype and benchmark.
- `experiments/`: organized experiment entry points.
- `run_curve_experiments.py`: compatibility wrapper for `experiments/run_all.py`.

## Build

Build the SGX prototype:

```bash
cd hr_pch_sgx
make clean
make SGX_MODE=HW SGX_DEBUG=0 -j"$(nproc)"
```

Build the baseline benchmark:

```bash
cd rpch_bench
make clean
make -j"$(nproc)"
```

## Basic Construction

The basic construction is implemented in `hr_pch_sgx/app`. A normal run executes setup, key generation, hashing, verification, server-side adaptation, enclave-side checks, and final user adaptation.

```bash
python3 experiments/exp0_basic_construction.py --curve mnt224 --build
```

The generated JSON records the measured roles:

- KGC setup and user key generation
- data-owner hash generation
- server adaptation
- enclave protected checks
- user final adaptation

## Experiment 1: Outsource vs Non-Outsource

Script:

```bash
python3 experiments/exp1_outsource_vs_no_outsource.py --curve mnt224 --build --force
```

This compares two modes in `hr_pch_sgx/app --bench cost`:

- `--mode hrpch`: the deployed TEE-RPCH path with server-side outsourcing.
- `--mode no_outsource`: the non-outsourced path used as the internal baseline.

The output files are named `hrpch_cost_hrpch_*.json` and `hrpch_cost_no_outsource_*.json` so the two paths can be separated directly by filename.

## Experiment 2: Multi-Thread Scaling

Script:

```bash
python3 experiments/exp2_multithread_scaling.py --curve mnt224 --build --force
```

This experiment measures how the outsourced path behaves when server-side concurrency changes.

It runs two groups:

- cost vs tasks: fixed policy size, varying task count and thread count
- cost vs threads: fixed task count, varying policy size and thread count

For the non-outsourced baseline, extra thread counts are recorded as metadata because there is no cloud/server stage to parallelize.

## Experiment 3: Hash-Check Efficiency

Script:

```bash
python3 experiments/exp3_hashcheck_efficiency.py --force
```

This experiment isolates the final user-side check. It compares:

- full re-encryption based consistency checking
- hash-check based finalization

The script validates that the JSON data was produced by the expected full implementation and then generates the hash-check comparison tables and figures under `out/targeted_hashcheck_revocation/`.

The legacy path `five_experiments_20260429/run_targeted_tables.py` is only a wrapper to this script.

## Experiment 4: Revocation Benchmark

Script:

```bash
python3 experiments/exp4_revocation_benchmark.py --curve mnt224 --build --force
```

This experiment compares revocation costs for:

- TEE-RPCH
- EHR-RPCH
- TAR-PCH

TEE-RPCH state signing and TEE checking are measured by `hr_pch_sgx/app --bench state`. EHR-RPCH and TAR-PCH are measured by `rpch_bench --mode revocation`, including split KGC-side and server/CSP-side costs.

## Full Organized Run

Run the organized suite for one curve:

```bash
python3 experiments/run_all.py --curve mnt224 --build --force
```

The old command still works and forwards to the organized suite:

```bash
python3 run_curve_experiments.py --curve mnt224 --build --force
```

## Notes

- Performance measurements should be taken in SGX HW mode.
- SIM mode is for functional debugging only.
- Some source folders retain historical names, but the implemented scheme is TEE-RPCH.

## License

See `LICENSE`.
