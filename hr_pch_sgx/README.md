# TEE-RPCH + Intel SGX (TEE) Prototype

This directory contains the **Intel SGX** implementation used to evaluate **TEE-RPCH**.

What it does:
- Implements the TEE-RPCH workflow (`Setup/KeyGen/Hash/Verify/ServerAdapt/KeyExtract/InsiderAdapt/UserAdapt`)
- Simulates five roles: `KGC / Server / DataOwner / DataUser / TEE(SGX)`
- Executes the TEE stage inside an **SGX enclave** (ECALL/OCALL)
- Outputs per-operation timings and cost-benchmark JSON used by the paper plots

## Dependencies

- Intel SGX SDK: `/opt/intel/sgxsdk`
- Intel SGXSSL: `/opt/intel/sgxssl`
- System libs: `gmp`, `pbc`, `openssl`

Building from source expects the pairing/ABE helper library under `../CH_PBC_example-main/`
(i.e., `include/` + `src/*.cpp`).

## Build

Hardware SGX mode (real enclave execution):

```bash
cd hr_pch_sgx
make clean
make SGX_MODE=HW SGX_DEBUG=0 -j"$(nproc)"
```

`QUIET=1` disables verbose prints in the underlying crypto library (recommended for timing).

```bash
make SGX_MODE=HW QUIET=0
```

Simulation mode (for development only; NOT for timing claims):

```bash
make clean
make SGX_MODE=SIM
```

## Run

Example run (writes a JSON summary under `artifacts/`):

```bash
cd hr_pch_sgx
./app --curve a1 --out artifacts/results.json
```

If your user is not permitted to access SGX devices, you may need to run under the `sgx` group:

```bash
sg sgx -c './app --curve a1 --out artifacts/results.json'
```

Generated files:
- `artifacts/results.json`: raw timing/storage measurements
- `artifacts/runtime.svg`: runtime plots
- `artifacts/storage.svg`: storage plots
- `artifacts/REPORT.md`: auto-generated report

## Notes About `app` vs `app.bin`

In some packaged environments, `app` may be a small wrapper script that runs a prebuilt binary
(`app.bin`) with a compatible loader/library path. For clean open-source releases, reviewers
should build from source and treat binaries as generated artifacts (do not commit them).
