# TEE-RPCH (Intel SGX) Implementation

This repository contains the implementation and Intel SGX (TEE) prototype for **TEE-RPCH**
(hardware-assisted revocable policy-based chameleon hash for blockchain redaction).

Key properties of this artifact:
- The TEE component is implemented with **Intel SGX**.
- The repository contains the public prototype, benchmark code, and reproducibility scripts for **TEE-RPCH**.
- Paper sources, figures, and private drafting materials are intentionally not included in this public repository.

Note: Some folder names are legacy (for example, `hr_pch_sgx/`); the scheme name is **TEE-RPCH**.

## Repository Layout

- `hr_pch_sgx/`: Intel SGX prototype (host app + enclave) for **TEE-RPCH**
- `rpch_bench/`: baseline benchmark tool for prior RPCH schemes (XNM'21 / TMM'22)
- `CH_PBC_example-main/`: crypto library used by both `hr_pch_sgx/` and `rpch_bench/`

## Re-run Experiments (Requires Intel SGX)

To regenerate JSON results by actually running the SGX prototype:

1. Install Intel SGX runtime (driver + PSW) and SGX SDK.
2. Install SGXSSL if you want to build the enclave with in-enclave crypto.
3. Provide enclave-friendly `pbc`/`gmp` headers and static libs (see `sgx_deps/`).
4. Ensure SGX device nodes exist in HW mode:

```bash
ls -la /dev/sgx/enclave /dev/sgx/provision 2>/dev/null || true
```

Then run:

```bash
mkdir -p out/mnt224 out/a1

python3 run_curve_experiments.py --curve mnt224 --out-dir out/mnt224 --build --force
python3 run_curve_experiments.py --curve a1 --out-dir out/a1 --build --force
```

## Notes For Public Review

- Performance claims should be measured in **SGX HW mode**.
- **SIM mode** is intended only for functional debugging.

## License

See `LICENSE`.
