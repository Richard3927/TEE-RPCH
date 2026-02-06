# TEE-RPCH (Intel SGX) — Implementation

This repository contains the **implementation** and **Intel SGX (TEE) prototype** for **TEE-RPCH**
(hardware-assisted revocable policy-based chameleon hash for blockchain redaction).

Key properties of this artifact:
- The TEE component is implemented with **Intel SGX**.
- The policy enforcement uses **outsourced ABE decryption (FAME-OD / OFAME, single-layer outsourcing)**.
- Paper sources / figures / raw reports are intentionally **not** included in this public repository.

Note: Some folder names are legacy (e.g., `hr_pch_sgx/`); the scheme name is **TEE-RPCH**.

## Repository Layout

- `hr_pch_sgx/`: Intel SGX prototype (host app + enclave) for **TEE-RPCH**
- `rpch_bench/`: baseline benchmark tool for prior RPCH schemes (XNM'21 / TMM'22)
- `CH_PBC_example-main/`: crypto library used by both `hr_pch_sgx/` and `rpch_bench/`

## Re-run Experiments (Requires Intel SGX)

To regenerate JSON results by actually running the SGX prototype:

1) Install Intel SGX runtime (driver + PSW) and SGX SDK.
2) Install SGXSSL (OpenSSL-in-enclave) if you want to build the enclave with crypto inside.
3) Provide enclave-friendly `pbc`/`gmp` headers + static libs (see `sgx_deps/`).
4) Ensure SGX device nodes exist (HW mode):

```bash
ls -la /dev/sgx/enclave /dev/sgx/provision 2>/dev/null || true
```

Then:

```bash
# Put outputs under an untracked folder
mkdir -p out/mnt224 out/a1

# Build and run experiments (MNT224)
python3 run_curve_experiments.py --curve mnt224 --out-dir out/mnt224 --build --force

# Build and run experiments (A1 / ss1024)
python3 run_curve_experiments.py --curve a1 --out-dir out/a1 --build --force
```

## Notes For Public Review

- **No double outsourcing**: this project uses **FAME-OD / OFAME (single-layer outsourcing)**; there is no FAME-2OD design here.
- **SGX HW vs SIM**: performance claims must be measured on **HW mode**; SIM is only for functional debugging.

## License

See `LICENSE`.
