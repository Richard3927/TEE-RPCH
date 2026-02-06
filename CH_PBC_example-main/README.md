# CH_PBC_example — Pairing/RSA/ABE Helper Library

This directory provides the cryptographic helper code used by the TEE-RPCH artifact:

- `../hr_pch_sgx/`: SGX (TEE) prototype for TEE-RPCH
- `../rpch_bench/`: baseline benchmarks (XNM'21 / TMM'22)

## What Is Used By This Artifact

- **ABE (outsourced decryption)**: FAME-OD / OFAME (single-layer outsourcing)
- **Pairing curves**: MNT224 and A1 (ss1024 parameter set)
- **RSA utilities**: big-number arithmetic via OpenSSL

The entry points are the headers under `include/` and implementations under `src/`.

## Build Notes

You typically build this library indirectly via the parent projects:
- `../hr_pch_sgx/Makefile`
- `../rpch_bench/Makefile`

System dependencies (headers + libs) usually include:
- PBC (`pbc/pbc.h`)
- GMP (`gmp.h`)
- OpenSSL

## Other Schemes (Legacy)

This repository also contains implementations/notes for other chameleon-hash and (R)PCH variants.
They are not required to reproduce TEE-RPCH results. The historical index is kept in:
- `SCHEMES.md`

