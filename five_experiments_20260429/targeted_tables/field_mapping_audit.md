# Targeted Table Field Mapping Audit

All HR-PCH values in this folder were regenerated from `hr_pch_sgx/app` in SGX hardware mode.

## Required implementation checks

- Expected HR-PCH version: `tee-rpch-v10-sgx-2od-split-full-reenc`.
- Required JSON flags: `sgx_mode=HW`, `tee_hk_decrypt=true`, `tee_transform2=true`, `tee_etd2_check=true`, `user_final_hash_check=true`.
- Server column for `CHET-2OA + ABE-2OD`: `times_ms.ServerAdapt`, whose code scope is `CHET-mu-plus-FAME-2OD-Transform1-only`.
- TEE column for `CHET-2OA + ABE-2OD`: `times_ms.InsiderAdapt(TEE)`, whose code scope is state verification, HK decryption, FAME-2OD Transform2, IBE share decryption, and ETD2 consistency checking.
- Modifier column for `CHET-2OA + ABE-2OD`: `times_ms.UserAdapt`, whose code scope is FAME-2OD final decryption, symmetric decryption of the user trapdoor share, RSA exponentiation, and final hash-check verification.
- TEE column for `CHET-OA + ABE-OD`: `times_ms.Baseline.OwnerAdapt` from the no-cloud baseline path.
- Modifier column for `CHET-OA + ABE-OD`: `times_ms.Baseline.UserAdapt` from the no-cloud baseline path.
- Hash-check comparison uses the newly measured `FullReEncUserAdapt` and `FullReEncUserAdapt.ReEncryptCheck` fields, not the older AES-only `LegacyUserAdapt` field.
- EHR-RPCH/TAR-PCH revocation values come from `rpch_bench` with `--mode revocation`; only these two server-assisted revocation schemes are included in Table 4.

## Important caveat

The strict full re-encryption comparison re-runs randomized FAME-2OD encryption and records its real cost. Exact ciphertext equality is not expected without storing or replaying encryption randomness, so the table uses timing values rather than a successful equality predicate.
