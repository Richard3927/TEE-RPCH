# Experiment Entry Points

The experiment scripts are split by the question they answer.

- `exp0_basic_construction.py`: runs one full TEE-RPCH workflow and writes a single JSON report.
- `exp1_outsource_vs_no_outsource.py`: compares the outsourced TEE-RPCH path with the no-outsource path.
- `exp2_multithread_scaling.py`: measures server-side thread scaling for the outsourced path.
- `exp3_hashcheck_efficiency.py`: regenerates the targeted hash-check comparison and revocation tables.
- `exp4_revocation_benchmark.py`: runs TEE-RPCH, EHR-RPCH, and TAR-PCH revocation measurements.
- `run_all.py`: runs the organized suite except the targeted table/PDF builder.

Use `--build` on the first run if `hr_pch_sgx/app` or `rpch_bench/rpch_bench` has not been built.
