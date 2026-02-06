# SGX Dependency Bundle (Optional, Not Committed)

`hr_pch_sgx/` links **pbc** and **gmp** inside the SGX enclave.
On many systems you need enclave-friendly builds (static libs + headers) that are compatible with SGX.

This folder is a **convenience location**:

- `sgx_deps/include/`: headers (e.g., `pbc/pbc.h`, `gmp.h`, ...)
- `sgx_deps/lib/`: libraries (e.g., `libpbc.a`, `libgmp.a`, ...)

By default, `hr_pch_sgx/Makefile` looks for these paths:
- `../sgx_deps/include`
- `../sgx_deps/lib`

If you use a different layout, override in the build command:

```bash
make -C hr_pch_sgx SGX_DEPS_DIR=/path/to/your/sgx_deps
```

This directory is intentionally excluded from git (except this README).

