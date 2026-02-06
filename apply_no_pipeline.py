#!/usr/bin/env python3
"""
Replace pipeline implementation with true parallel threading.
Replaces lines 1750-1981 in App.cpp with no-pipeline version.
"""

from pathlib import Path

def read_file_lines(path):
    with open(path, 'r', encoding='utf-8') as f:
        return f.readlines()

def write_file_lines(path, lines):
    with open(path, 'w', encoding='utf-8') as f:
        f.writelines(lines)

def main():
    root = Path(__file__).resolve().parent
    app_cpp = str((root / "hr_pch_sgx" / "App" / "App.cpp").resolve())

    lines = read_file_lines(app_cpp)

    # Find start: "if (bench_mode == "hrpch") {"
    start_line = None
    for i, line in enumerate(lines):
        if i >= 1745 and 'if (bench_mode == "hrpch")' in line:
            start_line = i
            break

    if start_line is None:
        print("ERROR: Could not find start of hrpch block")
        return 1

    # Find end: "} else {" with "no-outsourcing baseline" comment nearby
    end_line = None
    for i in range(start_line + 10, min(len(lines), start_line + 250)):
        if '} else {' in lines[i]:
            # Check if "no-outsourcing" or "baseline" in following lines
            context = ''.join(lines[i:min(len(lines), i+6)])
            if 'No-outsourcing baseline' in context or 'outsourcing baseline' in context:
                end_line = i
                break

    if end_line is None:
        print("ERROR: Could not find end of hrpch block")
        return 1

    print(f"Found hrpch block: lines {start_line+1} to {end_line}")
    print(f"Will replace {end_line - start_line} lines")

    # New implementation - NO PIPELINE
    new_impl = '''        if (bench_mode == "hrpch") {
            // ========================================================================
            // TRUE PARALLEL THREADING - NO PIPELINE
            // Each worker thread completes full Server → TEE → User flow for each task
            // This shows the real overhead at threads=1 compared to baseline.
            // ========================================================================
            std::atomic<size_t> next_task{0};

            // Worker function: each thread does complete Server→TEE→User flow
            auto parallel_worker = [&]() {
                AES aes;  // Local AES instance for user stage

                for (;;) {
                    // Get next task atomically
                    const size_t idx_task = next_task.fetch_add(1);
                    if (idx_task >= static_cast<size_t>(bench_tasks)) {
                        break;
                    }

                    // Use per-thread context to avoid contention
                    const size_t ctx_idx = idx_task % ctxs.size();
                    auto& ctx = ctxs[ctx_idx];

                    bool task_ok = true;

                    // ================================================================
                    // STAGE 1: Server-side CHET + OABE transform
                    // ================================================================
                    try {
                        // Server-side CHET: compute μ
                        Hgsm_n_2(ctx.m_p, ctx.n1, ctx.n2, ctx.n1, ctx.h1_mp);
                        mpz_invert(ctx.inv_h1_mp, ctx.h1_mp, ctx.n1);
                        mpz_mul(ctx.mu1, ctx.h1, ctx.inv_h1_mp);
                        mpz_mod(ctx.mu1, ctx.mu1, ctx.n1);

                        Hgsm_n_2(ctx.m, ctx.n1, ctx.n2, ctx.n2, ctx.x2_mp);
                        Hgsm_n_2(ctx.m_p, ctx.n1, ctx.n2, ctx.n2, ctx.x2_p);
                        mpz_powm(ctx.y2, ctx.r2, ctx.e1, ctx.n2);
                        mpz_mul(ctx.y2, ctx.x2_mp, ctx.y2);
                        mpz_mod(ctx.y2, ctx.y2, ctx.n2);
                        mpz_invert(ctx.inv_x2_p, ctx.x2_p, ctx.n2);
                        mpz_mul(ctx.X, ctx.y2, ctx.inv_x2_p);
                        mpz_mod(ctx.X, ctx.X, ctx.n2);
                        mpz_powm(ctx.mu2_1, ctx.X, ctx.a1, ctx.n2);
                        mpz_powm(ctx.mu2_2, ctx.X, ctx.a2, ctx.n2);

                        // Server-side OABE transform
                        ctx.fame->Transform(&mpk_abe, &ctx.ct, &ctx.tk, &ctx.tc);
                    } catch (...) {
                        task_ok = false;
                    }

                    std::vector<uint8_t> mu1_bytes;
                    std::vector<uint8_t> mu21_bytes;
                    std::vector<uint8_t> mu22_bytes;

                    if (task_ok) {
                        try {
                            mu1_bytes = mpz_to_bytes(ctx.mu1);
                            mu21_bytes = mpz_to_bytes(ctx.mu2_1);
                            mu22_bytes = mpz_to_bytes(ctx.mu2_2);
                        } catch (...) {
                            task_ok = false;
                        }
                    }

                    // ================================================================
                    // STAGE 2: TEE insider-adapt (SERIALIZED with mutex for SGX safety)
                    // ================================================================
                    std::vector<uint8_t> r1p_buf(512);
                    std::vector<uint8_t> pi_buf(512);
                    uint32_t r1p_len = 0;
                    uint32_t pi_len = 0;

                    if (task_ok) {
                        // CRITICAL: SGX enclave calls MUST be serialized
                        // Static mutex serializes all TEE calls across threads
                        static std::mutex tee_mutex;
                        std::lock_guard<std::mutex> tee_lock(tee_mutex);

                        int local_ret = -1;
                        const sgx_status_t rc = ecall_hrpch_insider_adapt(
                            eid,
                            &local_ret,
                            st0.t,
                            const_cast<uint8_t*>(st0.root_user.data()),
                            const_cast<uint8_t*>(st0.root_owner.data()),
                            const_cast<uint8_t*>(st0.sig_der.data()),
                            st0.sig_der.size(),
                            user_id.c_str(),
                            user_idx_u,
                            const_cast<uint8_t*>(user_tk_bytes.data()),
                            static_cast<uint32_t>(user_tk_bytes.size()),
                            const_cast<uint8_t*>(user_proof_ptr),
                            static_cast<uint32_t>(user_proof_bytes.size()),
                            owner_id.c_str(),
                            owner_idx_u,
                            const_cast<uint8_t*>(owner_enc_sk.data()),
                            static_cast<uint32_t>(owner_enc_sk.size()),
                            const_cast<uint8_t*>(owner_proof_ptr),
                            static_cast<uint32_t>(owner_proof_bytes.size()),
                            const_cast<uint8_t*>(n1_bytes.data()),
                            n1_bytes.size(),
                            const_cast<uint8_t*>(e1_bytes.data()),
                            e1_bytes.size(),
                            const_cast<uint8_t*>(n2_bytes.data()),
                            n2_bytes.size(),
                            const_cast<uint8_t*>(m_bytes.data()),
                            m_bytes.size(),
                            const_cast<uint8_t*>(mp_bytes.data()),
                            mp_bytes.size(),
                            const_cast<uint8_t*>(h1_bytes.data()),
                            h1_bytes.size(),
                            const_cast<uint8_t*>(mu1_bytes.data()),
                            static_cast<uint32_t>(mu1_bytes.size()),
                            const_cast<uint8_t*>(mu21_bytes.data()),
                            static_cast<uint32_t>(mu21_bytes.size()),
                            const_cast<uint8_t*>(mu22_bytes.data()),
                            static_cast<uint32_t>(mu22_bytes.size()),
                            const_cast<uint8_t*>(ibe_ct.data()),
                            static_cast<uint32_t>(ibe_ct.size()),
                            r1p_buf.data(),
                            static_cast<uint32_t>(r1p_buf.size()),
                            &r1p_len,
                            pi_buf.data(),
                            static_cast<uint32_t>(pi_buf.size()),
                            &pi_len);

                        if (rc != SGX_SUCCESS || local_ret != 0) {
                            task_ok = false;
                        } else {
                            r1p_buf.resize(r1p_len);
                            pi_buf.resize(pi_len);
                            if (r1p_buf.empty() || pi_buf.empty()) {
                                task_ok = false;
                            }
                        }
                    }

                    // ================================================================
                    // STAGE 3: User-side final decryption and verification
                    // ================================================================
                    if (task_ok) {
                        try {
                            mpz_from_bytes(ctx.r1_p, r1p_buf.data(), r1p_buf.size());
                            mpz_from_bytes(ctx.pi_mpz, pi_buf.data(), pi_buf.size());

                            // OABE decrypt (expensive!)
                            ctx.fame->Decrypt(&mpk_abe, &ctx.tc, &ctx.dk, &ctx.K_rec);

                            // AES decrypt
                            aes.Dec(&ctx.K_rec, &ctx.ct_usr, &ctx.d_dec_rec);

                            // Final RSA exponentiation
                            mpz_powm(ctx.r2_p, ctx.pi_mpz, ctx.d_dec_rec, ctx.n2);

                            // Verify chameleon hash
                            task_ok = tpch_check(ctx.n1, ctx.e1, ctx.n2, ctx.m_p,
                                                ctx.h1, ctx.h2, ctx.r1_p, ctx.r2_p);
                        } catch (...) {
                            task_ok = false;
                        }
                    }

                    if (!task_ok) {
                        failures.fetch_add(1);
                    }
                }
            };

            // Launch worker threads
            std::vector<std::thread> workers;
            workers.reserve(effective_threads);
            for (size_t i = 0; i < effective_threads; i++) {
                workers.emplace_back(parallel_worker);
            }

            // Wait for all threads to complete
            for (auto& th : workers) {
                th.join();
            }
'''

    # Build new file
    new_lines = lines[:start_line] + [new_impl] + lines[end_line:]

    # Write back
    write_file_lines(app_cpp, new_lines)

    print(f"✅ Successfully replaced hrpch block")
    print(f"   Removed: {end_line - start_line} lines")
    print(f"   Added: {new_impl.count(chr(10))} lines")
    return 0

if __name__ == '__main__':
    import sys
    sys.exit(main())
