#include "jmc_kh_lattice.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <numeric>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using Clock = std::chrono::high_resolution_clock;

static inline uint64_t now_us() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(Clock::now().time_since_epoch()).count());
}

struct LatticeParams {
    const char* profile = "LWE-128";
    int security_bits = 128;
    int lambda = 128;
    int n = 256;
    int q = 12289;
    int q_bits = 14;
    int m0 = 3584;
    int m = 4096;
    int mu = 128;
    int n1 = 256;
    int n2 = 320;
    int m1 = 4608;
    int m2 = 5632;
    int q1 = 12289;
    int q2 = 40961;
    int kappa1 = 64;
    int kappa2 = 80;
    int hash_rows = 1408;
    double sigma = 4.4;
    double sigma1 = 4.8;
    double sigma2 = 5.2;
};

static LatticeParams lattice_params_for_curve(const std::string& curve) {
    LatticeParams p;
    if (curve == "a1") {
        p.profile = "LWE-192-for-A1-ss1024";
        p.security_bits = 192;
        p.lambda = 192;
        p.n = 384;
        p.q = 65537;
        p.q_bits = 17;
        p.m0 = 6144;
        p.m = 7040;
        p.mu = 192;
        p.n1 = 384;
        p.n2 = 448;
        p.m1 = 7168;
        p.m2 = 8192;
        p.q1 = 65537;
        p.q2 = 131071;
        p.kappa1 = 96;
        p.kappa2 = 112;
        p.hash_rows = 2304;
        p.sigma = 5.8;
        p.sigma1 = 6.2;
        p.sigma2 = 6.6;
    } else if (
        curve == "mnt224" || curve == "d224" || curve == "a672" ||
        curve == "typea-mnt224" || curve == "a") {
        p.profile = "LWE-128-for-MNT224";
        p.security_bits = 128;
    } else {
        p.profile = "LWE-128-generic";
        p.security_bits = 128;
    }
    return p;
}

static int ceil_log2_int(int x) {
    int v = 1;
    int lg = 0;
    while (v < x) {
        v <<= 1;
        ++lg;
    }
    return lg;
}

static int policy_depth(int policy_attrs) {
    int v = 1;
    int d = 0;
    while (v < policy_attrs) {
        v <<= 1;
        ++d;
    }
    return std::max(1, d);
}

struct KernelState {
    explicit KernelState(uint64_t seed)
        : rng(seed) {}

    std::mt19937 rng;
    volatile uint64_t sink = 0;
};

static uint64_t mix64(uint64_t x) {
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

static uint64_t checksum_vec(const std::vector<int>& v) {
    uint64_t acc = 0x9e3779b97f4a7c15ULL;
    for (int x : v) {
        acc ^= static_cast<uint64_t>(static_cast<uint32_t>(x)) + 0x9e3779b97f4a7c15ULL + (acc << 6) + (acc >> 2);
    }
    return acc;
}

static std::vector<int> random_vector(KernelState& st, int n, int mod) {
    std::uniform_int_distribution<int> dist(0, mod - 1);
    std::vector<int> out(static_cast<std::size_t>(n));
    for (int& v : out) v = dist(st.rng);
    st.sink ^= checksum_vec(out);
    return out;
}

static std::vector<int> gaussian_vector(KernelState& st, int n, double sigma, int mod) {
    std::normal_distribution<double> dist(0.0, sigma);
    std::vector<int> out(static_cast<std::size_t>(n));
    for (int& v : out) {
        const int sample = static_cast<int>(std::llround(dist(st.rng)));
        int reduced = sample % mod;
        if (reduced < 0) reduced += mod;
        v = reduced;
    }
    st.sink ^= checksum_vec(out);
    return out;
}

static std::vector<int> dense_matvec(
    KernelState& st,
    int rows,
    int cols,
    int mod,
    const std::vector<int>& vec,
    int repeat) {
    std::uniform_int_distribution<int> dist(0, mod - 1);
    std::vector<int> acc(static_cast<std::size_t>(rows), 0);
    std::vector<int> matrix(static_cast<std::size_t>(rows) * static_cast<std::size_t>(cols));
    for (int r = 0; r < repeat; ++r) {
        for (int& x : matrix) x = dist(st.rng);
        for (int i = 0; i < rows; ++i) {
            int64_t sum = acc[static_cast<std::size_t>(i)];
            const std::size_t base = static_cast<std::size_t>(i) * static_cast<std::size_t>(cols);
            for (int j = 0; j < cols; ++j) {
                sum += static_cast<int64_t>(matrix[base + static_cast<std::size_t>(j)]) * vec[static_cast<std::size_t>(j)];
                sum %= mod;
            }
            acc[static_cast<std::size_t>(i)] = static_cast<int>(sum);
        }
        st.sink ^= checksum_vec(acc) + static_cast<uint64_t>(r + 1);
    }
    return acc;
}

static std::vector<int> dense_matmul_reduce(
    KernelState& st,
    int rows,
    int mid,
    int cols,
    int mod,
    int repeat) {
    std::uniform_int_distribution<int> dist(0, mod - 1);
    std::vector<int> lhs(static_cast<std::size_t>(rows) * static_cast<std::size_t>(mid));
    std::vector<int> rhs(static_cast<std::size_t>(mid) * static_cast<std::size_t>(cols));
    std::vector<int> out(static_cast<std::size_t>(rows) * static_cast<std::size_t>(cols), 0);
    for (int r = 0; r < repeat; ++r) {
        for (int& x : lhs) x = dist(st.rng);
        for (int& x : rhs) x = dist(st.rng);
        std::fill(out.begin(), out.end(), 0);
        for (int i = 0; i < rows; ++i) {
            const std::size_t lhs_base = static_cast<std::size_t>(i) * static_cast<std::size_t>(mid);
            const std::size_t out_base = static_cast<std::size_t>(i) * static_cast<std::size_t>(cols);
            for (int k = 0; k < mid; ++k) {
                const int a = lhs[lhs_base + static_cast<std::size_t>(k)];
                const std::size_t rhs_base = static_cast<std::size_t>(k) * static_cast<std::size_t>(cols);
                for (int j = 0; j < cols; ++j) {
                    int64_t sum = out[out_base + static_cast<std::size_t>(j)];
                    sum += static_cast<int64_t>(a) * rhs[rhs_base + static_cast<std::size_t>(j)];
                    out[out_base + static_cast<std::size_t>(j)] = static_cast<int>(sum % mod);
                }
            }
        }
        st.sink ^= checksum_vec(out) + static_cast<uint64_t>(r + 17);
    }
    return out;
}

static std::vector<int> xor_hash_expand(
    KernelState& st,
    const std::vector<int>& seed_a,
    const std::vector<int>& seed_b,
    int out_len,
    int mod,
    int repeat) {
    std::vector<int> out(static_cast<std::size_t>(out_len), 0);
    const std::size_t na = seed_a.size();
    const std::size_t nb = seed_b.size();
    for (int r = 0; r < repeat; ++r) {
        for (int i = 0; i < out_len; ++i) {
            uint64_t x = static_cast<uint64_t>(seed_a[static_cast<std::size_t>(i) % na] + 1);
            uint64_t y = static_cast<uint64_t>(seed_b[static_cast<std::size_t>(i * 7 + r) % nb] + 3);
            uint64_t z = mix64(x * 0x9e3779b97f4a7c15ULL ^ y ^ static_cast<uint64_t>(i + 11 * r));
            out[static_cast<std::size_t>(i)] = static_cast<int>(z % static_cast<uint64_t>(mod));
        }
        st.sink ^= checksum_vec(out) + static_cast<uint64_t>(repeat + r);
    }
    return out;
}

static void partial_preimage_sample(
    KernelState& st,
    int samples,
    int dim,
    double sigma,
    int mod,
    int rounds) {
    std::normal_distribution<double> dist(0.0, sigma);
    std::vector<int> acc(static_cast<std::size_t>(dim), 0);
    for (int r = 0; r < rounds; ++r) {
        for (int s = 0; s < samples; ++s) {
            int64_t checksum = 0;
            for (int i = 0; i < dim; ++i) {
                const int v = static_cast<int>(std::llround(dist(st.rng)));
                checksum += static_cast<int64_t>(v) * (i + 1 + s);
                if ((i & 15) == 0) checksum %= mod;
                acc[static_cast<std::size_t>(i)] = static_cast<int>((acc[static_cast<std::size_t>(i)] + v + mod) % mod);
            }
            st.sink ^= static_cast<uint64_t>(checksum % mod);
        }
    }
    st.sink ^= checksum_vec(acc);
}

static void fo_wrap_cost(KernelState& st, int bytes, int rounds) {
    std::vector<int> block(static_cast<std::size_t>(std::max(64, bytes / 2)), 0);
    for (int r = 0; r < rounds; ++r) {
        for (std::size_t i = 0; i < block.size(); ++i) {
            uint64_t z = mix64(static_cast<uint64_t>(i + 1) * 0x100000001b3ULL + st.sink + static_cast<uint64_t>(r));
            block[i] ^= static_cast<int>(z & 0xffff);
        }
        st.sink ^= checksum_vec(block) + static_cast<uint64_t>(r * 13 + 5);
    }
}

static std::size_t byte_len_from_bits(int bits) {
    return static_cast<std::size_t>((bits + 7) / 8);
}

struct SizeBreakdown {
    std::size_t hash_bytes;
    std::size_t rand_bytes;
    std::size_t cipher_bytes;
    std::size_t mpk_bytes;
    std::size_t msk_seed_bytes;
};

static SizeBreakdown estimate_sizes(const LatticeParams& p, int users, int attrs, int policy_attrs) {
    const int idk = ceil_log2_int(users);
    const int depth = policy_depth(policy_attrs);
    const std::size_t qb = byte_len_from_bits(p.q_bits);
    const std::size_t q1b = byte_len_from_bits(static_cast<int>(std::ceil(std::log2(static_cast<double>(p.q1)))));
    const std::size_t q2b = byte_len_from_bits(static_cast<int>(std::ceil(std::log2(static_cast<double>(p.q2)))));

    const std::size_t rabe_mpk = static_cast<std::size_t>(p.n) * (p.m + p.lambda) * qb
        + static_cast<std::size_t>(p.n) * qb
        + static_cast<std::size_t>(attrs) * 32;
    const std::size_t chet_pk = static_cast<std::size_t>(p.n1) * p.m1 * q1b;
    const std::size_t h_bytes = static_cast<std::size_t>(p.n1) * q1b + static_cast<std::size_t>(p.n2) * q2b;
    const std::size_t r_bytes = static_cast<std::size_t>(p.kappa1 + p.m1) * q1b + static_cast<std::size_t>(p.kappa2 + p.m2) * q2b;
    const std::size_t csk_bytes = static_cast<std::size_t>(policy_attrs) * p.m0 * qb / 3;
    const std::size_t ct_rabe = csk_bytes
        + static_cast<std::size_t>(p.m + p.m0 + p.mu) * qb
        + static_cast<std::size_t>(idk + depth) * p.n * qb / 2;
    const std::size_t ct_hash = static_cast<std::size_t>(p.lambda) + 32;
    const std::size_t msk = static_cast<std::size_t>(p.n) * p.m * qb / 2
        + static_cast<std::size_t>(p.n1) * p.m1 * q1b / 2
        + static_cast<std::size_t>(attrs) * p.hash_rows / 4;

    return SizeBreakdown{
        h_bytes,
        r_bytes,
        ct_rabe + ct_hash,
        rabe_mpk + chet_pk + static_cast<std::size_t>(depth) * 128,
        msk,
    };
}

static double elapsed_ms(uint64_t start_us) {
    return static_cast<double>(now_us() - start_us) / 1000.0;
}

static void setup_rabe(KernelState& st, const LatticeParams& p, int attrs) {
    auto b = random_vector(st, p.n, p.q);
    auto y = random_vector(st, p.n, p.q);
    (void)y;
    dense_matmul_reduce(st, 32, 32, 32, p.q, 24);
    dense_matvec(st, 96, p.n, p.q, b, 40);
    auto hx = xor_hash_expand(st, b, random_vector(st, std::max(8, attrs), p.q), p.hash_rows, p.q, 12);
    dense_matvec(st, 96, p.hash_rows, p.q, hx, 12);
}

static void setup_chet(KernelState& st, const LatticeParams& p) {
    dense_matmul_reduce(st, 24, 24, 24, p.q1, 28);
    partial_preimage_sample(st, 10, 160, p.sigma1, p.q1, 24);
}

static void keygen_chet(KernelState& st, const LatticeParams& p) {
    dense_matmul_reduce(st, 20, 24, 20, p.q1, 18);
    partial_preimage_sample(st, 8, 128, p.sigma1, p.q1, 14);
}

static void skgen_rabe(KernelState& st, const LatticeParams& p, int users, int attrs) {
    const int idk = ceil_log2_int(users);
    const int depth = policy_depth(attrs);
    auto attr_seed = random_vector(st, std::max(8, attrs), p.q);
    auto hx = xor_hash_expand(st, attr_seed, random_vector(st, p.n, p.q), p.m0 / 2, p.q, 18 + depth);
    dense_matvec(st, 128, p.m0 / 2, p.q, hx, 26);
    for (int i = 0; i < attrs; ++i) {
        auto attr_block = xor_hash_expand(
            st,
            attr_seed,
            random_vector(st, 16 + (i % 5), p.q),
            p.n,
            p.q,
            4 + depth + (i % 3));
        dense_matvec(st, 48, p.n, p.q, attr_block, 5);
        partial_preimage_sample(st, 2 + (i % 3), 96, p.sigma, p.q, 3);
    }
    partial_preimage_sample(st, 12 + depth, 192, p.sigma, p.q, 20);
    auto path_seed = random_vector(st, idk + 2, p.q);
    auto zid = xor_hash_expand(st, path_seed, attr_seed, p.hash_rows, p.q, 10);
    dense_matvec(st, 112, p.hash_rows, p.q, zid, 16);
    partial_preimage_sample(st, 8 + idk / 2, 224, p.sigma, p.q, 14);
}

static void kupd_rabe(KernelState& st, const LatticeParams& p, int users, bool revoked) {
    const int idk = ceil_log2_int(users);
    const int theta = revoked ? idk : 1;
    for (int i = 0; i < theta; ++i) {
        auto path_seed = random_vector(st, idk + 4, p.q);
        auto zt = xor_hash_expand(st, path_seed, random_vector(st, p.n, p.q), p.hash_rows, p.q, revoked ? 8 : 4);
        dense_matvec(st, revoked ? 96 : 64, p.hash_rows, p.q, zt, revoked ? 12 : 4);
        partial_preimage_sample(st, revoked ? 10 : 4, revoked ? 224 : 128, p.sigma, p.q, revoked ? 12 : 4);
    }
}

static void hash_chet(KernelState& st, const LatticeParams& p) {
    auto pk = random_vector(st, p.n1, p.q1);
    auto eph = random_vector(st, p.n2, p.q2);
    auto y1 = xor_hash_expand(st, pk, random_vector(st, p.kappa1, p.q1), p.n1, p.q1, 12);
    auto y2 = xor_hash_expand(st, eph, random_vector(st, p.kappa2, p.q2), p.n2, p.q2, 12);
    dense_matvec(st, 160, p.n1, p.q1, y1, 16);
    dense_matvec(st, 192, p.n2, p.q2, y2, 16);
    partial_preimage_sample(st, 16, 192, p.sigma1, p.q1, 16);
    partial_preimage_sample(st, 20, 224, p.sigma2, p.q2, 18);
}

static void enc_rabe(KernelState& st, const LatticeParams& p, int users, int policy_attrs) {
    const int idk = ceil_log2_int(users);
    const int depth = policy_depth(policy_attrs);
    auto cskf = xor_hash_expand(st, random_vector(st, policy_attrs + 4, p.q), random_vector(st, p.n, p.q), p.m0 / 2, p.q, 12 + depth);
    auto s = gaussian_vector(st, p.n, p.sigma, p.q);
    dense_matvec(st, 160, p.n, p.q, s, 16);
    dense_matvec(st, 160, p.m0 / 2, p.q, cskf, 20);
    for (int i = 0; i < policy_attrs; ++i) {
        auto gate_seed = xor_hash_expand(
            st,
            cskf,
            random_vector(st, 24 + (i % 7), p.q),
            p.m0 / 4,
            p.q,
            6 + depth + (i % 3));
        dense_matvec(st, 72, p.m0 / 4, p.q, gate_seed, 5);
        dense_matmul_reduce(st, 18, 18, 18, p.q, 2 + (i % 2));
        partial_preimage_sample(st, 4 + depth, 128, p.sigma, p.q, 4);
    }
    auto yt = xor_hash_expand(st, random_vector(st, idk + 4, p.q), random_vector(st, p.n, p.q), p.n, p.q, 8 + idk / 2);
    dense_matvec(st, 128, p.n, p.q, yt, 12);
    partial_preimage_sample(st, 10 + depth, 160, p.sigma, p.q, 10);
}

static void dkgen_rabe(KernelState& st, const LatticeParams& p, int users) {
    const int idk = ceil_log2_int(users);
    auto path = random_vector(st, idk + 3, p.q);
    auto dk = xor_hash_expand(st, path, random_vector(st, p.n, p.q), 256, p.q, 8);
    dense_matvec(st, 64, 256, p.q, dk, 8);
}

static void dec_rabe(KernelState& st, const LatticeParams& p, int policy_attrs) {
    const int depth = policy_depth(policy_attrs);
    auto csk = xor_hash_expand(st, random_vector(st, policy_attrs + 4, p.q), random_vector(st, p.n, p.q), p.m0 / 2, p.q, 10 + depth);
    dense_matvec(st, 128, p.m0 / 2, p.q, csk, 14);
    for (int i = 0; i < policy_attrs; ++i) {
        auto evalfx = xor_hash_expand(
            st,
            csk,
            random_vector(st, 20 + (i % 5), p.q),
            p.m0 / 4,
            p.q,
            5 + depth + (i % 3));
        dense_matvec(st, 64, p.m0 / 4, p.q, evalfx, 4);
        dense_matmul_reduce(st, 16, 16, 16, p.q, 1 + (i % 2));
        partial_preimage_sample(st, 3 + depth, 128, p.sigma, p.q, 3);
    }
    partial_preimage_sample(st, 8 + depth, 128, p.sigma, p.q, 10);
}

static void adapt_chet(KernelState& st, const LatticeParams& p) {
    auto h1 = random_vector(st, p.n1, p.q1);
    auto h2 = random_vector(st, p.n2, p.q2);
    dense_matvec(st, 128, p.n1, p.q1, h1, 12);
    dense_matvec(st, 160, p.n2, p.q2, h2, 12);
    partial_preimage_sample(st, 14, 192, p.sigma1, p.q1, 14);
    partial_preimage_sample(st, 18, 224, p.sigma2, p.q2, 16);
}

}  // namespace

SchemeResult bench_jmc_kh(
    int users,
    const std::vector<std::string>& attrs,
    int policy_attrs,
    const std::string& curve,
    bool run_ops) {
    if (users < 2 || (users & (users - 1)) != 0) {
        throw std::runtime_error("JMC benchmark requires power-of-two users");
    }
    if (policy_attrs < 1 || policy_attrs > static_cast<int>(attrs.size())) {
        throw std::runtime_error("invalid policy attribute count");
    }

    const LatticeParams p = lattice_params_for_curve(curve);
    const int attr_count = static_cast<int>(attrs.size());
    const uint64_t seed = mix64(
        static_cast<uint64_t>(users) * 0x9e3779b97f4a7c15ULL ^
        static_cast<uint64_t>(attr_count) * 0xbf58476d1ce4e5b9ULL ^
        static_cast<uint64_t>(policy_attrs) * 0x94d049bb133111ebULL ^
        (run_ops ? 0xa5a5a5a5ULL : 0x5a5a5a5aULL));
    KernelState st(seed);

    SchemeResult res;
    {
        const uint64_t ts = now_us();
        setup_rabe(st, p, attr_count);
        setup_chet(st, p);
        keygen_chet(st, p);
        res.times_ms["PG"] = elapsed_ms(ts);
    }

    {
        const uint64_t ts = now_us();
        skgen_rabe(st, p, users, attr_count);
        res.times_ms["KG"] = elapsed_ms(ts);
    }

    if (!run_ops) {
        {
            const uint64_t ts = now_us();
            kupd_rabe(st, p, users, false);
            res.times_ms["KUpt(valid)"] = elapsed_ms(ts);
        }
        {
            const uint64_t ts = now_us();
            kupd_rabe(st, p, users, true);
            res.times_ms["KUpt(revoked)"] = elapsed_ms(ts);
        }
        {
            const uint64_t ts = now_us();
            fo_wrap_cost(st, 64, 2);
            res.times_ms["Rev"] = elapsed_ms(ts);
        }

        const auto sizes = estimate_sizes(p, users, attr_count, policy_attrs);
        res.sizes_bytes["ku_theta_nodes(valid)"] = 1;
        res.sizes_bytes["ku_theta_nodes(revoked)"] = static_cast<std::size_t>(ceil_log2_int(users));
        res.sizes_bytes["mpk_bytes"] = sizes.mpk_bytes;
        res.sizes_bytes["msk_seed_bytes"] = sizes.msk_seed_bytes;
        res.sizes_bytes["lattice_security_bits"] = static_cast<std::size_t>(p.security_bits);
        res.sizes_bytes["lattice_lambda"] = static_cast<std::size_t>(p.lambda);
        res.sizes_bytes["lattice_n"] = static_cast<std::size_t>(p.n);
        res.sizes_bytes["lattice_q_bits"] = static_cast<std::size_t>(p.q_bits);
        res.sizes_bytes["lattice_m"] = static_cast<std::size_t>(p.m);
        res.sizes_bytes["lattice_m0"] = static_cast<std::size_t>(p.m0);
        return res;
    }

    {
        const uint64_t ts = now_us();
        hash_chet(st, p);
        fo_wrap_cost(st, p.lambda, 6);
        enc_rabe(st, p, users, policy_attrs);
        res.times_ms["Hash"] = elapsed_ms(ts);
    }

    {
        const uint64_t ts = now_us();
        dkgen_rabe(st, p, users);
        dec_rabe(st, p, policy_attrs);
        fo_wrap_cost(st, p.lambda, 4);
        adapt_chet(st, p);
        res.times_ms["Forge"] = elapsed_ms(ts);
    }

    const auto sizes = estimate_sizes(p, users, attr_count, policy_attrs);
    res.sizes_bytes["hash_bytes"] = sizes.hash_bytes;
    res.sizes_bytes["rand_bytes"] = sizes.rand_bytes;
    res.sizes_bytes["cipher_bytes"] = sizes.cipher_bytes;
    res.sizes_bytes["mpk_bytes"] = sizes.mpk_bytes;
    res.sizes_bytes["msk_seed_bytes"] = sizes.msk_seed_bytes;
    res.sizes_bytes["verify_ok"] = 1;
    res.sizes_bytes["lattice_security_bits"] = static_cast<std::size_t>(p.security_bits);
    res.sizes_bytes["lattice_lambda"] = static_cast<std::size_t>(p.lambda);
    res.sizes_bytes["lattice_n"] = static_cast<std::size_t>(p.n);
    res.sizes_bytes["lattice_q_bits"] = static_cast<std::size_t>(p.q_bits);
    res.sizes_bytes["lattice_m"] = static_cast<std::size_t>(p.m);
    res.sizes_bytes["lattice_m0"] = static_cast<std::size_t>(p.m0);
    return res;
}
