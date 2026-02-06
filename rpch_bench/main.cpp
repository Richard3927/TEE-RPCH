#include <scheme/PCH_DSS_2019.h>
#include <scheme/RPCH_TMM_2022.h>
#include <scheme/RPCH_XNM_2021.h>

#include <curve/params.h>
#include <pbc/pbc.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

static uint64_t now_us() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count());
}

static const char* kBenchVersion = "dlo-pch-v2";

// Type A parameters whose target size roughly matches the MNT224 GT field size
// (q^2 ~ 1340 bits) while keeping |r| ≈ 224 bits, for fair curve comparisons.
static const char kTypeA_MatchMNT224[] =
    "type a\n"
    "q 17766997032643197491046606944190905774051190620006706915460055046138442399897523902114896912007863886941424946913235397726710002627363672764129867099692660030872615227193606101386160344094161837653380711\n"
    "h 659014546727253126099258596647467033612527390198793135375504282663445307024319858867227512246280204015635703803863849910726199405209704\n"
    "r 26959946667150639794667015087019630673637144422540572481103610249153\n"
    "exp2 224\n"
    "exp1 6\n"
    "sign1 -1\n"
    "sign0 1\n";

static std::string curve_param_from_name(const std::string& curve, const CurveParams& curves) {
    if (curve == "a") return curves.a_param;
    if (curve == "a672" || curve == "typea-mnt224") return std::string(kTypeA_MatchMNT224);
    if (curve == "a1") return curves.a1_param;
    if (curve == "e") return curves.e_param;
    if (curve == "i") return curves.i_param;
    if (curve == "f") return curves.f_param;
    if (curve == "d224" || curve == "mnt224") return curves.d224_param;
    throw std::runtime_error("unknown curve");
}

static std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '\"': out += "\\\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out += c; break;
        }
    }
    return out;
}

static size_t mpz_bytes(const mpz_t v) {
    return (mpz_sizeinbase(v, 2) + 7) / 8;
}

static size_t element_bytes(const element_s* e) {
    return static_cast<size_t>(element_length_in_bytes(const_cast<element_s*>(e)));
}

static std::vector<std::string> make_attr_list(int count) {
    std::vector<std::string> out;
    out.reserve(count > 0 ? static_cast<size_t>(count) : 0);
    for (int i = 1; i <= count; i++) {
        out.push_back("A" + std::to_string(i));
    }
    return out;
}

static std::string make_policy(const std::vector<std::string>& attrs, int policy_attrs) {
    if (policy_attrs <= 0) return "";
    if (static_cast<size_t>(policy_attrs) > attrs.size()) policy_attrs = static_cast<int>(attrs.size());
    std::vector<std::string> parts;
    for (int i = 0; i < policy_attrs; i += 2) {
        if (i + 1 < policy_attrs) {
            parts.push_back("(" + attrs[static_cast<size_t>(i)] + "|" + attrs[static_cast<size_t>(i + 1)] + ")");
        } else {
            parts.push_back("(" + attrs[static_cast<size_t>(i)] + ")");
        }
    }
    std::string p;
    for (size_t i = 0; i < parts.size(); i++) {
        if (i != 0) p += "&";
        p += parts[i];
    }
    return p;
}

static size_t rabe_cipher_bytes(const RABE::ciphertext& ct) {
    size_t total = 0;
    total += element_bytes(ct.ct0.ct0_1) + element_bytes(ct.ct0.ct0_2) + element_bytes(ct.ct0.ct0_3) + element_bytes(ct.ct0.ct0_4);
    total += element_bytes(ct.ct_prime);
    for (const auto* c : ct.ct_y) {
        total += element_bytes(c->ct_1) + element_bytes(c->ct_2) + element_bytes(c->ct_3);
    }
    return total;
}

static size_t rabe_tmm_cipher_bytes(const RABE_TMM::ciphertext& ct) {
    size_t total = 0;
    total += element_bytes(ct.ct0.ct0_1) + element_bytes(ct.ct0.ct0_2) + element_bytes(ct.ct0.ct0_3) + element_bytes(ct.ct0.ct0_4);
    total += element_bytes(ct.ct_prime);
    for (const auto* c : ct.ct_y) {
        total += element_bytes(c->ct_1) + element_bytes(c->ct_2) + element_bytes(c->ct_3);
    }
    return total;
}

static size_t cpabe_cipher_bytes(const CP_ABE::ciphertext& ct) {
    size_t total = 0;
    total += element_bytes(ct.ct0.ct_1) + element_bytes(ct.ct0.ct_2) + element_bytes(ct.ct0.ct_3);
    total += element_bytes(ct.ct_prime);
    for (const auto* c : ct.ct_y) {
        total += element_bytes(c->ct_1) + element_bytes(c->ct_2) + element_bytes(c->ct_3);
    }
    return total;
}

struct SchemeResult {
    std::map<std::string, double> times_ms;
    std::map<std::string, size_t> sizes_bytes;
};

static SchemeResult bench_pch_dss(
    int k,
    const std::vector<std::string>& attrs,
    int policy_attrs,
    const std::string& curve,
    bool run_ops) {
    SchemeResult res;

    CurveParams curves;
    std::string param = curve_param_from_name(curve, curves);

    pbc_param_t par;
    pairing_t pairing;
    pbc_param_init_set_str(par, param.c_str());
    pairing_init_pbc_param(pairing, par);

    {
        element_t G1, G2, GT, Zp;
        element_init_G1(G1, pairing);
        element_init_G2(G2, pairing);
        element_init_GT(GT, pairing);
        element_init_Zr(Zp, pairing);

        mpz_t n, e, d;
        mpz_inits(n, e, d, nullptr);

        PCH_DSS_2019::skPCH sk;
        PCH_DSS_2019::pkPCH pk;
        PCH_DSS_2019::sksPCH sks;
        sk.Init(&G1, &G2, &Zp);
        pk.Init(&G2, &GT);
        sks.Init(&G1, &G2, static_cast<int>(attrs.size()));

        PCH_DSS_2019 scheme(&n, &e, &d, &G1, &G2, &Zp, &GT);

        // PG
        {
            const uint64_t ts = now_us();
            scheme.PG(k, &sk, &pk);
            const uint64_t te = now_us();
            res.times_ms["PG"] = (te - ts) / 1000.0;
        }
        // KG
        {
            const uint64_t ts = now_us();
            scheme.KG(&sk, &pk, const_cast<std::vector<std::string>*>(&attrs), &sks);
            const uint64_t te = now_us();
            res.times_ms["KG"] = (te - ts) / 1000.0;
        }

        if (run_ops) {
            const std::string policy = make_policy(attrs, policy_attrs);
            PCH_DSS_2019::h h;
            PCH_DSS_2019::r r, r_p;
            h.Init(&G1, &G2, &GT, policy_attrs);
            r.Init();
            r_p.Init();

            mpz_t m, m_p;
            mpz_inits(m, m_p, nullptr);
            GenerateRandomWithLength(m, 128);
            GenerateRandomWithLength(m_p, 128);

            // Hash
            {
                const uint64_t ts = now_us();
                scheme.Hash(&pk, &m, policy, &h, &r);
                const uint64_t te = now_us();
                res.times_ms["Hash"] = (te - ts) / 1000.0;
            }
            // Forge
            {
                const uint64_t ts = now_us();
                scheme.Forge(&pk, &sks, &m, &m_p, &h, &r, &r_p);
                const uint64_t te = now_us();
                res.times_ms["Forge"] = (te - ts) / 1000.0;
            }

            const bool ok = scheme.Verify(&pk, &m_p, &h, &r_p);
            res.sizes_bytes["verify_ok"] = ok ? 1 : 0;

            // Size breakdown (hash / randomness / ciphertext)
            res.sizes_bytes["hash_bytes"] = mpz_bytes(h.h1) + mpz_bytes(h.h2) + mpz_bytes(h.N2);
            res.sizes_bytes["rand_bytes"] = mpz_bytes(r.r1) + mpz_bytes(r.r2);
            res.sizes_bytes["cipher_bytes"] = cpabe_cipher_bytes(h.ct) + mpz_bytes(h.ct_);

            mpz_clears(m, m_p, nullptr);
        }

        mpz_clears(n, e, d, nullptr);
        element_clear(G1);
        element_clear(G2);
        element_clear(GT);
        element_clear(Zp);
    }

    pairing_clear(pairing);
    pbc_param_clear(par);
    return res;
}

static SchemeResult bench_xnm(
    int k,
    int users_pow2,
    const std::vector<std::string>& attrs,
    int policy_attrs,
    const std::string& curve,
    bool run_ops) {
    SchemeResult res;

    CurveParams curves;
    std::string param = curve_param_from_name(curve, curves);

    pbc_param_t par;
    pairing_t pairing;
    pbc_param_init_set_str(par, param.c_str());
    pairing_init_pbc_param(pairing, par);

    {
        element_t G1, G2, GT, Zp;
        element_init_G1(G1, pairing);
        element_init_G2(G2, pairing);
        element_init_GT(GT, pairing);
        element_init_Zr(Zp, pairing);

        mpz_t n, e, d;
        mpz_inits(n, e, d, nullptr);

        RPCH_XNM_2021::skRPCH sk;
        RPCH_XNM_2021::pkRPCH pk;
        RPCH_XNM_2021::skidRPCH skid;
        RPCH_XNM_2021::dkidtRPCH dkidt;
        RABE::kut kut;
        std::vector<RABE::revokedPreson*> rl;
        binary_tree_RABE* st = nullptr;
        element_t id;
        element_init_same_as(id, Zp);

        sk.Init(&G1, &G2, &Zp);
        pk.Init(&G2, &GT);
        skid.Init(&G1, &G2, static_cast<int>(attrs.size()));
        dkidt.Init(&G1, &G2, static_cast<int>(attrs.size()));

        RPCH_XNM_2021 scheme(&n, &e, &d, &G1, &G2, &Zp, &GT);

        // PG
        {
            const uint64_t ts = now_us();
            scheme.PG(k, users_pow2, &sk, &pk, &rl, st);
            const uint64_t te = now_us();
            res.times_ms["PG"] = (te - ts) / 1000.0;
        }
        // KG
        {
            const uint64_t ts = now_us();
            scheme.KG(&pk, &sk, st, &id, const_cast<std::vector<std::string>*>(&attrs), &skid);
            const uint64_t te = now_us();
            res.times_ms["KG"] = (te - ts) / 1000.0;
        }
        // Rev (schedule revoke at 2025)
        const time_t t_rev = TimeCast(2025, 12, 31, 0, 0, 0);
        {
            const uint64_t ts = now_us();
            scheme.Rev(&rl, &id, t_rev);
            const uint64_t te = now_us();
            res.times_ms["Rev"] = (te - ts) / 1000.0;
        }
        // valid time (matches upstream unit tests): revoked user not yet effective (leaf time is 2025)
        const time_t t_valid = TimeCast(2024, 12, 21, 0, 0, 0);
        {
            const uint64_t ts = now_us();
            scheme.KUpt(&pk, st, &rl, t_valid, &kut);
            const uint64_t te = now_us();
            res.times_ms["KUpt(valid)"] = (te - ts) / 1000.0;
            res.sizes_bytes["ku_theta_nodes(valid)"] = kut.ku_theta.size();
        }
        // revoked time: revocation becomes effective (used for revocation-scaling experiments)
        {
            RABE::kut kut_rev;
            const time_t t_revoked = TimeCast(2026, 1, 1, 0, 0, 0);
            const uint64_t ts = now_us();
            scheme.KUpt(&pk, st, &rl, t_revoked, &kut_rev);
            const uint64_t te = now_us();
            res.times_ms["KUpt(revoked)"] = (te - ts) / 1000.0;
            res.sizes_bytes["ku_theta_nodes(revoked)"] = kut_rev.ku_theta.size();
        }
        if (run_ops) {
            const std::string policy = make_policy(attrs, policy_attrs);
            RPCH_XNM_2021::h h;
            RPCH_XNM_2021::r r, r_p;
            h.Init(&G1, &G2, &GT, policy_attrs);
            r.Init();
            r_p.Init();

            mpz_t m, m_p;
            mpz_inits(m, m_p, nullptr);
            GenerateRandomWithLength(m, 128);
            GenerateRandomWithLength(m_p, 128);

            // DKGen
            {
                const uint64_t ts = now_us();
                scheme.DKGen(&pk, &skid, &kut, &dkidt);
                const uint64_t te = now_us();
                res.times_ms["DKGen"] = (te - ts) / 1000.0;
            }
            // Hash
            {
                const uint64_t ts = now_us();
                scheme.Hash(&pk, &m, policy, t_valid, &h, &r);
                const uint64_t te = now_us();
                res.times_ms["Hash"] = (te - ts) / 1000.0;
            }
            // Forge
            {
                const uint64_t ts = now_us();
                scheme.Forge(&pk, &dkidt, &m, &m_p, &h, &r, &r_p);
                const uint64_t te = now_us();
                res.times_ms["Forge"] = (te - ts) / 1000.0;
            }

            const bool ok = scheme.Verify(&pk, &m_p, &h, &r_p);
            res.sizes_bytes["verify_ok"] = ok ? 1 : 0;

            // Size breakdown (hash / randomness / ciphertext)
            res.sizes_bytes["hash_bytes"] = mpz_bytes(h.h1) + mpz_bytes(h.h2) + mpz_bytes(h.N2);
            res.sizes_bytes["rand_bytes"] = mpz_bytes(r.r1) + mpz_bytes(r.r2);
            res.sizes_bytes["cipher_bytes"] = rabe_cipher_bytes(h.ct) + mpz_bytes(h.cSE);

            mpz_clears(m, m_p, nullptr);
        }

        mpz_clears(n, e, d, nullptr);
        element_clear(id);
        element_clear(G1);
        element_clear(G2);
        element_clear(GT);
        element_clear(Zp);
    }

    pairing_clear(pairing);
    pbc_param_clear(par);
    return res;
}

static SchemeResult bench_tmm(
    int k,
    int users_pow2,
    const std::vector<std::string>& attrs,
    int policy_attrs,
    const std::string& curve,
    bool run_ops) {
    SchemeResult res;

    CurveParams curves;
    std::string param = curve_param_from_name(curve, curves);

    pbc_param_t par;
    pairing_t pairing;
    pbc_param_init_set_str(par, param.c_str());
    pairing_init_pbc_param(pairing, par);

    {
        element_t G1, G2, GT, Zp;
        element_init_G1(G1, pairing);
        element_init_G2(G2, pairing);
        element_init_GT(GT, pairing);
        element_init_Zr(Zp, pairing);

        mpz_t n, e, d;
        mpz_inits(n, e, d, nullptr);

        RPCH_TMM_2022::skRPCH sk;
        RPCH_TMM_2022::pkRPCH pk;
        RPCH_TMM_2022::skidRPCH skid;
        RPCH_TMM_2022::dkidtRPCH dkidt;
        RABE_TMM::kut kut;
        std::vector<RABE_TMM::revokedPreson*> rl;
        binary_tree_RABE* st = nullptr;
        element_t id;
        element_init_same_as(id, Zp);

        sk.Init(&G1, &G2, &Zp);
        pk.Init(&G1, &G2, &GT);
        skid.Init(&G1, &G2, &Zp, static_cast<int>(attrs.size()));
        dkidt.Init(&G1, &G2, &Zp, static_cast<int>(attrs.size()));

        RPCH_TMM_2022 scheme(&n, &e, &d, &G1, &G2, &Zp, &GT);

        // PG
        {
            const uint64_t ts = now_us();
            scheme.PG(k, users_pow2, &sk, &pk, &rl, st);
            const uint64_t te = now_us();
            res.times_ms["PG"] = (te - ts) / 1000.0;
        }
        // KG
        {
            const uint64_t ts = now_us();
            scheme.KG(&pk, &sk, st, &id, const_cast<std::vector<std::string>*>(&attrs), &skid);
            const uint64_t te = now_us();
            res.times_ms["KG"] = (te - ts) / 1000.0;
        }
        // Rev
        const time_t t_rev = TimeCast(2025, 12, 31, 0, 0, 0);
        {
            const uint64_t ts = now_us();
            scheme.Rev(&rl, &id, t_rev);
            const uint64_t te = now_us();
            res.times_ms["Rev"] = (te - ts) / 1000.0;
        }
        // valid time (matches upstream unit tests): revoked user not yet effective (leaf time is 2025)
        const time_t t_valid = TimeCast(2024, 12, 21, 0, 0, 0);
        {
            const uint64_t ts = now_us();
            scheme.KUpt(&pk, st, &rl, t_valid, &kut);
            const uint64_t te = now_us();
            res.times_ms["KUpt(valid)"] = (te - ts) / 1000.0;
            res.sizes_bytes["ku_theta_nodes(valid)"] = kut.ku_theta.size();
        }
        // revoked time: revocation becomes effective (used for revocation-scaling experiments)
        {
            RABE_TMM::kut kut_rev;
            const time_t t_revoked = TimeCast(2026, 1, 1, 0, 0, 0);
            const uint64_t ts = now_us();
            scheme.KUpt(&pk, st, &rl, t_revoked, &kut_rev);
            const uint64_t te = now_us();
            res.times_ms["KUpt(revoked)"] = (te - ts) / 1000.0;
            res.sizes_bytes["ku_theta_nodes(revoked)"] = kut_rev.ku_theta.size();
        }
        if (run_ops) {
            const std::string policy = make_policy(attrs, policy_attrs);
            RABE_TMM::ciphertext C;
            C.Init(&G1, &G2, &Zp, policy_attrs);

            element_t m, m_p, b, h, r, r_p;
            element_init_same_as(m, Zp);
            element_init_same_as(m_p, Zp);
            element_init_same_as(b, G1);
            element_init_same_as(h, G1);
            element_init_same_as(r, Zp);
            element_init_same_as(r_p, Zp);
            element_random(m);
            element_random(m_p);

            // DKGen
            {
                const uint64_t ts = now_us();
                scheme.DKGen(&pk, &skid, &kut, &dkidt);
                const uint64_t te = now_us();
                res.times_ms["DKGen"] = (te - ts) / 1000.0;
            }
            // Hash
            {
                const uint64_t ts = now_us();
                scheme.Hash(&pk, &m, policy, t_valid, &b, &r, &h, &C);
                const uint64_t te = now_us();
                res.times_ms["Hash"] = (te - ts) / 1000.0;
            }
            // Forge
            {
                const uint64_t ts = now_us();
                scheme.Forge(&pk, &dkidt, &m, &m_p, &b, &r, &h, &C, &r_p);
                const uint64_t te = now_us();
                res.times_ms["Forge"] = (te - ts) / 1000.0;
            }

            const bool ok = scheme.Verify(&pk, &m_p, &b, &r_p, &h);
            res.sizes_bytes["verify_ok"] = ok ? 1 : 0;

            // Size breakdown (hash / randomness / ciphertext)
            res.sizes_bytes["hash_bytes"] = element_bytes(b) + element_bytes(h);
            res.sizes_bytes["rand_bytes"] = element_bytes(r);
            res.sizes_bytes["cipher_bytes"] = rabe_tmm_cipher_bytes(C);

            element_clear(m);
            element_clear(m_p);
            element_clear(b);
            element_clear(h);
            element_clear(r);
            element_clear(r_p);
        }

        mpz_clears(n, e, d, nullptr);
        element_clear(id);
        element_clear(G1);
        element_clear(G2);
        element_clear(GT);
        element_clear(Zp);
    }

    pairing_clear(pairing);
    pbc_param_clear(par);
    return res;
}

int main(int argc, char** argv) {
    std::string curve = "a";
    int users = 1024;
    int attr_count = 60;
    int policy_attrs = 20;
    std::string out_path = "artifacts/rpch.json";
    std::string mode = "all";
    int rsa_bits = 3072;

    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "--curve") == 0 && i + 1 < argc) {
            curve = argv[++i];
        } else if (std::strcmp(argv[i], "--users") == 0 && i + 1 < argc) {
            users = std::atoi(argv[++i]);
        } else if (std::strcmp(argv[i], "--attrs") == 0 && i + 1 < argc) {
            attr_count = std::atoi(argv[++i]);
        } else if (std::strcmp(argv[i], "--policy-attrs") == 0 && i + 1 < argc) {
            policy_attrs = std::atoi(argv[++i]);
        } else if (std::strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            out_path = argv[++i];
        } else if (std::strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            mode = argv[++i];
        } else if (std::strcmp(argv[i], "--rsa-bits") == 0 && i + 1 < argc) {
            rsa_bits = std::atoi(argv[++i]);
        }
    }

    if (users < 2 || (users & (users - 1)) != 0) {
        std::fprintf(stderr, "--users must be power of two and >= 2\n");
        return 1;
    }
    if (attr_count < 1) attr_count = 1;
    if (policy_attrs < 1) policy_attrs = 1;
    if (policy_attrs > attr_count) policy_attrs = attr_count;

    std::system("mkdir -p artifacts");

    const int k = rsa_bits;
    const auto attrs = make_attr_list(attr_count);
    const bool run_ops = (mode != "revocation");

    SchemeResult pch;
    SchemeResult xnm;
    SchemeResult tmm;
    try {
        pch = bench_pch_dss(k, attrs, policy_attrs, curve, run_ops);
        xnm = bench_xnm(k, users, attrs, policy_attrs, curve, run_ops);
        tmm = bench_tmm(k, users, attrs, policy_attrs, curve, run_ops);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "bench failed: %s\n", e.what());
        return 2;
    }

    std::ostringstream js;
    js << "{\n";
    js << "  \"params\": {\n";
    js << "    \"curve\": \"" << json_escape(curve) << "\",\n";
    js << "    \"bench_version\": \"" << kBenchVersion << "\",\n";
    js << "    \"rsa_bits\": " << rsa_bits << ",\n";
    js << "    \"users\": " << users << ",\n";
    js << "    \"attrs\": " << attr_count << ",\n";
    js << "    \"policy_attrs\": " << policy_attrs << "\n";
    js << "  },\n";
    js << "  \"schemes\": {\n";
    auto emit_scheme = [&](const char* name, const SchemeResult& r, bool last) {
        js << "    \"" << name << "\": {\n";
        js << "      \"times_ms\": {\n";
        {
            bool first = true;
            for (const auto& kv : r.times_ms) {
                if (!first) js << ",\n";
                first = false;
                js << "        \"" << json_escape(kv.first) << "\": " << kv.second;
            }
            js << "\n";
        }
        js << "      },\n";
        js << "      \"sizes_bytes\": {\n";
        {
            bool first = true;
            for (const auto& kv : r.sizes_bytes) {
                if (!first) js << ",\n";
                first = false;
                js << "        \"" << json_escape(kv.first) << "\": " << kv.second;
            }
            js << "\n";
        }
        js << "      }\n";
        js << "    }" << (last ? "\n" : ",\n");
    };
    emit_scheme("PCH_DSS_2019", pch, false);
    emit_scheme("RPCH_XNM_2021", xnm, false);
    emit_scheme("RPCH_TMM_2022", tmm, true);
    js << "  }\n";
    js << "}\n";

    {
        std::ofstream out(out_path, std::ios::binary);
        out << js.str();
    }

    return 0;
}
