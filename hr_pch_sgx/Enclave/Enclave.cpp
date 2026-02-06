#include "Enclave_t.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

// SGX tlibc does not define FILE. libgmp/libpbc only use FILE in I/O-related declarations,
// which we never call inside the enclave, so we provide a minimal stub type to satisfy headers.
struct SGX_FILE;
typedef SGX_FILE FILE;
// Also, SGX libc++ headers intentionally avoid exposing std::FILE (see _LIBCPP_SGX_CONFIG),
// but libgmp uses `using std::FILE;` in C++ mode, so we provide the alias explicitly.
namespace std {
using ::FILE;
}
#include <pbc/pbc.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace {

void enclave_log(const char* msg) {
    ocall_print_string(msg);
}

struct OwnedBnCtx {
    BN_CTX* ctx = BN_CTX_new();
    ~OwnedBnCtx() { BN_CTX_free(ctx); }
};

struct OwnedBn {
    BIGNUM* bn = BN_new();
    ~OwnedBn() { BN_free(bn); }
};

struct OwnedEvpPkey {
    EVP_PKEY* pkey = nullptr;
    ~OwnedEvpPkey() { EVP_PKEY_free(pkey); }
};

struct OwnedEvpMdCtx {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    ~OwnedEvpMdCtx() { EVP_MD_CTX_free(ctx); }
};

struct OwnedEvpCipherCtx {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    ~OwnedEvpCipherCtx() { EVP_CIPHER_CTX_free(ctx); }
};

struct OwnedEcGroup {
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    ~OwnedEcGroup() { EC_GROUP_free(group); }
};

struct OwnedEcPoint {
    EC_POINT* point;
    explicit OwnedEcPoint(const EC_GROUP* group) : point(EC_POINT_new(group)) {}
    ~OwnedEcPoint() { EC_POINT_free(point); }
};

std::vector<uint8_t> bn_to_bytes(const BIGNUM* bn) {
    const int len = BN_num_bytes(bn);
    std::vector<uint8_t> out(len > 0 ? static_cast<size_t>(len) : 1);
    if (len > 0) {
        BN_bn2bin(bn, out.data());
    } else {
        out[0] = 0;
    }
    return out;
}

BIGNUM* bn_from_bytes(const uint8_t* buf, uint32_t len) {
    if (buf == nullptr || len == 0) {
        return BN_new();
    }
    return BN_bin2bn(buf, static_cast<int>(len), nullptr);
}

static uint32_t be_to_u32(const uint8_t in[4]) {
    return (static_cast<uint32_t>(in[0]) << 24) |
           (static_cast<uint32_t>(in[1]) << 16) |
           (static_cast<uint32_t>(in[2]) << 8) |
           (static_cast<uint32_t>(in[3]));
}

static bool parse_two_bn(const std::vector<uint8_t>& buf, BIGNUM* out1, BIGNUM* out2) {
    if (out1 == nullptr || out2 == nullptr) {
        return false;
    }
    if (buf.size() < 8) {
        return false;
    }
    const uint32_t len1 = be_to_u32(buf.data());
    const size_t off1 = 4;
    if (buf.size() < off1 + len1 + 4) {
        return false;
    }
    const uint32_t len2 = be_to_u32(buf.data() + off1 + len1);
    const size_t off2 = off1 + len1 + 4;
    if (buf.size() != off2 + len2) {
        return false;
    }
    if (len1 > 0) {
        BN_bin2bn(buf.data() + off1, static_cast<int>(len1), out1);
    } else {
        BN_zero(out1);
    }
    if (len2 > 0) {
        BN_bin2bn(buf.data() + off2, static_cast<int>(len2), out2);
    } else {
        BN_zero(out2);
    }
    return true;
}

static bool sha256_hash_mod_bn(
    const uint8_t* a,
    uint32_t a_len,
    const uint8_t* b,
    uint32_t b_len,
    const uint8_t* c,
    uint32_t c_len,
    const BIGNUM* mod,
    BIGNUM* out,
    BN_CTX* bn_ctx) {
    if (out == nullptr || mod == nullptr || bn_ctx == nullptr) {
        return false;
    }

    SHA256_CTX sha;
    SHA256_Init(&sha);
    if (a != nullptr && a_len > 0) SHA256_Update(&sha, a, a_len);
    if (b != nullptr && b_len > 0) SHA256_Update(&sha, b, b_len);
    if (c != nullptr && c_len > 0) SHA256_Update(&sha, c, c_len);

    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256_Final(digest, &sha);

    OwnedBn digest_bn;
    BN_bin2bn(digest, SHA256_DIGEST_LENGTH, digest_bn.bn);
    return BN_mod(out, digest_bn.bn, mod, bn_ctx) == 1;
}

static bool compute_mu_from_public(
    const BIGNUM* n1_bn,
    const BIGNUM* e1_bn,
    const BIGNUM* n2_bn,
    const uint8_t* m,
    uint32_t m_len,
    const uint8_t* m_p,
    uint32_t mp_len,
    const uint8_t* n1_bytes,
    uint32_t n1_len,
    const uint8_t* n2_bytes,
    uint32_t n2_len,
    const uint8_t* r2,
    uint32_t r2_len,
    const uint8_t* a,
    uint32_t a_len,
    BIGNUM* mu_out,
    BN_CTX* bn_ctx) {
    if (n1_bn == nullptr || e1_bn == nullptr || n2_bn == nullptr || mu_out == nullptr || bn_ctx == nullptr) {
        return false;
    }
    if (m == nullptr || m_len == 0 || m_p == nullptr || mp_len == 0) {
        return false;
    }
    if (n1_bytes == nullptr || n1_len == 0 || n2_bytes == nullptr || n2_len == 0) {
        return false;
    }
    if (r2 == nullptr || r2_len == 0 || a == nullptr || a_len == 0) {
        return false;
    }

    OwnedBn x2_m;
    OwnedBn x2_mp;
    if (!sha256_hash_mod_bn(m, m_len, n1_bytes, n1_len, n2_bytes, n2_len, n2_bn, x2_m.bn, bn_ctx)) {
        return false;
    }
    if (!sha256_hash_mod_bn(m_p, mp_len, n1_bytes, n1_len, n2_bytes, n2_len, n2_bn, x2_mp.bn, bn_ctx)) {
        return false;
    }

    OwnedBn r2_bn;
    r2_bn.bn = bn_from_bytes(r2, r2_len);
    if (r2_bn.bn == nullptr) {
        return false;
    }

    OwnedBn r2_pow_e;
    if (BN_mod_exp(r2_pow_e.bn, r2_bn.bn, e1_bn, n2_bn, bn_ctx) != 1) {
        return false;
    }

    OwnedBn y2;
    if (BN_mod_mul(y2.bn, x2_m.bn, r2_pow_e.bn, n2_bn, bn_ctx) != 1) {
        return false;
    }

    OwnedBn inv_x2_mp;
    if (BN_mod_inverse(inv_x2_mp.bn, x2_mp.bn, n2_bn, bn_ctx) == nullptr) {
        return false;
    }

    OwnedBn X;
    if (BN_mod_mul(X.bn, y2.bn, inv_x2_mp.bn, n2_bn, bn_ctx) != 1) {
        return false;
    }

    OwnedBn a_bn;
    a_bn.bn = bn_from_bytes(a, a_len);
    if (a_bn.bn == nullptr) {
        return false;
    }

    return BN_mod_exp(mu_out, X.bn, a_bn.bn, n2_bn, bn_ctx) == 1;
}

using Hash32 = std::array<uint8_t, 32>;

static void u64_to_be(uint64_t v, uint8_t out[8]) {
    out[0] = static_cast<uint8_t>((v >> 56) & 0xff);
    out[1] = static_cast<uint8_t>((v >> 48) & 0xff);
    out[2] = static_cast<uint8_t>((v >> 40) & 0xff);
    out[3] = static_cast<uint8_t>((v >> 32) & 0xff);
    out[4] = static_cast<uint8_t>((v >> 24) & 0xff);
    out[5] = static_cast<uint8_t>((v >> 16) & 0xff);
    out[6] = static_cast<uint8_t>((v >> 8) & 0xff);
    out[7] = static_cast<uint8_t>(v & 0xff);
}

static void u32_to_be(uint32_t v, uint8_t out[4]) {
    out[0] = static_cast<uint8_t>((v >> 24) & 0xff);
    out[1] = static_cast<uint8_t>((v >> 16) & 0xff);
    out[2] = static_cast<uint8_t>((v >> 8) & 0xff);
    out[3] = static_cast<uint8_t>(v & 0xff);
}

static Hash32 sha256_2(const uint8_t* a, size_t a_len, const uint8_t* b, size_t b_len) {
    Hash32 out{};
    SHA256_CTX sha;
    SHA256_Init(&sha);
    if (a != nullptr && a_len > 0) SHA256_Update(&sha, a, a_len);
    if (b != nullptr && b_len > 0) SHA256_Update(&sha, b, b_len);
    SHA256_Final(out.data(), &sha);
    return out;
}

static Hash32 sha256_concat(const Hash32& left, const Hash32& right) {
    return sha256_2(left.data(), left.size(), right.data(), right.size());
}

static bool merkle_verify(
    const Hash32& root,
    const Hash32& leaf,
    uint32_t index,
    const uint8_t* proof,
    uint32_t proof_len) {
    if (proof_len % 32 != 0) {
        return false;
    }
    Hash32 cur = leaf;
    const uint32_t depth = proof_len / 32;
    for (uint32_t i = 0; i < depth; i++) {
        Hash32 sibling{};
        std::memcpy(sibling.data(), proof + i * 32, 32);
        if ((index & 1U) == 0U) {
            cur = sha256_concat(cur, sibling);
        } else {
            cur = sha256_concat(sibling, cur);
        }
        index >>= 1U;
    }
    return cur == root;
}

static Hash32 hash_user_leaf(const char* user_id, const uint8_t* user_tk, uint32_t user_tk_len) {
    Hash32 out{};
    if (user_id == nullptr || (user_tk_len > 0 && user_tk == nullptr)) {
        return out;
    }
    const uint32_t id_len = static_cast<uint32_t>(std::strlen(user_id));
    uint8_t id_len_be[4];
    uint8_t tk_len_be[4];
    u32_to_be(id_len, id_len_be);
    u32_to_be(user_tk_len, tk_len_be);

    SHA256_CTX sha;
    SHA256_Init(&sha);
    const uint8_t domain = 0x01;
    SHA256_Update(&sha, &domain, 1);
    SHA256_Update(&sha, id_len_be, sizeof(id_len_be));
    if (id_len > 0) {
        SHA256_Update(&sha, reinterpret_cast<const uint8_t*>(user_id), id_len);
    }
    SHA256_Update(&sha, tk_len_be, sizeof(tk_len_be));
    if (user_tk_len > 0) {
        SHA256_Update(&sha, user_tk, user_tk_len);
    }
    SHA256_Final(out.data(), &sha);
    return out;
}

static Hash32 hash_owner_leaf(const char* owner_id, const uint8_t* owner_enc_sk, uint32_t owner_enc_sk_len) {
    Hash32 out{};
    if (owner_id == nullptr || owner_enc_sk == nullptr) {
        return out;
    }
    const uint32_t id_len = static_cast<uint32_t>(std::strlen(owner_id));
    uint8_t len_be[4];
    u32_to_be(id_len, len_be);

    SHA256_CTX sha;
    SHA256_Init(&sha);
    const uint8_t domain = 0x02;
    SHA256_Update(&sha, &domain, 1);
    SHA256_Update(&sha, len_be, sizeof(len_be));
    if (id_len > 0) {
        SHA256_Update(&sha, reinterpret_cast<const uint8_t*>(owner_id), id_len);
    }
    if (owner_enc_sk_len > 0) {
        SHA256_Update(&sha, owner_enc_sk, owner_enc_sk_len);
    }
    SHA256_Final(out.data(), &sha);
    return out;
}

static bool verify_state_sig(
    const EVP_PKEY* vk,
    uint64_t t,
    const uint8_t root_user[32],
    const uint8_t root_owner[32],
    const uint8_t* sig,
    uint32_t sig_len) {
    if (vk == nullptr || root_user == nullptr || root_owner == nullptr || sig == nullptr || sig_len == 0) {
        return false;
    }

    uint8_t msg[8 + 32 + 32];
    u64_to_be(t, msg);
    std::memcpy(msg + 8, root_user, 32);
    std::memcpy(msg + 8 + 32, root_owner, 32);

    OwnedEvpMdCtx md;
    if (EVP_DigestVerifyInit(md.ctx, nullptr, EVP_sha256(), nullptr, const_cast<EVP_PKEY*>(vk)) != 1) {
        return false;
    }
    if (EVP_DigestVerifyUpdate(md.ctx, msg, sizeof(msg)) != 1) {
        return false;
    }
    return EVP_DigestVerifyFinal(md.ctx, sig, sig_len) == 1;
}

static bool aes256_gcm_decrypt(
    const uint8_t key[32],
    const uint8_t* iv,
    uint32_t iv_len,
    const uint8_t* aad,
    uint32_t aad_len,
    const uint8_t* ciphertext,
    uint32_t ciphertext_len,
    const uint8_t* tag,
    uint32_t tag_len,
    std::vector<uint8_t>& plaintext_out) {
    if (iv == nullptr || ciphertext == nullptr || tag == nullptr) {
        return false;
    }
    if (tag_len != 16) {
        return false;
    }
    plaintext_out.assign(ciphertext_len, 0);

    OwnedEvpCipherCtx c;
    if (EVP_DecryptInit_ex(c.ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        return false;
    }
    if (EVP_CIPHER_CTX_ctrl(c.ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, nullptr) != 1) {
        return false;
    }
    if (EVP_DecryptInit_ex(c.ctx, nullptr, nullptr, key, iv) != 1) {
        return false;
    }

    int out_len = 0;
    if (aad != nullptr && aad_len > 0) {
        if (EVP_DecryptUpdate(c.ctx, nullptr, &out_len, aad, aad_len) != 1) {
            return false;
        }
    }

    int pt_len = 0;
    if (EVP_DecryptUpdate(c.ctx, plaintext_out.data(), &out_len, ciphertext, ciphertext_len) != 1) {
        return false;
    }
    pt_len += out_len;

    if (EVP_CIPHER_CTX_ctrl(c.ctx, EVP_CTRL_GCM_SET_TAG, tag_len, const_cast<uint8_t*>(tag)) != 1) {
        return false;
    }

    const int final_ok = EVP_DecryptFinal_ex(c.ctx, plaintext_out.data() + pt_len, &out_len);
    if (final_ok != 1) {
        return false;
    }
    pt_len += out_len;
    plaintext_out.resize(static_cast<size_t>(pt_len));
    return true;
}

static bool aes256_gcm_decrypt_packed(
    const uint8_t key[32],
    const uint8_t* aad,
    uint32_t aad_len,
    const uint8_t* in,
    uint32_t in_len,
    std::vector<uint8_t>& plaintext_out) {
    // pack: iv(12) | tag(16) | ct_len(u32 be) | ct(ct_len)
    if (in == nullptr || in_len < (12 + 16 + 4)) {
        return false;
    }
    const uint8_t* iv = in;
    const uint8_t* tag = in + 12;
    const uint8_t* ct_len_be = in + 12 + 16;
    const uint32_t ct_len = (static_cast<uint32_t>(ct_len_be[0]) << 24) |
                            (static_cast<uint32_t>(ct_len_be[1]) << 16) |
                            (static_cast<uint32_t>(ct_len_be[2]) << 8) |
                            (static_cast<uint32_t>(ct_len_be[3]));
    const uint32_t header_len = 12 + 16 + 4;
    if (header_len + ct_len != in_len) {
        return false;
    }
    const uint8_t* ciphertext = in + header_len;
    return aes256_gcm_decrypt(key, iv, 12, aad, aad_len, ciphertext, ct_len, tag, 16, plaintext_out);
}

// --------- Enclave global state ----------
std::vector<uint8_t> g_d1_bytes;
std::array<uint8_t, 32> g_ktee_key{};
bool g_has_ktee_key = false;
OwnedEvpPkey g_vk_sig;
std::atomic<uint64_t> g_t_tee{0};
bool g_has_ibe_pairing = false;
pbc_param_t g_ibe_par;
pairing_t g_ibe_pairing;

static bool bf_ibe_decrypt_packed(
    const uint8_t* id,
    uint32_t id_len,
    const std::vector<uint8_t>& sk_bytes,
    const uint8_t* ct,
    uint32_t ct_len,
    std::vector<uint8_t>& plaintext_out) {
    // Layout: u_len(u32 be) | U(u_len) | AESGCM(iv|tag|len|ct)
    if (!g_has_ibe_pairing) {
        enclave_log("Enclave: IBE pairing not initialized\n");
        return false;
    }
    if (ct == nullptr || ct_len < (4 + 12 + 16 + 4)) {
        return false;
    }
    if (id == nullptr) {
        id_len = 0;
    }
    const uint32_t u_len = be_to_u32(ct);
    const uint32_t header = 4;
    if (ct_len < header + u_len) {
        return false;
    }
    const uint8_t* u_bytes = ct + header;
    const uint8_t* payload = ct + header + u_len;
    const uint32_t payload_len = ct_len - header - u_len;

    element_t U;
    element_t d_id;
    element_t K;
    element_init_G2(U, g_ibe_pairing);
    element_init_G1(d_id, g_ibe_pairing);
    element_init_GT(K, g_ibe_pairing);

    const uint32_t exp_u_len = static_cast<uint32_t>(element_length_in_bytes(U));
    const uint32_t exp_sk_len = static_cast<uint32_t>(element_length_in_bytes(d_id));
    if (u_len != exp_u_len || sk_bytes.size() != exp_sk_len) {
        element_clear(K);
        element_clear(d_id);
        element_clear(U);
        return false;
    }

    element_from_bytes(U, const_cast<unsigned char*>(u_bytes));
    element_from_bytes(d_id, const_cast<unsigned char*>(sk_bytes.data()));
    pairing_apply(K, d_id, U, g_ibe_pairing);

    const size_t k_len = static_cast<size_t>(element_length_in_bytes(K));
    std::vector<uint8_t> k_bytes(k_len > 0 ? k_len : 1, 0);
    if (k_len > 0) {
        element_to_bytes(k_bytes.data(), K);
    }
    uint8_t key[32];
    SHA256(k_bytes.data(), k_bytes.size(), key);

    const bool ok = aes256_gcm_decrypt_packed(key, id, id_len, payload, payload_len, plaintext_out);
    element_clear(K);
    element_clear(d_id);
    element_clear(U);
    return ok;
}

} // namespace

int ecall_provision(
    uint8_t* d1,
    uint32_t d1_len,
    uint8_t* k_tee,
    uint32_t ktee_len,
    uint8_t* vk_sig_der,
    uint32_t vk_len,
    uint8_t* pbc_param,
    uint32_t pbc_param_len) {
    if (d1 == nullptr || d1_len == 0 || k_tee == nullptr || ktee_len != 32 || vk_sig_der == nullptr || vk_len == 0) {
        return -1;
    }
    if (pbc_param == nullptr || pbc_param_len == 0) {
        enclave_log("Enclave: missing PBC params\n");
        return -1;
    }

    g_d1_bytes.assign(d1, d1 + d1_len);
    std::memcpy(g_ktee_key.data(), k_tee, 32);
    g_has_ktee_key = true;

    const unsigned char* p = vk_sig_der;
    g_vk_sig.pkey = d2i_PUBKEY(nullptr, &p, vk_len);
    if (g_vk_sig.pkey == nullptr) {
        enclave_log("Enclave: load vk_sig failed\n");
        return -2;
    }

    // Initialize pairing for BF-IBE decryption inside the enclave.
    // The untrusted app passes the full PBC parameter string (including '\0').
    const char* param_str = reinterpret_cast<const char*>(pbc_param);
    if (param_str[pbc_param_len - 1] != '\0') {
        enclave_log("Enclave: PBC params must be NUL-terminated\n");
        return -3;
    }
    pbc_param_init_set_str(g_ibe_par, param_str);
    pairing_init_pbc_param(g_ibe_pairing, g_ibe_par);
    g_has_ibe_pairing = true;

    g_t_tee.store(0);
    return 0;
}

int ecall_hrpch_insider_adapt(
    uint64_t state_t,
    uint8_t* root_user,
    uint8_t* root_owner,
    uint8_t* state_sig_der,
    uint32_t sig_len,
    const char* user_id,
    uint32_t user_idx,
    uint8_t* user_tk,
    uint32_t user_tk_len,
    uint8_t* user_proof,
    uint32_t user_proof_len,
    const char* owner_id,
    uint32_t owner_idx,
    uint8_t* owner_enc_sk,
    uint32_t owner_enc_sk_len,
    uint8_t* owner_proof,
    uint32_t owner_proof_len,
    uint8_t* n1,
    uint32_t n1_len,
    uint8_t* e1,
    uint32_t e1_len,
    uint8_t* n2,
    uint32_t n2_len,
    uint8_t* m,
    uint32_t m_len,
    uint8_t* m_p,
    uint32_t mp_len,
    uint8_t* h1,
    uint32_t h1_len,
    uint8_t* mu1,
    uint32_t mu1_len,
    uint8_t* mu2_1,
    uint32_t mu2_1_len,
    uint8_t* mu2_2,
    uint32_t mu2_2_len,
    uint8_t* ibe_ct,
    uint32_t ibe_ct_len,
    uint8_t* r1p_buf,
    uint32_t r1p_buf_len,
    uint32_t* r1p_len,
    uint8_t* pi_buf,
    uint32_t pi_buf_len,
    uint32_t* pi_len) {
    if (r1p_len == nullptr || pi_len == nullptr) {
        return -1;
    }
    *r1p_len = 0;
    *pi_len = 0;

    if (g_d1_bytes.empty() || g_vk_sig.pkey == nullptr || !g_has_ktee_key) {
        enclave_log("Enclave: not provisioned\n");
        return -2;
    }

    if (root_user == nullptr || root_owner == nullptr || state_sig_der == nullptr || sig_len == 0) {
        return -3;
    }
    if (!verify_state_sig(g_vk_sig.pkey, state_t, root_user, root_owner, state_sig_der, sig_len)) {
        enclave_log("Enclave: state signature verify failed\n");
        return -4;
    }

    if (state_t < g_t_tee.load()) {
        enclave_log("Enclave: rollback detected\n");
        return -5;
    }
    g_t_tee.store(state_t);

    Hash32 root_u{};
    Hash32 root_o{};
    std::memcpy(root_u.data(), root_user, 32);
    std::memcpy(root_o.data(), root_owner, 32);

    if (user_id == nullptr || (user_tk_len > 0 && user_tk == nullptr) || (user_proof_len > 0 && user_proof == nullptr)) {
        return -6;
    }
    const Hash32 leaf_user = hash_user_leaf(user_id, user_tk, user_tk_len);
    if (!merkle_verify(root_u, leaf_user, user_idx, user_proof, user_proof_len)) {
        enclave_log("Enclave: user membership invalid\n");
        return -7;
    }

    if (owner_id == nullptr || owner_enc_sk == nullptr || (owner_proof_len > 0 && owner_proof == nullptr)) {
        return -8;
    }
    const Hash32 leaf_owner = hash_owner_leaf(owner_id, owner_enc_sk, owner_enc_sk_len);
    if (!merkle_verify(root_o, leaf_owner, owner_idx, owner_proof, owner_proof_len)) {
        enclave_log("Enclave: owner membership invalid\n");
        return -9;
    }

    std::vector<uint8_t> sk_bytes;
    const uint32_t owner_id_len = static_cast<uint32_t>(std::strlen(owner_id));
    if (!aes256_gcm_decrypt_packed(g_ktee_key.data(),
                                   reinterpret_cast<const uint8_t*>(owner_id),
                                   owner_id_len,
                                   owner_enc_sk,
                                   owner_enc_sk_len,
                                   sk_bytes)) {
        enclave_log("Enclave: owner sk decrypt failed\n");
        return -10;
    }

    OwnedBnCtx bn_ctx;
    if (bn_ctx.ctx == nullptr) {
        return -11;
    }

    OwnedBn bn_n1;
    bn_n1.bn = bn_from_bytes(n1, n1_len);
    OwnedBn bn_e1;
    bn_e1.bn = bn_from_bytes(e1, e1_len);
    OwnedBn bn_n2;
    bn_n2.bn = bn_from_bytes(n2, n2_len);

    if (bn_n1.bn == nullptr || bn_e1.bn == nullptr || bn_n2.bn == nullptr) {
        return -12;
    }

    // --- Decrypt b using BF-IBE (2001/090) + AES-GCM ---
    std::vector<uint8_t> b_bytes;
    if (!bf_ibe_decrypt_packed(
            reinterpret_cast<const uint8_t*>(owner_id),
            owner_id_len,
            sk_bytes,
            ibe_ct,
            ibe_ct_len,
            b_bytes)) {
        enclave_log("Enclave: IBE decrypt failed\n");
        return -13;
    }

    OwnedBn bn_b1;
    OwnedBn bn_b2;
    if (!parse_two_bn(b_bytes, bn_b1.bn, bn_b2.bn)) {
        enclave_log("Enclave: parse b1/b2 failed\n");
        return -24;
    }

    // --- pi = mu2_i^{b_i} mod N2 ---
    OwnedBn bn_mu21;
    bn_mu21.bn = bn_from_bytes(mu2_1, mu2_1_len);
    OwnedBn bn_mu22;
    bn_mu22.bn = bn_from_bytes(mu2_2, mu2_2_len);
    if (bn_mu21.bn == nullptr || bn_mu22.bn == nullptr) {
        return -25;
    }
    OwnedBn bn_pi1;
    OwnedBn bn_pi2;
    if (BN_mod_exp(bn_pi1.bn, bn_mu21.bn, bn_b1.bn, bn_n2.bn, bn_ctx.ctx) != 1) {
        enclave_log("Enclave: BN_mod_exp(pi1) failed\n");
        return -26;
    }
    if (BN_mod_exp(bn_pi2.bn, bn_mu22.bn, bn_b2.bn, bn_n2.bn, bn_ctx.ctx) != 1) {
        enclave_log("Enclave: BN_mod_exp(pi2) failed\n");
        return -27;
    }
    if (BN_cmp(bn_pi1.bn, bn_pi2.bn) != 0) {
        enclave_log("Enclave: pi mismatch\n");
        return -28;
    }

    // --- r1' computation ---
    OwnedBn bn_mu1;
    bn_mu1.bn = bn_from_bytes(mu1, mu1_len);
    if (bn_mu1.bn == nullptr) {
        return -29;
    }
    OwnedBn bn_d1;
    BN_bin2bn(g_d1_bytes.data(), static_cast<int>(g_d1_bytes.size()), bn_d1.bn);

    OwnedBn bn_r1p;
    if (BN_mod_exp(bn_r1p.bn, bn_mu1.bn, bn_d1.bn, bn_n1.bn, bn_ctx.ctx) != 1) {
        enclave_log("Enclave: BN_mod_exp(r1') failed\n");
        return -30;
    }

    // --- verify h1 ---
    OwnedBn bn_h1;
    bn_h1.bn = bn_from_bytes(h1, h1_len);
    OwnedBn h1_mp;
    if (!sha256_hash_mod_bn(m_p, mp_len, n1, n1_len, n2, n2_len, bn_n1.bn, h1_mp.bn, bn_ctx.ctx)) {
        enclave_log("Enclave: H1(m') failed\n");
        return -31;
    }
    OwnedBn r1p_pow_e;
    if (BN_mod_exp(r1p_pow_e.bn, bn_r1p.bn, bn_e1.bn, bn_n1.bn, bn_ctx.ctx) != 1) {
        enclave_log("Enclave: r1'^e mod N1 failed\n");
        return -32;
    }
    OwnedBn expected_h1;
    if (BN_mod_mul(expected_h1.bn, h1_mp.bn, r1p_pow_e.bn, bn_n1.bn, bn_ctx.ctx) != 1) {
        return -33;
    }
    if (BN_cmp(expected_h1.bn, bn_h1.bn) != 0) {
        enclave_log("Enclave: h1 check failed\n");
        return -34;
    }

    // outputs
    const auto r1p_bytes = bn_to_bytes(bn_r1p.bn);
    const auto pi_bytes = bn_to_bytes(bn_pi1.bn);

    if (r1p_bytes.size() > r1p_buf_len || pi_bytes.size() > pi_buf_len) {
        enclave_log("Enclave: output buffer too small\n");
        return -33;
    }
    std::memcpy(r1p_buf, r1p_bytes.data(), r1p_bytes.size());
    std::memcpy(pi_buf, pi_bytes.data(), pi_bytes.size());
    *r1p_len = static_cast<uint32_t>(r1p_bytes.size());
    *pi_len = static_cast<uint32_t>(pi_bytes.size());
    return 0;
}

int ecall_hrpch_insider_adapt_all_tee(
    uint64_t state_t,
    uint8_t* root_user,
    uint8_t* root_owner,
    uint8_t* state_sig_der,
    uint32_t sig_len,
    const char* user_id,
    uint32_t user_idx,
    uint8_t* user_tk,
    uint32_t user_tk_len,
    uint8_t* user_proof,
    uint32_t user_proof_len,
    const char* owner_id,
    uint32_t owner_idx,
    uint8_t* owner_enc_sk,
    uint32_t owner_enc_sk_len,
    uint8_t* owner_proof,
    uint32_t owner_proof_len,
    uint8_t* n1,
    uint32_t n1_len,
    uint8_t* e1,
    uint32_t e1_len,
    uint8_t* n2,
    uint32_t n2_len,
    uint8_t* m,
    uint32_t m_len,
    uint8_t* m_p,
    uint32_t mp_len,
    uint8_t* h1,
    uint32_t h1_len,
    uint8_t* r1,
    uint32_t r1_len,
    uint8_t* r2,
    uint32_t r2_len,
    uint8_t* a1,
    uint32_t a1_len,
    uint8_t* a2,
    uint32_t a2_len,
    uint8_t* ibe_ct,
    uint32_t ibe_ct_len,
    uint8_t* r1p_buf,
    uint32_t r1p_buf_len,
    uint32_t* r1p_len,
    uint8_t* pi_buf,
    uint32_t pi_buf_len,
    uint32_t* pi_len) {
    if (r1p_len == nullptr || pi_len == nullptr) {
        return -1;
    }
    *r1p_len = 0;
    *pi_len = 0;

    if (g_d1_bytes.empty() || g_vk_sig.pkey == nullptr || !g_has_ktee_key) {
        enclave_log("Enclave: not provisioned\n");
        return -2;
    }

    if (root_user == nullptr || root_owner == nullptr || state_sig_der == nullptr || sig_len == 0) {
        return -3;
    }
    if (!verify_state_sig(g_vk_sig.pkey, state_t, root_user, root_owner, state_sig_der, sig_len)) {
        enclave_log("Enclave: state signature verify failed\n");
        return -4;
    }

    if (state_t < g_t_tee.load()) {
        enclave_log("Enclave: rollback detected\n");
        return -5;
    }
    g_t_tee.store(state_t);

    Hash32 root_u{};
    Hash32 root_o{};
    std::memcpy(root_u.data(), root_user, 32);
    std::memcpy(root_o.data(), root_owner, 32);

    if (user_id == nullptr || (user_tk_len > 0 && user_tk == nullptr) || (user_proof_len > 0 && user_proof == nullptr)) {
        return -6;
    }
    const Hash32 leaf_user = hash_user_leaf(user_id, user_tk, user_tk_len);
    if (!merkle_verify(root_u, leaf_user, user_idx, user_proof, user_proof_len)) {
        enclave_log("Enclave: user membership invalid\n");
        return -7;
    }

    if (owner_id == nullptr || owner_enc_sk == nullptr || (owner_proof_len > 0 && owner_proof == nullptr)) {
        return -8;
    }
    const Hash32 leaf_owner = hash_owner_leaf(owner_id, owner_enc_sk, owner_enc_sk_len);
    if (!merkle_verify(root_o, leaf_owner, owner_idx, owner_proof, owner_proof_len)) {
        enclave_log("Enclave: owner membership invalid\n");
        return -9;
    }

    std::vector<uint8_t> sk_bytes;
    const uint32_t owner_id_len = static_cast<uint32_t>(std::strlen(owner_id));
    if (!aes256_gcm_decrypt_packed(g_ktee_key.data(),
                                   reinterpret_cast<const uint8_t*>(owner_id),
                                   owner_id_len,
                                   owner_enc_sk,
                                   owner_enc_sk_len,
                                   sk_bytes)) {
        enclave_log("Enclave: owner sk decrypt failed\n");
        return -10;
    }

    OwnedBnCtx bn_ctx;
    if (bn_ctx.ctx == nullptr) {
        return -11;
    }

    OwnedBn bn_n1;
    bn_n1.bn = bn_from_bytes(n1, n1_len);
    OwnedBn bn_e1;
    bn_e1.bn = bn_from_bytes(e1, e1_len);
    OwnedBn bn_n2;
    bn_n2.bn = bn_from_bytes(n2, n2_len);
    if (bn_n1.bn == nullptr || bn_e1.bn == nullptr || bn_n2.bn == nullptr) {
        return -12;
    }

    // --- Decrypt b using BF-IBE (2001/090) + AES-GCM ---
    std::vector<uint8_t> b_bytes;
    if (!bf_ibe_decrypt_packed(
            reinterpret_cast<const uint8_t*>(owner_id),
            owner_id_len,
            sk_bytes,
            ibe_ct,
            ibe_ct_len,
            b_bytes)) {
        enclave_log("Enclave: IBE decrypt failed\n");
        return -13;
    }

    OwnedBn bn_b1;
    OwnedBn bn_b2;
    if (!parse_two_bn(b_bytes, bn_b1.bn, bn_b2.bn)) {
        enclave_log("Enclave: parse b1/b2 failed\n");
        return -24;
    }

    // --- mu1 = H1(m) * r1^e * H1(m')^{-1} mod N1 ---
    OwnedBn bn_r1;
    bn_r1.bn = bn_from_bytes(r1, r1_len);

    OwnedBn h1_m;
    OwnedBn h1_mp;
    if (!sha256_hash_mod_bn(m, m_len, n1, n1_len, n2, n2_len, bn_n1.bn, h1_m.bn, bn_ctx.ctx)) {
        enclave_log("Enclave: H1(m) failed\n");
        return -25;
    }
    if (!sha256_hash_mod_bn(m_p, mp_len, n1, n1_len, n2, n2_len, bn_n1.bn, h1_mp.bn, bn_ctx.ctx)) {
        enclave_log("Enclave: H1(m') failed\n");
        return -26;
    }

    OwnedBn r1_pow_e;
    if (BN_mod_exp(r1_pow_e.bn, bn_r1.bn, bn_e1.bn, bn_n1.bn, bn_ctx.ctx) != 1) {
        enclave_log("Enclave: r1^e mod N1 failed\n");
        return -27;
    }

    OwnedBn inv_h1_mp;
    if (BN_mod_inverse(inv_h1_mp.bn, h1_mp.bn, bn_n1.bn, bn_ctx.ctx) == nullptr) {
        enclave_log("Enclave: inv H1(m') failed\n");
        return -28;
    }

    OwnedBn bn_mu1;
    if (BN_mod_mul(bn_mu1.bn, h1_m.bn, r1_pow_e.bn, bn_n1.bn, bn_ctx.ctx) != 1) {
        return -29;
    }
    if (BN_mod_mul(bn_mu1.bn, bn_mu1.bn, inv_h1_mp.bn, bn_n1.bn, bn_ctx.ctx) != 1) {
        return -30;
    }

    // --- r1' = mu1^{d1} mod N1 ---
    OwnedBn bn_d1;
    BN_bin2bn(g_d1_bytes.data(), static_cast<int>(g_d1_bytes.size()), bn_d1.bn);

    OwnedBn bn_r1p;
    if (BN_mod_exp(bn_r1p.bn, bn_mu1.bn, bn_d1.bn, bn_n1.bn, bn_ctx.ctx) != 1) {
        enclave_log("Enclave: BN_mod_exp(r1') failed\n");
        return -31;
    }

    // --- verify h1 ---
    OwnedBn bn_h1;
    bn_h1.bn = bn_from_bytes(h1, h1_len);
    OwnedBn r1p_pow_e;
    if (BN_mod_exp(r1p_pow_e.bn, bn_r1p.bn, bn_e1.bn, bn_n1.bn, bn_ctx.ctx) != 1) {
        enclave_log("Enclave: r1'^e mod N1 failed\n");
        return -32;
    }
    OwnedBn expected_h1;
    if (BN_mod_mul(expected_h1.bn, h1_mp.bn, r1p_pow_e.bn, bn_n1.bn, bn_ctx.ctx) != 1) {
        return -33;
    }
    if (BN_cmp(expected_h1.bn, bn_h1.bn) != 0) {
        enclave_log("Enclave: h1 check failed\n");
        return -34;
    }

    // --- X = H2(m) * r2^e * H2(m')^{-1} mod N2 ---
    OwnedBn x2_m;
    OwnedBn x2_mp;
    if (!sha256_hash_mod_bn(m, m_len, n1, n1_len, n2, n2_len, bn_n2.bn, x2_m.bn, bn_ctx.ctx)) {
        enclave_log("Enclave: H2(m) failed\n");
        return -35;
    }
    if (!sha256_hash_mod_bn(m_p, mp_len, n1, n1_len, n2, n2_len, bn_n2.bn, x2_mp.bn, bn_ctx.ctx)) {
        enclave_log("Enclave: H2(m') failed\n");
        return -36;
    }

    OwnedBn bn_r2;
    bn_r2.bn = bn_from_bytes(r2, r2_len);
    OwnedBn r2_pow_e;
    if (BN_mod_exp(r2_pow_e.bn, bn_r2.bn, bn_e1.bn, bn_n2.bn, bn_ctx.ctx) != 1) {
        enclave_log("Enclave: r2^e mod N2 failed\n");
        return -37;
    }
    OwnedBn y2;
    if (BN_mod_mul(y2.bn, x2_m.bn, r2_pow_e.bn, bn_n2.bn, bn_ctx.ctx) != 1) {
        return -38;
    }
    OwnedBn inv_x2_mp;
    if (BN_mod_inverse(inv_x2_mp.bn, x2_mp.bn, bn_n2.bn, bn_ctx.ctx) == nullptr) {
        enclave_log("Enclave: inv H2(m') failed\n");
        return -39;
    }
    OwnedBn X;
    if (BN_mod_mul(X.bn, y2.bn, inv_x2_mp.bn, bn_n2.bn, bn_ctx.ctx) != 1) {
        return -40;
    }

    OwnedBn bn_a1;
    bn_a1.bn = bn_from_bytes(a1, a1_len);
    OwnedBn bn_a2;
    bn_a2.bn = bn_from_bytes(a2, a2_len);
    if (bn_a1.bn == nullptr || bn_a2.bn == nullptr) {
        return -41;
    }

    OwnedBn bn_mu21;
    OwnedBn bn_mu22;
    if (BN_mod_exp(bn_mu21.bn, X.bn, bn_a1.bn, bn_n2.bn, bn_ctx.ctx) != 1) {
        enclave_log("Enclave: BN_mod_exp(mu21) failed\n");
        return -42;
    }
    if (BN_mod_exp(bn_mu22.bn, X.bn, bn_a2.bn, bn_n2.bn, bn_ctx.ctx) != 1) {
        enclave_log("Enclave: BN_mod_exp(mu22) failed\n");
        return -43;
    }

    // --- pi = mu2_i^{b_i} mod N2 ---
    OwnedBn bn_pi1;
    OwnedBn bn_pi2;
    if (BN_mod_exp(bn_pi1.bn, bn_mu21.bn, bn_b1.bn, bn_n2.bn, bn_ctx.ctx) != 1) {
        enclave_log("Enclave: BN_mod_exp(pi1) failed\n");
        return -44;
    }
    if (BN_mod_exp(bn_pi2.bn, bn_mu22.bn, bn_b2.bn, bn_n2.bn, bn_ctx.ctx) != 1) {
        enclave_log("Enclave: BN_mod_exp(pi2) failed\n");
        return -45;
    }
    if (BN_cmp(bn_pi1.bn, bn_pi2.bn) != 0) {
        enclave_log("Enclave: pi mismatch\n");
        return -46;
    }

    const auto r1p_bytes = bn_to_bytes(bn_r1p.bn);
    const auto pi_bytes = bn_to_bytes(bn_pi1.bn);
    if (r1p_bytes.size() > r1p_buf_len || pi_bytes.size() > pi_buf_len) {
        enclave_log("Enclave: output buffer too small\n");
        return -47;
    }
    std::memcpy(r1p_buf, r1p_bytes.data(), r1p_bytes.size());
    std::memcpy(pi_buf, pi_bytes.data(), pi_bytes.size());
    *r1p_len = static_cast<uint32_t>(r1p_bytes.size());
    *pi_len = static_cast<uint32_t>(pi_bytes.size());
    return 0;
}

int ecall_hrpch_insider_adapt_no_outsource(
    const char* owner_id,
    uint8_t* owner_enc_sk,
    uint32_t owner_enc_sk_len,
    uint8_t* n1,
    uint32_t n1_len,
    uint8_t* e1,
    uint32_t e1_len,
    uint8_t* n2,
    uint32_t n2_len,
    uint8_t* m,
    uint32_t m_len,
    uint8_t* m_p,
    uint32_t mp_len,
    uint8_t* h1,
    uint32_t h1_len,
    uint8_t* r1,
    uint32_t r1_len,
    uint8_t* r2,
    uint32_t r2_len,
    uint8_t* a1,
    uint32_t a1_len,
    uint8_t* a2,
    uint32_t a2_len,
    uint8_t* ibe_ct,
    uint32_t ibe_ct_len,
    uint8_t* r1p_buf,
    uint32_t r1p_buf_len,
    uint32_t* r1p_len,
    uint8_t* pi_buf,
    uint32_t pi_buf_len,
    uint32_t* pi_len) {
    if (r1p_len == nullptr || pi_len == nullptr) {
        return -1;
    }
    *r1p_len = 0;
    *pi_len = 0;

    if (g_d1_bytes.empty() || !g_has_ktee_key) {
        enclave_log("Enclave: not provisioned\n");
        return -2;
    }

    if (owner_id == nullptr || owner_enc_sk == nullptr) {
        return -3;
    }

    std::vector<uint8_t> sk_bytes;
    const uint32_t owner_id_len = static_cast<uint32_t>(std::strlen(owner_id));
    if (!aes256_gcm_decrypt_packed(g_ktee_key.data(),
                                   reinterpret_cast<const uint8_t*>(owner_id),
                                   owner_id_len,
                                   owner_enc_sk,
                                   owner_enc_sk_len,
                                   sk_bytes)) {
        enclave_log("Enclave: owner sk decrypt failed\n");
        return -4;
    }

    OwnedBnCtx bn_ctx;
    if (bn_ctx.ctx == nullptr) {
        return -5;
    }

    OwnedBn bn_n1;
    bn_n1.bn = bn_from_bytes(n1, n1_len);
    OwnedBn bn_e1;
    bn_e1.bn = bn_from_bytes(e1, e1_len);
    OwnedBn bn_n2;
    bn_n2.bn = bn_from_bytes(n2, n2_len);
    if (bn_n1.bn == nullptr || bn_e1.bn == nullptr || bn_n2.bn == nullptr) {
        return -6;
    }

    // --- Decrypt b using BF-IBE (2001/090) + AES-GCM ---
    std::vector<uint8_t> b_bytes;
    if (!bf_ibe_decrypt_packed(
            reinterpret_cast<const uint8_t*>(owner_id),
            owner_id_len,
            sk_bytes,
            ibe_ct,
            ibe_ct_len,
            b_bytes)) {
        enclave_log("Enclave: IBE decrypt failed\n");
        return -7;
    }

    OwnedBn bn_b1;
    bn_b1.bn = bn_from_bytes(b_bytes.data(), static_cast<uint32_t>(b_bytes.size()));
    if (bn_b1.bn == nullptr) {
        enclave_log("Enclave: parse b1 failed\n");
        return -18;
    }

    // --- mu1 = H1(m) * r1^e * H1(m')^{-1} mod N1 ---
    OwnedBn bn_r1;
    bn_r1.bn = bn_from_bytes(r1, r1_len);

    OwnedBn h1_m;
    OwnedBn h1_mp;
    if (!sha256_hash_mod_bn(m, m_len, n1, n1_len, n2, n2_len, bn_n1.bn, h1_m.bn, bn_ctx.ctx)) {
        enclave_log("Enclave: H1(m) failed\n");
        return -19;
    }
    if (!sha256_hash_mod_bn(m_p, mp_len, n1, n1_len, n2, n2_len, bn_n1.bn, h1_mp.bn, bn_ctx.ctx)) {
        enclave_log("Enclave: H1(m') failed\n");
        return -20;
    }

    OwnedBn r1_pow_e;
    if (BN_mod_exp(r1_pow_e.bn, bn_r1.bn, bn_e1.bn, bn_n1.bn, bn_ctx.ctx) != 1) {
        enclave_log("Enclave: r1^e mod N1 failed\n");
        return -21;
    }

    OwnedBn inv_h1_mp;
    if (BN_mod_inverse(inv_h1_mp.bn, h1_mp.bn, bn_n1.bn, bn_ctx.ctx) == nullptr) {
        enclave_log("Enclave: inv H1(m') failed\n");
        return -22;
    }

    OwnedBn bn_mu1;
    if (BN_mod_mul(bn_mu1.bn, h1_m.bn, r1_pow_e.bn, bn_n1.bn, bn_ctx.ctx) != 1) {
        return -23;
    }
    if (BN_mod_mul(bn_mu1.bn, bn_mu1.bn, inv_h1_mp.bn, bn_n1.bn, bn_ctx.ctx) != 1) {
        return -24;
    }

    // --- r1' = mu1^{d1} mod N1 ---
    OwnedBn bn_d1;
    BN_bin2bn(g_d1_bytes.data(), static_cast<int>(g_d1_bytes.size()), bn_d1.bn);

    OwnedBn bn_r1p;
    if (BN_mod_exp(bn_r1p.bn, bn_mu1.bn, bn_d1.bn, bn_n1.bn, bn_ctx.ctx) != 1) {
        enclave_log("Enclave: BN_mod_exp(r1') failed\n");
        return -25;
    }

    // --- verify h1 ---
    OwnedBn bn_h1;
    bn_h1.bn = bn_from_bytes(h1, h1_len);
    OwnedBn r1p_pow_e;
    if (BN_mod_exp(r1p_pow_e.bn, bn_r1p.bn, bn_e1.bn, bn_n1.bn, bn_ctx.ctx) != 1) {
        enclave_log("Enclave: r1'^e mod N1 failed\n");
        return -26;
    }
    OwnedBn expected_h1;
    if (BN_mod_mul(expected_h1.bn, h1_mp.bn, r1p_pow_e.bn, bn_n1.bn, bn_ctx.ctx) != 1) {
        return -27;
    }
    if (BN_cmp(expected_h1.bn, bn_h1.bn) != 0) {
        enclave_log("Enclave: h1 check failed\n");
        return -28;
    }

    // --- X = H2(m) * r2^e * H2(m')^{-1} mod N2 ---
    OwnedBn x2_m;
    OwnedBn x2_mp;
    if (!sha256_hash_mod_bn(m, m_len, n1, n1_len, n2, n2_len, bn_n2.bn, x2_m.bn, bn_ctx.ctx)) {
        enclave_log("Enclave: H2(m) failed\n");
        return -29;
    }
    if (!sha256_hash_mod_bn(m_p, mp_len, n1, n1_len, n2, n2_len, bn_n2.bn, x2_mp.bn, bn_ctx.ctx)) {
        enclave_log("Enclave: H2(m') failed\n");
        return -30;
    }

    OwnedBn bn_r2;
    bn_r2.bn = bn_from_bytes(r2, r2_len);
    OwnedBn r2_pow_e;
    if (BN_mod_exp(r2_pow_e.bn, bn_r2.bn, bn_e1.bn, bn_n2.bn, bn_ctx.ctx) != 1) {
        enclave_log("Enclave: r2^e mod N2 failed\n");
        return -31;
    }
    OwnedBn y2;
    if (BN_mod_mul(y2.bn, x2_m.bn, r2_pow_e.bn, bn_n2.bn, bn_ctx.ctx) != 1) {
        return -32;
    }
    OwnedBn inv_x2_mp;
    if (BN_mod_inverse(inv_x2_mp.bn, x2_mp.bn, bn_n2.bn, bn_ctx.ctx) == nullptr) {
        enclave_log("Enclave: inv H2(m') failed\n");
        return -33;
    }
    OwnedBn X;
    if (BN_mod_mul(X.bn, y2.bn, inv_x2_mp.bn, bn_n2.bn, bn_ctx.ctx) != 1) {
        return -34;
    }

    // --- pi = X^{b1} mod N2 ---
    OwnedBn bn_pi;
    if (BN_mod_exp(bn_pi.bn, X.bn, bn_b1.bn, bn_n2.bn, bn_ctx.ctx) != 1) {
        enclave_log("Enclave: BN_mod_exp(pi) failed\n");
        return -38;
    }

    const auto r1p_bytes = bn_to_bytes(bn_r1p.bn);
    const auto pi_bytes = bn_to_bytes(bn_pi.bn);
    if (r1p_bytes.size() > r1p_buf_len || pi_bytes.size() > pi_buf_len) {
        enclave_log("Enclave: output buffer too small\n");
        return -41;
    }
    std::memcpy(r1p_buf, r1p_bytes.data(), r1p_bytes.size());
    std::memcpy(pi_buf, pi_bytes.data(), pi_bytes.size());
    *r1p_len = static_cast<uint32_t>(r1p_bytes.size());
    *pi_len = static_cast<uint32_t>(pi_bytes.size());
    return 0;
}

int ecall_state_check(
    uint64_t state_t,
    uint8_t* root_user,
    uint8_t* root_owner,
    uint8_t* state_sig_der,
    uint32_t sig_len,
    const char* user_id,
    uint32_t user_idx,
    uint8_t* user_tk,
    uint32_t user_tk_len,
    uint8_t* user_proof,
    uint32_t user_proof_len) {
    if (g_d1_bytes.empty() || g_vk_sig.pkey == nullptr) {
        enclave_log("Enclave: not provisioned\n");
        return -2;
    }
    if (root_user == nullptr || root_owner == nullptr || state_sig_der == nullptr || sig_len == 0) {
        return -3;
    }
    if (!verify_state_sig(g_vk_sig.pkey, state_t, root_user, root_owner, state_sig_der, sig_len)) {
        enclave_log("Enclave: state signature verify failed\n");
        return -4;
    }
    if (state_t < g_t_tee.load()) {
        enclave_log("Enclave: rollback detected\n");
        return -5;
    }
    g_t_tee.store(state_t);
    if (user_id == nullptr || (user_tk_len > 0 && user_tk == nullptr) || (user_proof_len > 0 && user_proof == nullptr)) {
        return -6;
    }
    Hash32 root_u{};
    std::memcpy(root_u.data(), root_user, 32);
    const Hash32 leaf_user = hash_user_leaf(user_id, user_tk, user_tk_len);
    if (!merkle_verify(root_u, leaf_user, user_idx, user_proof, user_proof_len)) {
        enclave_log("Enclave: user membership invalid\n");
        return -7;
    }
    return 0;
}
