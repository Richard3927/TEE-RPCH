#include <SE/AES.h>
#include <algorithm>
#include <cstring>
#include <vector>

AES::AES(){
    this->k = 256;
}

/**
 * KGen 
 * input: k
 * output: key
 */
void AES::KGen(int k, element_t *key){
    if(this->k != 256){
        throw std::invalid_argument("AES-256 Enc: k must be 256");
    }
    this->k = k;
    element_random(*key);
}

/**
 * AES-256 KGen 
 * output: key
 */
void AES::KGen(element_t *key){
    element_random(*key);
}

/**
 * AES-256 Enc
 * input: key, plaintext
 * output: ciphertext
 */
void AES::Enc(element_t *key, mpz_t *plaintext, mpz_t *ciphertext){
    // Derive a 32-byte AES-256 key from the group element bytes (avoid variable-length key material).
    const size_t key_len = static_cast<size_t>(element_length_in_bytes(*key));
    std::vector<unsigned char> key_bytes(key_len);
    element_to_bytes(key_bytes.data(), *key);

    unsigned char aes_key[32];
    unsigned int md_len = 0;
    EVP_Digest(key_bytes.data(), key_bytes.size(), aes_key, &md_len, EVP_sha256(), nullptr);

    // Serialize plaintext mpz_t into a byte array.
    const size_t pt_len = (mpz_sizeinbase(*plaintext, 2) + 7) / 8;
    std::vector<unsigned char> pt(std::max<size_t>(1, pt_len), 0);
    size_t exported = 0;
    mpz_export(pt.data(), &exported, 1, 1, 1, 0, *plaintext);
    pt.resize(std::max<size_t>(1, exported));

    // AES-CBC ciphertext length <= pt_len + block_size.
    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    // AES-CBC block size is always 16 bytes.
    const int block = 16;
    std::vector<unsigned char> ct(pt.size() + static_cast<size_t>(block));
    unsigned char iv[16] = {0};

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    int len = 0;
    int out_len = 0;
    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, aes_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }
    if (EVP_EncryptUpdate(ctx, ct.data(), &len, pt.data(), static_cast<int>(pt.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }
    out_len = len;
    if (EVP_EncryptFinal_ex(ctx, ct.data() + out_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    out_len += len;
    EVP_CIPHER_CTX_free(ctx);

    // mpz_export drops leading 0x00 bytes. Prefix with a non-zero sentinel so the
    // ciphertext bytes round-trip through mpz_{import,export} without losing length.
    std::vector<unsigned char> ct_pack(static_cast<size_t>(out_len) + 1, 0);
    ct_pack[0] = 1;
    if (out_len > 0) {
        std::memcpy(ct_pack.data() + 1, ct.data(), static_cast<size_t>(out_len));
    }
    mpz_import(*ciphertext, ct_pack.size(), 1, 1, 1, 0, ct_pack.data());
}

/**
 * input: key, ciphertext
 * output: decrypted_plaintext
 */
void AES::Dec(element_t *key, mpz_t *ciphertext, mpz_t *decrypted_plaintext){
    const size_t key_len = static_cast<size_t>(element_length_in_bytes(*key));
    std::vector<unsigned char> key_bytes(key_len);
    element_to_bytes(key_bytes.data(), *key);

    unsigned char aes_key[32];
    unsigned int md_len = 0;
    EVP_Digest(key_bytes.data(), key_bytes.size(), aes_key, &md_len, EVP_sha256(), nullptr);

    // Serialize ciphertext mpz_t into a byte array (with leading sentinel byte).
    const size_t ct_len = (mpz_sizeinbase(*ciphertext, 2) + 7) / 8;
    std::vector<unsigned char> ct_pack(std::max<size_t>(1, ct_len), 0);
    size_t exported = 0;
    mpz_export(ct_pack.data(), &exported, 1, 1, 1, 0, *ciphertext);
    ct_pack.resize(std::max<size_t>(1, exported));

    if (ct_pack.size() < 2 || ct_pack[0] != 1) {
        throw std::runtime_error("AES::Dec: invalid ciphertext encoding");
    }
    const std::vector<unsigned char> ct(ct_pack.begin() + 1, ct_pack.end());

    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    const int block = 16;
    std::vector<unsigned char> pt(ct.size() + static_cast<size_t>(block));
    unsigned char iv[16] = {0};

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    int len = 0;
    int out_len = 0;
    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, aes_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }
    if (EVP_DecryptUpdate(ctx, pt.data(), &len, ct.data(), static_cast<int>(ct.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }
    out_len = len;
    if (EVP_DecryptFinal_ex(ctx, pt.data() + out_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptFinal_ex failed");
    }
    out_len += len;
    EVP_CIPHER_CTX_free(ctx);

    mpz_import(*decrypted_plaintext, static_cast<size_t>(out_len), 1, 1, 1, 0, pt.data());
}

AES::~AES(){

}
