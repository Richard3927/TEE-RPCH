/**
 * FAME-OD: Outsourced decryption variant of FAME CP-ABE (single outsourcing layer).
 *
 * Notes:
 * - This implementation matches the interface expected by TEE-RPCH's SGX prototype:
 *   KeyGen outputs (TK, DK), the cloud runs Transform(TK, CT)->TC, and the user runs
 *   Decrypt(DK, TC)->msg.
 * - The heavier pairing work is offloaded to Transform; Decrypt is lightweight.
 */
#ifndef FAME_OD_H
#define FAME_OD_H

#include <pbc/pbc.h>
#include <utils/func.h>

#include <ABE/policy/policy_generation.h>
#include <ABE/policy/policy_resolution.h>

#include <string>
#include <unordered_map>
#include <vector>

class FAME_OD {
    private:
        element_t* G;
        element_t* H;
        element_t* GT;
        element_t* Zn;

        element_t tmp_G, tmp_G_2, tmp_G_3, tmp_G_4;
        element_t tmp_H, tmp_H_2, tmp_H_3;
        element_t tmp_GT, tmp_GT_2, tmp_GT_3;
        element_t tmp_Zn, tmp_Zn_2, tmp_Zn_3;
        element_t tmp_D_1, tmp_D_2, tmp_D_3;

        element_t d1, d2, d3;
        element_t r1, r2;

        element_t b1r1a1, b1r1a2, b2r2a1, b2r2a2, r1r2a1, r1r2a2;
        element_t sigma_y, sigma;
        element_t s1, s2;

        element_t R_1, R_2;

        std::unordered_map<unsigned long int, std::string> pai;      // π(i) -> attr
        std::unordered_map<std::string, unsigned long int> attr_map; // attr -> index of attr_list

        std::string policy_str;

    public:
        FAME_OD(element_t* _G, element_t* _H, element_t* _GT, element_t* _Zn);

        struct mpk {
            element_t h, H1, H2, T1, T2;

            void Init(element_t* _H, element_t* _GT) {
                element_init_same_as(h, *_H);
                element_init_same_as(H1, *_H);
                element_init_same_as(H2, *_H);
                element_init_same_as(T1, *_GT);
                element_init_same_as(T2, *_GT);
            }
            ~mpk() {
                element_clear(h);
                element_clear(H1);
                element_clear(H2);
                element_clear(T1);
                element_clear(T2);
            }
        };

        struct msk {
            element_t g, h, a1, a2, b1, b2, g_pow_d1, g_pow_d2, g_pow_d3;

            void Init(element_t* _G, element_t* _H, element_t* _Zn) {
                element_init_same_as(g, *_G);
                element_init_same_as(h, *_H);
                element_init_same_as(a1, *_Zn);
                element_init_same_as(a2, *_Zn);
                element_init_same_as(b1, *_Zn);
                element_init_same_as(b2, *_Zn);
                element_init_same_as(g_pow_d1, *_G);
                element_init_same_as(g_pow_d2, *_G);
                element_init_same_as(g_pow_d3, *_G);
            }
            ~msk() {
                element_clear(g);
                element_clear(h);
                element_clear(a1);
                element_clear(a2);
                element_clear(b1);
                element_clear(b2);
                element_clear(g_pow_d1);
                element_clear(g_pow_d2);
                element_clear(g_pow_d3);
            }
        };

        struct DK {
            element_t beta;
            void Init(element_t* _Zn) { element_init_same_as(beta, *_Zn); }
            ~DK() { element_clear(beta); }
        };

        struct sk {
            element_t sk_1, sk_2, sk_3;

            // _Group: G or H
            void Init(element_t* _Group) {
                element_init_same_as(sk_1, *_Group);
                element_init_same_as(sk_2, *_Group);
                element_init_same_as(sk_3, *_Group);
            }
            ~sk() {
                element_clear(sk_1);
                element_clear(sk_2);
                element_clear(sk_3);
            }
        };

        struct sks {
            sk sk0;
            std::vector<sk*> sk_y;
            sk sk_prime;

            void Init(element_t* _G, element_t* _H, int y_size) {
                sk0.Init(_H);
                sk_prime.Init(_G);
                for (int i = 0; i < y_size; i++) {
                    sk* sk_y_tmp = new sk();
                    sk_y_tmp->Init(_G);
                    sk_y.push_back(sk_y_tmp);
                }
            }
            ~sks() {
                for (int i = 0; i < (int)sk_y.size(); i++) {
                    sk_y[i]->~sk();
                }
            }
        };

        struct TK {
            sks* TK1;

            void Init(element_t* _G, element_t* _H, int y_size) {
                TK1 = new sks;
                TK1->Init(_G, _H, y_size);
            }
            ~TK() { TK1->~sks(); }
        };

        void Setup(msk* msk, mpk* mpk);

        // Output: (TK, DK) for outsourced decryption.
        void KeyGen(msk* msk, mpk* mpk, std::vector<std::string>* attr_list, TK* TK, DK* DK);

        void Hash(std::string m, element_t* res);
        void Hash2(element_t* m, element_t* res);

        struct ct {
            element_t ct_1, ct_2, ct_3;

            void Init(element_t* _Group) {
                element_init_same_as(ct_1, *_Group);
                element_init_same_as(ct_2, *_Group);
                element_init_same_as(ct_3, *_Group);
            }
            ~ct() {
                element_clear(ct_1);
                element_clear(ct_2);
                element_clear(ct_3);
            }
        };

        struct ciphertext {
            ct ct0;
            std::vector<ct*> ct_y;
            element_t ct_prime;
            element_t ct_prime2;
            element_t ct_prime3;

            void Init(element_t* _Zn, element_t* _G, element_t* _H, element_t* _GT, const int rows) {
                ct0.Init(_H);
                element_init_same_as(ct_prime, *_GT);
                for (int i = 0; i < rows; i++) {
                    ct* ct_y_tmp = new ct();
                    ct_y_tmp->Init(_G);
                    ct_y.push_back(ct_y_tmp);
                }
                element_init_same_as(ct_prime2, *_GT);
                element_init_same_as(ct_prime3, *_GT);
            }
            ~ciphertext() {
                for (int i = 0; i < (int)ct_y.size(); i++) {
                    ct_y[i]->~ct();
                }
                element_clear(ct_prime);
                element_clear(ct_prime2);
                element_clear(ct_prime3);
            }
        };

        struct TC {
            element_t ct_prime;
            element_t ct_prime2;
            element_t ct_prime3;
            element_t ct_p;

            void Init(element_t* _Zn, element_t* _G, element_t* _H, element_t* _GT) {
                element_init_same_as(ct_prime, *_GT);
                element_init_same_as(ct_prime2, *_GT);
                element_init_same_as(ct_prime3, *_GT);
                element_init_same_as(ct_p, *_GT);
            }
            ~TC() {
                element_clear(ct_prime);
                element_clear(ct_prime2);
                element_clear(ct_prime3);
                element_clear(ct_p);
            }
        };

        void Encrypt(mpk* mpk, element_t* msg, std::string policy_str, ciphertext* ciphertext);
        void Encrypt(mpk* mpk, element_t* msg, std::string policy_str, element_t* s1, element_t* s2, ciphertext* ciphertext);

        // Cloud transform (outsourced decryption): TC carries the transformed value ct_p and the remaining ciphertext.
        void Transform(mpk* mpk, ciphertext* ciphertext, TK* TK, TC* TC);

        // User finalize.
        void Decrypt(mpk* mpk, TC* TC, DK* DK, element_t* res);

        ~FAME_OD();
};

#endif // FAME_OD_H
