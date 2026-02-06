/**
 * Policy-based Chameleon Hash for Blockchain Rewriting with Black-box Accountability
 */
#ifndef ABET_H
#define ABET_H

#include <pbc/pbc.h>
#include <utils/func.h>
#include <vector>
#include <string>
#include <unordered_map>
#include <ABE/policy/policy_resolution.h>
#include <ABE/policy/policy_generation.h>

class ABET{
    private:
        element_t *G, *H, *GT, *Zn;
        element_t tmp_G,tmp_G_2,tmp_G_3,tmp_G_4,tmp_H,tmp_H_2,tmp_H_3,tmp_GT,tmp_GT_2,tmp_GT_3,tmp_Zn,tmp_Zn_2,tmp_Zn_3;

        int k;
        element_t d1,d2,d3;
        element_t r1,r2;
        element_t R;
        element_t b1r1a1,b1r1a2,b2r2a1,b2r2a2,r1r2a1,r1r2a2;
        element_t s1,s2;

        unordered_map<unsigned long int, string> pai;  // π(i) -> attr
        unordered_map<string, unsigned long int> attr_map;  // attr -> index of attr_list
        string policy_str;

    public:
        ABET(element_t *_G, element_t *_H, element_t *_GT, element_t *_Zn);

        struct mpk{
            element_t g,h,H1,H2,T1,T2;
            vector<element_t *> gk;  // {g1, g2, ..., gk}
            vector<element_t *> gk_pow_a;  // {g1^a, g2^a, ..., gk^a}
            vector<element_t *> hk;  // {h1, h2, ..., hk}
            element_t g_pow_a, h_pow_d_div_a, h_pow_1_div_a, h_pow_b_div_a;  // g^α, h^(d/α), h^(1/α), h^(β/α)

            void Init(element_t *_G, element_t *_H, element_t *_GT, int k){
                element_init_same_as(g, *_G);
                element_init_same_as(h, *_H);
                element_init_same_as(H1, *_H);
                element_init_same_as(H2, *_H);
                element_init_same_as(T1, *_GT);
                element_init_same_as(T2, *_GT);
                gk.resize(k+1);
                gk_pow_a.resize(k+1);
                hk.resize(k+1);
                for(int i = 1;i <= k;i++){
                    element_t* gk_tmp = new element_t[1];
                    element_t* gk_pow_a_tmp = new element_t[1];
                    element_t* hk_tmp = new element_t[1];
                    element_init_same_as(*gk_tmp, *_G);                    
                    element_init_same_as(*gk_pow_a_tmp, *_G);                                   
                    element_init_same_as(*hk_tmp, *_H);
                    gk[i] = gk_tmp;
                    gk_pow_a[i] = gk_pow_a_tmp; 
                    hk[i] = hk_tmp;
                }
                element_init_same_as(g_pow_a, *_G);
                element_init_same_as(h_pow_d_div_a, *_H);
                element_init_same_as(h_pow_1_div_a, *_H);
                element_init_same_as(h_pow_b_div_a, *_H);
            }
            ~mpk(){
                element_clear(g);
                element_clear(h);
                element_clear(H1);
                element_clear(H2);
                element_clear(T1);
                element_clear(T2);
                for(int i = 1;i < gk.size();i++){
                    element_clear(*gk[i]);
                    element_clear(*gk_pow_a[i]);
                    element_clear(*hk[i]);
                }
                element_clear(g_pow_a);
                element_clear(h_pow_d_div_a);
                element_clear(h_pow_1_div_a);
                element_clear(h_pow_b_div_a);
            }
        };

        struct  msk{
            element_t a1,a2,b1,b2,a,b,g_pow_d1,g_pow_d2,g_pow_d3;
            vector<element_t *> zk;  // {z1, z2, ..., zk}

            void Init(element_t *_G, element_t *_H, element_t *_Zn, int k){
                element_init_same_as(a1, *_Zn);
                element_init_same_as(a2, *_Zn);
                element_init_same_as(b1, *_Zn);
                element_init_same_as(b2, *_Zn);
                element_init_same_as(a, *_Zn);
                element_init_same_as(b, *_Zn);
                element_init_same_as(g_pow_d1, *_G);
                element_init_same_as(g_pow_d2, *_G);
                element_init_same_as(g_pow_d3, *_G);
                zk.resize(k+1);
                for(int i = 1;i <= k;i++){
                    element_t* zk_tmp = new element_t[1];
                    element_init_same_as(*zk_tmp, *_Zn);
                    zk[i] = zk_tmp;
                }
            }
            ~msk(){
                element_clear(a1);
                element_clear(a2);
                element_clear(b1);
                element_clear(b2);
                element_clear(a);
                element_clear(b);
                element_clear(g_pow_d1);
                element_clear(g_pow_d2);
                element_clear(g_pow_d3);
                for(int i = 1;i < zk.size();i++){
                    element_clear(*zk[i]);
                }
            }
        };

        struct ID{
            vector<element_t *> Ik;  // {I1, I2, ..., Ik}
            void Init(element_t *_Zn, int k){
                Ik.resize(k+1);
                for(int i = 1;i <= k;i++){
                    element_t *Ik_tmp = new element_t[1];
                    element_init_same_as(*Ik_tmp, *_Zn);
                    Ik[i] = Ik_tmp;
                }
            }
            ~ID(){
                for(int i = 1;i < Ik.size();i++){
                    element_clear(*Ik[i]);
                }
            }
        };

        struct sk{
            element_t sk_1,sk_2,sk_3;

            // _Group: G or H
            void Init(element_t *_Group){
                element_init_same_as(sk_1, *_Group);
                element_init_same_as(sk_2, *_Group);
                element_init_same_as(sk_3, *_Group);
            }
            ~sk(){
                element_clear(sk_1);
                element_clear(sk_2);
                element_clear(sk_3);
            }
        };

        struct sk0{
            element_t sk0_1,sk0_2,sk0_3,sk0_4,sk0_5,sk0_6;
            void Init(element_t *_G, element_t *_H){
                element_init_same_as(sk0_1, *_H);
                element_init_same_as(sk0_2, *_H);
                element_init_same_as(sk0_3, *_H);
                element_init_same_as(sk0_4, *_G);
                element_init_same_as(sk0_5, *_G);
                element_init_same_as(sk0_6, *_G);
            }
            ~sk0(){
                element_clear(sk0_1);
                element_clear(sk0_2);
                element_clear(sk0_3);
                element_clear(sk0_4);
                element_clear(sk0_5);
                element_clear(sk0_6);
            }
        };

        struct sks{
            sk0 sk_0;
            std::vector<sk *> sk_y;
            sk sk_prime;
            element_t sk1;
            vector<element_t *> sk2;
            
            void Init(element_t *_G, element_t *_H, int y_size, int I){
                sk_0.Init(_G, _H);
                sk_prime.Init(_G);
                for(int i = 0;i < y_size;i++){
                    sk* sk_y_tmp = new sk();
                    sk_y_tmp->Init(_G);
                    sk_y.push_back(sk_y_tmp);
                }
                element_init_same_as(sk1, *_G);
                sk2.resize(I);
                for(int i = 1;i <= (I-1);i++){
                    element_t *sk2_tmp = new element_t[1];
                    element_init_same_as(*sk2_tmp, *_G);
                    sk2[i] = sk2_tmp;
                }
            }
            ~sks(){
                for(int i = 0;i < sk_y.size();i++){
                    sk_y[i]->~sk();
                }
                element_clear(sk1);
                for(int i = 1;i < sk2.size();i++){
                    element_clear(*sk2[i]);
                }
            }
        };

        void Setup(msk *msk, mpk *mpk, int k);

        void KeyGen(msk *msk, mpk *mpk, std::vector<std::string> *attr_list, ID *ID, int mi, sks *sks);

        void Hash(std::string m, element_t *res);
        void Hash2(element_t *m, element_t *res);

        struct ct0{
            element_t ct0_1,ct0_2,ct0_3,ct0_4;

            void Init(element_t *_H){
                element_init_same_as(ct0_1, *_H);
                element_init_same_as(ct0_2, *_H);
                element_init_same_as(ct0_3, *_H);
                element_init_same_as(ct0_4, *_H);
            }
            ~ct0(){
                element_clear(ct0_1);
                element_clear(ct0_2);
                element_clear(ct0_3);
                element_clear(ct0_4);
            }
        };

        struct ct{
            element_t ct_1,ct_2,ct_3;

            void Init(element_t *_Group){
                element_init_same_as(ct_1, *_Group);
                element_init_same_as(ct_2, *_Group);
                element_init_same_as(ct_3, *_Group);
            }
            ~ct(){
                element_clear(ct_1);
                element_clear(ct_2);
                element_clear(ct_3);
            }
        };

        struct ciphertext{
            ct0 ct_0;
            std::vector<ct *> ct_y;
            element_t ct_;  // use ct_ to avoid conflict with ct(ct_1, ct_2, ct_3)
            element_t ct_prime;
            element_t ct1;
            element_t ct2;
            element_t ct3;

            void Init(element_t *_G, element_t *_H, element_t *_GT, element_t *_Zn, int rows){
                ct_0.Init(_H);
                element_init_same_as(ct_, *_Zn);
                element_init_same_as(ct_prime, *_Zn);
                element_init_same_as(ct1, *_H);
                element_init_same_as(ct2, *_H);
                element_init_same_as(ct3, *_H);
                for(int i = 0;i < rows;i++){
                    ct* ct_y_tmp = new ct();
                    ct_y_tmp->Init(_G);
                    ct_y.push_back(ct_y_tmp);
                }
            }
            ~ciphertext(){
                for(int i = 0;i < ct_y.size();i++){
                    ct_y[i]->~ct();
                }
                element_clear(ct_);
                element_clear(ct_prime);
                element_clear(ct1);
                element_clear(ct2);
                element_clear(ct3);
            }
        };

        void Encrypt(mpk *mpk, msk *msk,  element_t *r, element_t *R, std::string policy_str, ID *ID, int oj,  element_t *s1, element_t *s2, ciphertext *ciphertext);

        void Decrypt(mpk *mpk, ciphertext *ciphertext, sks *sks, element_t *res_R, element_t *res_r);

        ~ABET();

        const int MODIFIER = 1;
        const int OWNER = 2;
        void GetID_(mpk *mpk, ID *ID, int mi_oj, int type, element_t *ID_);
};


#endif // ABET_H