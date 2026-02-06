/**
 * FAME： ciphertext-policy attribute-based encryotion
 */
#ifndef FAME_2OD_H
#define FAME_2OD_H

#include <pbc/pbc.h>
#include <utils/func.h>
#include <vector>
#include <string>
#include <unordered_map>
#include <ABE/policy/policy_resolution.h>
#include <ABE/policy/policy_generation.h>

class FAME_2OD{
    private:
        element_t *G, *H, *GT, *Zn;
        element_t tmp_G,tmp_G_2,tmp_G_3,tmp_G_4,tmp_H,tmp_H_2,tmp_H_3,tmp_GT,tmp_GT_2,tmp_GT_3,tmp_Zn,tmp_Zn_2,tmp_Zn_3,tmp_D_1,tmp_D_2,tmp_D_3;

        element_t d1,d2,d3;
        element_t r1,r2;
 
        element_t i1b1r1a1,i1b1r1a2,i1b2r2a1,i1b2r2a2,i1r1r2a1,i1r1r2a2;
        element_t i2b1r1a1,i2b1r1a2,i2b2r2a1,i2b2r2a2,i2r1r2a1,i2r1r2a2;
        element_t sigma_y, sigma;
        element_t s1,s2;
        element_t ct_p1, ct_p2;
        element_t R_1,R_2;
        unordered_map<unsigned long int, string> pai;  // π(i) -> attr
        unordered_map<string, unsigned long int> attr_map;  // attr -> index of attr_list

        string policy_str;

    public:
        FAME_2OD(element_t *_G, element_t *_H, element_t *_GT, element_t *_Zn);

        struct mpk{
            element_t h,H1,H2,T1,T2;

            void Init(element_t *_H, element_t *_GT){
                element_init_same_as(h, *_H);
                element_init_same_as(H1, *_H);
                element_init_same_as(H2, *_H);
                element_init_same_as(T1, *_GT);
                element_init_same_as(T2, *_GT);
            }
            ~mpk(){
                element_clear(h);
                element_clear(H1);
                element_clear(H2);
                element_clear(T1);
                element_clear(T2);
            }
        };

        struct  msk{
            element_t g,h,a1,a2,b1,b2,g_pow_d1,g_pow_d2,g_pow_d3;

            void Init(element_t *_G, element_t *_H, element_t *_Zn){
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
            ~msk(){
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
        struct DK
        {
            element_t beta;
            void Init(element_t *_Zn){
                element_init_same_as(beta,*_Zn);
            }
            ~DK(){
                element_clear(beta);
            }
        };
        struct  HK
        {
            element_t gama1,gama2;
            void Init(element_t *_Zn){
                element_init_same_as(gama1,*_Zn);
                element_init_same_as(gama2,*_Zn);
            }
            ~HK(){
                element_clear(gama1);
                element_clear(gama2);
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

        struct sks{
            sk sk0;
            std::vector<sk *> sk_y;
            sk sk_prime;
            
            void Init(element_t *_G, element_t *_H, int y_size){
                sk0.Init(_H);
                sk_prime.Init(_G);
                for(int i = 0;i < y_size;i++){
                    sk* sk_y_tmp = new sk();
                    sk_y_tmp->Init(_G);
                    sk_y.push_back(sk_y_tmp);
                }
            }
            ~sks(){
                for(int i = 0;i < sk_y.size();i++){
                    sk_y[i]->~sk();
                }
            }
        };
        struct TK{
            sks* TK1;
            sks* TK2;
            
            void Init(element_t *_G, element_t *_H, int y_size){
                TK1 = new sks;
                TK1->Init(_G, _H, y_size);
                TK2 = new sks;
                TK2->Init(_G, _H, y_size);
            }
            ~TK(){
                TK1->~sks();
                TK2->~sks();
            }
        };

        void Setup(msk *msk, mpk *mpk);

        void KeyGen(msk *msk, mpk *mpk, std::vector<std::string> *attr_list, sks *sks);

        void Hash(std::string m, element_t *res);
        void Hash2(element_t *m, element_t *res);
        

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
            ct ct0;
            std::vector<ct *> ct_y;
            element_t ct_prime;
            element_t ct_prime2;//这里我们新加，引入R1随机数
            element_t ct_prime3;//引入R2是随机数

            void Init(element_t *_Zn, element_t *_G, element_t *_H, element_t *_GT, const int rows){
                ct0.Init(_H);
                element_init_same_as(ct_prime, *_GT);
                for(int i = 0;i < rows;i++){
                    ct* ct_y_tmp = new ct();
                    ct_y_tmp->Init(_G);
                    ct_y.push_back(ct_y_tmp);
                }
                element_init_same_as(ct_prime2, *_GT);
                element_init_same_as(ct_prime3, *_GT);
            }
            ~ciphertext(){
                for(int i = 0;i < ct_y.size();i++){
                    ct_y[i]->~ct();
                }
                element_clear(ct_prime);
                element_clear(ct_prime2);
                element_clear(ct_prime3);
            }
        };


        struct PTC{
            element_t ct_prime;
            element_t ct_prime2;//这里我们新加，引入R1随机数
            element_t ct_prime3;//引入R2是随机数
            element_t ct_p1;//中间密文ct_p1
            element_t ct_p2;//中间密文ct_p2

            void Init(element_t *_Zn, element_t *_G, element_t *_H, element_t *_GT){
                element_init_same_as(ct_prime, *_GT);
                element_init_same_as(ct_prime2, *_GT);
                element_init_same_as(ct_prime3, *_GT);
                element_init_same_as(ct_p1, *_GT);
                element_init_same_as(ct_p2, *_GT);
            }
            ~PTC(){
                element_clear(ct_prime);
                element_clear(ct_prime2);
                element_clear(ct_prime3);
                element_clear(ct_p1);
                element_clear(ct_p2);
            }
        };

        struct TC
        {
            element_t ct_prime;
            element_t ct_prime2;
            element_t ct_prime3;
            element_t ct_pgama;

            void Init(element_t *_Zn, element_t *_G, element_t *_H, element_t *_GT){
                element_init_same_as(ct_prime, *_GT);
                element_init_same_as(ct_prime2, *_GT);
                element_init_same_as(ct_prime3, *_GT);
                element_init_same_as(ct_pgama, *_GT);
            }
            ~TC(){
                element_clear(ct_prime);
                element_clear(ct_prime2);
                element_clear(ct_prime3);
                element_clear(ct_pgama);
            }
        };
        
        
        void Encrypt(mpk *mpk, element_t *msg, std::string policy_str, ciphertext *ciphertext);
        void Encrypt(mpk *mpk, element_t *msg, std::string policy_str, element_t *s1, element_t *s2, ciphertext *ciphertext);
        void KeyGen(msk *msk, mpk *mpk, std::vector<std::string> *attr_list, TK *TK, HK *HK, DK *DK);
        void Transform1(mpk *mpk, ciphertext *ciphertext, TK *TK, PTC *PTC);
        void Transform2(mpk *mpk, PTC *PTC, HK *HK, TC *TC);
        void Decrypt(mpk *mpk, TC *TC, DK *DK, element_t *res);

        ~FAME_2OD();
};


#endif // CP_ABE_H