#ifndef RABE_TMM_H
#define RABE_TMM_H

#include <pbc/pbc.h>
#include <utils/func.h>
#include <vector>
#include <string>
#include <unordered_map>
#include <ABE/policy/policy_resolution.h>
#include <ABE/policy/policy_generation.h>
#include <ABE/data_structure/binary_tree_RABE.h>

class RABE_TMM{
    protected:
        element_t *G, *H, *GT, *Zn;
        element_t tmp_G,tmp_G_2,tmp_G_3,tmp_G_4,tmp_H,tmp_H_2,tmp_H_3,tmp_GT,tmp_GT_2,tmp_GT_3, tmp_GT_4,tmp_Zn,tmp_Zn_2,tmp_Zn_3;

        element_t d1,d2,d3;
        element_t r1,r2;
        element_t b1r1a1,b1r1a2,b2r2a1,b2r2a2,r1r2a1,r1r2a2;
        element_t s1,s2;

        unordered_map<unsigned long int, string> pai;  // π(i) -> attr
        unordered_map<string, unsigned long int> attr_map;  // attr -> index of attr_list
        string policy_str;
    
    public:
        struct mpk
        {
            element_t g,h,H1,H2,T1,T2;

            void Init(element_t *_G, element_t *_H, element_t *_GT){
                element_init_same_as(g, *_G);
                element_init_same_as(h, *_H);
                element_init_same_as(H1, *_H);
                element_init_same_as(H2, *_H);
                element_init_same_as(T1, *_GT);
                element_init_same_as(T2, *_GT);
            }
            ~mpk(){
                element_clear(g);
                element_clear(h);
                element_clear(H1);
                element_clear(H2);
                element_clear(T1);
                element_clear(T2);
            }
        };

        struct msk
        {
            element_t a1,a2,b1,b2,g_pow_d1,g_pow_d2,g_pow_d3;

            void Init(element_t *_G, element_t *_Zn){
                element_init_same_as(a1, *_Zn);
                element_init_same_as(a2, *_Zn);
                element_init_same_as(b1, *_Zn);
                element_init_same_as(b2, *_Zn);
                element_init_same_as(g_pow_d1, *_G);
                element_init_same_as(g_pow_d2, *_G);
                element_init_same_as(g_pow_d3, *_G);
            }
            ~msk(){
                element_clear(a1);
                element_clear(a2);
                element_clear(b1);
                element_clear(b2);
                element_clear(g_pow_d1);
                element_clear(g_pow_d2);
                element_clear(g_pow_d3);
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

        struct sk_prime{
            sk sk_prime;
            binary_tree_node_RABE *theta;

            void Init(element_t *_G){
                sk_prime.Init(_G);
            }
        };

        struct skid{
            sk sk0;
            std::vector<sk *> sk_y;
            std::vector<RABE_TMM::sk_prime *> sk_prime;
            
            void Init(element_t *_G, element_t *_H, int y_size){
                sk0.Init(_H);
                for(int i = 0;i < y_size;i++){
                    sk* sk_y_tmp = new sk();
                    sk_y_tmp->Init(_G);
                    sk_y.push_back(sk_y_tmp);
                }
            }
            ~skid(){
                for(int i = 0;i < sk_y.size();i++){
                    sk_y[i]->~sk();
                }
                for(int i = 0;i < sk_prime.size();i++){
                    sk_prime[i]->~sk_prime();
                }
            }
        };

        struct revokedPreson{
            element_t id;
            time_t time;

            void Init(element_t *_Zn){
                element_init_same_as(id, *_Zn);
            }
            ~revokedPreson(){
                element_clear(id);
                std::cout << "revokedPreson 被销毁" << std::endl;
            }
        };



        struct kuTheta{
            binary_tree_node_RABE *theta;
            element_t ku_theta_1;
            element_t ku_theta_2;

            void Init(element_t *_G, element_t *_H){
                element_init_same_as(ku_theta_1, *_G);
                element_init_same_as(ku_theta_2, *_H);
            }
            ~kuTheta(){
                element_clear(ku_theta_1);
                element_clear(ku_theta_2);
            }
        };

        struct kut{
            time_t t;
            std::vector<kuTheta *> ku_theta;

            ~kut(){
                for(int i = 0;i < ku_theta.size();i++){
                    ku_theta[i]->~kuTheta();
                }
            }
        };

        

        struct dkidt{
            time_t t;
            sk sk0;
            std::vector<sk *> sk_y;
            sk sk_prime;
            element_t skt1;  // sk(t,1)

            void Init(element_t *_G, element_t *_H, int y_size){
                sk0.Init(_H);
                sk_prime.Init(_G);
                element_init_same_as(skt1, *_H);
            }
            ~dkidt(){
                element_clear(skt1);
                for(int i = 0;i < sk_y.size();i++){
                    sk_y[i]->~sk();
                }
            }
        };

        struct ct0{
            element_t ct0_1,ct0_2,ct0_3,ct0_4;

            void Init(element_t *_G,element_t *_H){
                element_init_same_as(ct0_1, *_H);
                element_init_same_as(ct0_2, *_H);
                element_init_same_as(ct0_3, *_H);
                element_init_same_as(ct0_4, *_G);
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
            time_t t;
            RABE_TMM::ct0 ct0;
            std::vector<ct *> ct_y;
            element_t ct_prime;

            void Init(element_t *_G, element_t *_H, element_t *_Zn, int rows){
                ct0.Init(_G, _H);
                element_init_same_as(ct_prime, *_Zn);
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
                element_clear(ct_prime);
            }
        };

        
        
        
        RABE_TMM(element_t *_G, element_t *_H, element_t *_GT, element_t *_Zn);

        ~RABE_TMM();

        void Setup(int n, mpk *mpk, msk *msk, vector<revokedPreson *> *rl, binary_tree_RABE *&st);

        void Hash(std::string m, element_t *res);
        void Hash(element_t *m, element_t *res);

        void KGen(mpk *mpk, msk *msk, binary_tree_RABE *st, element_t *id, std::vector<std::string> *attr_list, skid *skid);

        vector<binary_tree_node_RABE *> KUNodes(binary_tree_RABE *st, vector<revokedPreson *> *rl, time_t t);

        void KUpt(mpk *mpk, binary_tree_RABE *st, vector<revokedPreson *> *rl, time_t t, kut *kut);

        void DKGen(mpk *mpk, skid *skid, kut *kut, dkidt *dkidt);

        void Enc(mpk *mpk, element_t *msg, std::string policy_str,time_t t, element_t *s1, element_t *s2, ciphertext *ciphertext);

        void Dec(mpk *mpk, ciphertext *ciphertext, dkidt *dkidt, element_t *res);

        void Rev(vector<revokedPreson *> *rl, element_t *id, time_t t);
};

#endif  // RABE_TMM_H