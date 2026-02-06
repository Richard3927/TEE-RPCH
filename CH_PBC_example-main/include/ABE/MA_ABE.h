#ifndef MA_ABE_H
#define MA_ABE_H

#include <pbc/pbc.h>
#include <utils/func.h>
#include <vector>
#include <string>
#include <unordered_map>
#include <ABE/policy/policy_resolution.h>
#include <ABE/policy/policy_generation.h>

class MA_ABE{
    private:
        element_t *G, *H, *GT, *Zn;
        element_t tmp_G,tmp_G_2,tmp_G_3,tmp_G_4,tmp_H,tmp_H_2,tmp_H_3,tmp_GT,tmp_GT_2,tmp_GT_3,tmp_Zn,tmp_Zn_2,tmp_Zn_3;

        element_t z;

        unordered_map<unsigned long int, string> pai;  // π(i) -> attr

    public:
        struct gpk{
            element_t g;
            void Init(element_t *_G){
                element_init_same_as(g, *_G);
            }
            void setValues(element_t *_g){
                element_set(g, *_g);
            }
            void setValues(gpk *_gpk){
                element_set(g, _gpk->g);
            }
            ~gpk(){
                element_clear(g);
            }
        };

        struct pkTheta{
            string A;
            element_t pkTheta_1,pkTheta_2;
            void Init(element_t *_G, element_t *_GT){
                element_init_same_as(pkTheta_1, *_GT);
                element_init_same_as(pkTheta_2, *_G);
            }
            void setValues(string _A, element_t *_pkTheta_1, element_t *_pkTheta_2){
                A = _A;
                element_set(pkTheta_1, *_pkTheta_1);
                element_set(pkTheta_2, *_pkTheta_2);
            }
            void setValues(pkTheta *_pkTheta){
                A = _pkTheta->A;
                element_set(pkTheta_1, _pkTheta->pkTheta_1);
                element_set(pkTheta_2, _pkTheta->pkTheta_2);
            }
            ~pkTheta(){
                element_clear(pkTheta_1);
                element_clear(pkTheta_2);
            }
        };

        struct skTheta{
            element_t aTheta,yTheta;
            void Init(element_t *_Zn){
                element_init_same_as(aTheta, *_Zn);
                element_init_same_as(yTheta, *_Zn);
            }
            ~skTheta(){
                element_clear(aTheta);
                element_clear(yTheta);
            }
        };

        struct skgidA{
            string gid;
            string A;
            element_t skgidA_0,skgidA_1;
            void Init(element_t *_G){
                element_init_same_as(skgidA_0, *_G);
                element_init_same_as(skgidA_1, *_G);
            }
            void setValues(string _gid, string _A, element_t *_skgidA_0, element_t *_skgidA_1){
                gid = _gid;
                A = _A;
                element_set(skgidA_0, *_skgidA_0);
                element_set(skgidA_1, *_skgidA_1);
            }
            void setValues(skgidA *_skgidA){
                gid = _skgidA->gid;
                A = _skgidA->A;
                element_set(skgidA_0, _skgidA->skgidA_0);
                element_set(skgidA_1, _skgidA->skgidA_1);
            }
            ~skgidA(){
                element_clear(skgidA_0);
                element_clear(skgidA_1);
            }
        };

        struct ci{
            element_t ci_1,ci_2,ci_3,ci_4;
            void Init(element_t *_G, element_t *_GT){
                element_init_same_as(ci_1, *_GT);
                element_init_same_as(ci_2, *_G);
                element_init_same_as(ci_3, *_G);
                element_init_same_as(ci_4, *_G);
            }
            void setValues(element_t *_ci_1, element_t *_ci_2, element_t *_ci_3, element_t *_ci_4){
                element_set(ci_1, *_ci_1);
                element_set(ci_2, *_ci_2);
                element_set(ci_3, *_ci_3);
                element_set(ci_4, *_ci_4);
            }
            void setValues(ci *_ci){
                element_set(ci_1, _ci->ci_1);
                element_set(ci_2, _ci->ci_2);
                element_set(ci_3, _ci->ci_3);
                element_set(ci_4, _ci->ci_4);
            }
            ~ci(){
                element_clear(ci_1);
                element_clear(ci_2);
                element_clear(ci_3);
                element_clear(ci_4); 
            }
        };

        struct ciphertext{
            string policy;
            element_t c0;
            std::vector<MA_ABE::ci *> ci;
            void Init(element_t *_G, element_t *_GT, int rows){
                element_init_same_as(c0, *_GT);
                for(int i = 0;i < rows;i++){
                    MA_ABE::ci* ci_tmp = new MA_ABE::ci();
                    ci_tmp->Init(_G, _GT);
                    ci.push_back(ci_tmp);
                }
            }
            void setValues(string _policy, element_t *_c0, std::vector<MA_ABE::ci *> *_ci){
                policy = _policy;
                element_set(c0, *_c0);
                for(int i=0;i<_ci->size();i++){
                    ci[i]->setValues(_ci->at(i));
                }
            }
            void setValues(ciphertext *_c){
                policy = _c->policy;
                element_set(c0, _c->c0);
                for(int i=0;i<_c->ci.size();i++){
                    ci[i]->setValues(_c->ci[i]);
                }
            }
            ~ciphertext(){
                for(int i = 0;i < ci.size();i++){
                    ci[i]->~ci();
                }
                element_clear(c0);
            }
        };

        MA_ABE(element_t *_G, element_t *_H, element_t *_GT, element_t *_Zn);

        void HGID(bool bit, string gid, element_t *res);
        void Hu(string u, element_t *res);

        void GlobalSetup(gpk *gpk);
        void GlobalSetup(gpk *gpk, element_t *g);

        void AuthSetup(gpk *gpk, string A, pkTheta *pkTheta, skTheta *skTheta);

        void KeyGen(gpk *gpk, skTheta *skTheta, string gid, string A, skgidA *skgidA);        

        void Encrypt(gpk *gpk, vector<pkTheta *> *pkThetas, string polocy, element_t *m, ciphertext *C);

        void Decrypt(vector<MA_ABE::skgidA *> *skgidAs, ciphertext *C, element_t *res);

        ~MA_ABE();
};


#endif // MA_ABE_H