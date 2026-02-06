#ifndef RPCH_2OD_H
#define RPCH_2OD_H

#include <stdexcept>  // 包含 std::invalid_argument
#include "utils/func.h"
#include <RSA/RSA.h>
#include <ABE/FAME-2OD.h>
#include <SE/AES.h>


class RPCH_2OD {
    protected:
        MyRSA rsa;
        FAME_2OD fame_2od;
        AES aes;

        mpz_t *n,e,d;
        element_t *G, *H, *GT, *Zn;
        element_t tmp_G,tmp_G_2,tmp_G_3,tmp_G_4,tmp_H,tmp_H_2,tmp_H_3,tmp_GT,tmp_GT_2,tmp_GT_3,tmp_Zn,tmp_Zn_2,tmp_Zn_3;
    
        int k;
        element_t u1,u2;
        element_t K;

    public:
        struct skCHET{
            mpz_t d1;
            void Init(){
                mpz_init(d1);
            }
            ~skCHET(){
                mpz_clear(d1);
            }
        };
        struct pkCHET{
            int k;
            mpz_t N1;
            mpz_t e;
            void Init(){
                mpz_inits(N1,e,NULL);
            }
            ~pkCHET(){
                mpz_clears(N1,e,NULL);
            }
        };
        struct TK{
            FAME_2OD::TK TKABE;
            void Init(element_t *_G, element_t *_H, int y_size){
                TKABE.Init(_G, _H, y_size);
            }
            ~TK(){
                TKABE.~TK();
            }
        };
        struct HK{
            FAME_2OD::HK HKABE;
            void Init(element_t *_Zn){
                HKABE.Init(_Zn);
            }
            ~HK(){
                HKABE.~HK();
            }
        };
        struct TC{
            FAME_2OD::TC TCABE;
            void Init(element_t *_Zn, element_t *_G, element_t *_H, element_t *_GT){
                TCABE.Init(_Zn, _G, _H, _GT);
            }
            ~TC(){
                TCABE.~TC();
            }
        };
        struct PTC{
            FAME_2OD::PTC PTCABE;
            void Init(element_t *_Zn, element_t *_G, element_t *_H, element_t *_GT){
                PTCABE.Init(_Zn, _G, _H, _GT);
            }
            ~PTC(){
                PTCABE.~PTC();
            }
        };
        struct skPCH{
            FAME_2OD::msk mskABE;
            RPCH_2OD::skCHET skCHET;
            void Init(element_t *_G, element_t *_H, element_t *_Zn){
                mskABE.Init(_G, _H, _Zn);
                skCHET.Init();
            }
            ~skPCH(){
                mskABE.~msk();
                skCHET.~skCHET();
            }
        };
        struct pkPCH{
            FAME_2OD::mpk mpkABE;
            RPCH_2OD::pkCHET pkCHET;
            void Init(element_t *_H, element_t *_GT){
                mpkABE.Init(_H, _GT);
                pkCHET.Init();
            }
            ~pkPCH(){
                mpkABE.~mpk();
                pkCHET.~pkCHET();
            }
        };
        struct sksPCH{
            RPCH_2OD::skCHET skCHET;
            FAME_2OD::DK DK;
            void Init(element_t *_Zn){
                skCHET.Init();
                DK.Init(_Zn);
            }
            ~sksPCH(){
                skCHET.~skCHET();
                DK.~DK();
            }
        };
        struct r{
            mpz_t r1,r2;
            void Init(){
                mpz_inits(r1,r2,NULL);
            }
            ~r(){
                mpz_clears(r1,r2,NULL);
            }
        };
        struct h{
            mpz_t h1,h2;
            mpz_t N2;
            FAME_2OD::ciphertext ct;
            mpz_t ct_;
            void Init(element_t *_Zn, element_t *_G, element_t *_H, element_t *_GT, int rows){
                mpz_inits(h1,h2,N2,ct_,NULL);
                ct.Init(_Zn,_G, _H, _GT, rows);
            }
            ~h(){
                mpz_clears(h1,h2,N2,ct_,NULL);
            }
        };


        RPCH_2OD(mpz_t *_n,mpz_t *_e, mpz_t *_d, element_t *_G, element_t *_H, element_t *_Zn, element_t *_GT);

        void PG(int k, skPCH *skPCH, pkPCH *pkPCH);

        void KG(skPCH *skPCH, pkPCH *pkPCH, std::vector<std::string> *attr_list, sksPCH *sksPCH,HK *HK, TK *TK);

        void H1(mpz_t *m, mpz_t *N1, mpz_t *N2, mpz_t * n, mpz_t *res);
        void H2(mpz_t *m, mpz_t *N1, mpz_t *N2, mpz_t * n, mpz_t *res);
        void H4(mpz_t *r, string A, element_t *u1, element_t *u2);

        void Hash(pkPCH *pkPCH, mpz_t *m, string policy_str, h *h, r *r);

        bool Check(pkPCH *pkPCH, mpz_t *m, h *h, r *r);
        void Transform1(pkPCH * pkPCH, TK *TK, h *h, PTC *PTC);
        void Transform2(pkPCH * pkPCH, HK *HK, PTC *PTC, TC *TC);
        void Forge(pkPCH * pkPCH, sksPCH *sksPCH, mpz_t *m, mpz_t *m_p, h *h, RPCH_2OD::r *r, RPCH_2OD::r *r_p, TC *TC);
        bool Verify(pkPCH *pkPCH, mpz_t *m_p, h *h, r *r_p);


        ~RPCH_2OD();
};


#endif //RPCH_2OD_H