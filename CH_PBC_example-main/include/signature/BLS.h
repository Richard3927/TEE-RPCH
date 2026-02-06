#ifndef BLS_H
#define BLS_H

#include <pbc/pbc.h>
#include <string>
#include <utils/func.h>

class BLS{
    private:
        element_t *G1, *G2, *GT, *Zn;
        element_t tmp_G,tmp_G_2,tmp_G_3,tmp_G_4,tmp_H,tmp_H_2,tmp_H_3,tmp_GT,tmp_GT_2,tmp_GT_3,tmp_Zn,tmp_Zn_2,tmp_Zn_3;

    public:
        struct pp{
            element_t g;
            void Init(element_t *_G){
                element_init_same_as(g, *_G);
            }
            ~pp(){
                element_clear(g);
            }
        };
        struct pk{
            element_t y;
            void Init(element_t *_G){
                element_init_same_as(y, *_G);
            }
            ~pk(){
                element_clear(y);
            }
        };
        struct sk{
            element_t a;
            void Init(element_t *_Zn){
                element_init_same_as(a, *_Zn);
            }
            ~sk(){
                element_clear(a);
            }
        };
        struct signature{
            element_t sigma;
            void Init(element_t *_H){
                element_init_same_as(sigma, *_H);
            }
            ~signature(){
                element_clear(sigma);
            }
        };

        BLS(element_t *_G, element_t *_H, element_t *_GT, element_t *_Zn);

        void Setup(pp *pp);
        void Setup(pp *pp, element_t *g);

        void KeyGen(pp *pp, pk *pk, sk *sk);

        void H(std::string m, element_t *res);

        void Sign(sk *sk, std::string message, signature *signature);

        bool Verify(pp *pp, pk *pk, std::string message, signature *signature);

        ~BLS();
        
};

#endif  // BLS_H