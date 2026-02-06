#ifndef CH_KEF_F_CTZ_2010_H
#define CH_KEF_F_CTZ_2010_H

#include <stdio.h>
#include <gmp.h>
#include <utils/func.h>

class CH_KEF_F_CTZ_2010{
    private:
        int k;
        int fk;

    public:
        struct pk{
            mpz_t N;

            void Init(){
                mpz_init(N);
            }

            ~pk(){
                mpz_clear(N);
            }
        };

        struct sk{
            mpz_t p,q;

            void Init(){
                mpz_init(p);
                mpz_init(q);
            }

            ~sk(){
                mpz_clear(p);
                mpz_clear(q);
            }
        };

        CH_KEF_F_CTZ_2010();

        ~CH_KEF_F_CTZ_2010();

        void GenKey(int _k, pk *pk, sk *sk);

        void generate_prime(mpz_t *p, mpz_t *q);

        int f(int k);

        void Hash(pk *pk, mpz_t *L, mpz_t *m, mpz_t *r, mpz_t *b, mpz_t *h);

        void H(mpz_t *m, mpz_t *res, mpz_t *n);

        void Uforge(pk *pk,sk *sk, mpz_t *L, mpz_t *m, mpz_t *r, mpz_t *b, mpz_t *m_p, mpz_t *r_p, mpz_t *b_p);

        void Iforge(pk *pk, mpz_t *L, mpz_t *m, mpz_t *r, mpz_t *b, mpz_t *h, mpz_t *m_p, mpz_t *r_p, mpz_t *b_p, mpz_t *m_pp, mpz_t *r_pp, mpz_t *b_pp);

        bool Check(pk *pk, mpz_t *L, mpz_t *m, mpz_t *r, mpz_t *b, mpz_t *h);

        bool Verify(pk *pk, mpz_t *L, mpz_t *m, mpz_t *r, mpz_t *b, mpz_t *h);

        int getfk() const {return this->fk;}
};

#endif  //CH_KEF_F_CTZ_2010_H