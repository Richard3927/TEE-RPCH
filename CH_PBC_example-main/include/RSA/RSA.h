#ifndef MYRSA_H
#define MYRSA_H

#include <stdio.h>
#include <gmp.h>
#include <stdlib.h>
#include <time.h>
#include <utils/func.h>
#include <sys/time.h>

class MyRSA{
    private:
        mpz_t *n;
        mpz_t *e;
        mpz_t *d;
    
    public:
        MyRSA();
        MyRSA(mpz_t *n, mpz_t *e, mpz_t *d);

        void KeyGen(mpz_t *n, mpz_t *e, mpz_t *d, unsigned long k);

        void rsa_clear();

        void rsa_generate_keys(unsigned long bit_size);

        void rsa_generate_keys_2(unsigned long bit_size, unsigned long int k);
        void rsa_generate_keys_2(unsigned long bit_size, unsigned long int k, mpz_t *phi);

        void rsa_generate_keys_pqn(unsigned long bit_size, mpz_t *p, mpz_t *q, mpz_t *n);

        void rsa_generate_keys_with_e(unsigned long bit_size, mpz_t *e);

        void rsa_encrypt(mpz_t *ciphertext, const mpz_t *plaintext);

        void rsa_decrypt(mpz_t *plaintext, const mpz_t *ciphertext);

        mpz_t *getN();
        mpz_t *getE();
        mpz_t *getD();

};



#endif  //MYRSA_H