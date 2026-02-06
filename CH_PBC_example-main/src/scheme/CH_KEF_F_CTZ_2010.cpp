#include <scheme/CH_KEF_F_CTZ_2010.h>

CH_KEF_F_CTZ_2010::CH_KEF_F_CTZ_2010() {
 
}

/**
 * input: k
 * output: pk, sk
 */
void CH_KEF_F_CTZ_2010::GenKey(int _k, pk *pk, sk *sk) {
    // set k
    this->k = _k;
    // set fk
    this->fk = this->f(_k);

    // Generate two primes p and q, p=q=3mod4
    this->generate_prime(&sk->p, &sk->q);
    gmp_printf("Prime p = %Zd\n", sk->p);
    gmp_printf("Prime q = %Zd\n", sk->q);

    // N = pq
    mpz_mul(pk->N, sk->p, sk->q);
    gmp_printf("Public key N = %Zd\n", pk->N);
}

/**
 * Generate prime p,q s.t. p = q = 3 mod 4
 * input: p,q
 * output: p,q
 */
void CH_KEF_F_CTZ_2010::generate_prime(mpz_t *p, mpz_t *q) {
    GenerateRandomWithLength(*p, 512);
    while (1) {
        mpz_nextprime(*p, *p);    
        if (mpz_fdiv_ui(*p, 4) == 3) {
            break;
        }
    }
    GenerateRandomWithLength(*q, 512);
    while (1) {
        mpz_nextprime(*q, *q);    
        if (mpz_fdiv_ui(*q, 4) == 3) {
            break;
        }
    }
}

/**
 * a super-logarithmic function
 * f(k) = 
 * input: k
 * output: int
 */
int CH_KEF_F_CTZ_2010::f(int k) {
    // TODO
    return 1024;
}


/**
 * input: pk, L, m, r, b
 * output: h
 */
void CH_KEF_F_CTZ_2010::Hash(pk *pk, mpz_t *L, mpz_t *m, mpz_t *r, mpz_t *b, mpz_t *h) {
    // random r ∈ ZN
    gmp_randstate_t state;
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, time(NULL));
    mpz_urandomm(*r, state, pk->N);
    gmp_printf("r = %Zd\n", *r);

    // random b ∈ {-1,1}
    gmp_randseed_ui(state, time(NULL));
    mpz_urandomb(*b, state, 1);
    if (mpz_cmp_ui(*b, 0) == 0) {
        mpz_set_si(*b, -1);
    }else{
        mpz_set_si(*b, 1);
    }
    gmp_printf("b = %Zd\n", *b);

    // J = H(L)
    mpz_t J;
    mpz_init(J);
    this->H(L, &J, &pk->N);

    // h = b (J^m) (r^(2^fk)) mod N
    mpz_t J_pow_m, fk, mpz_two,two_pow_fk, r_pow_two_pow_fk;
    mpz_inits(J_pow_m, fk, mpz_two,two_pow_fk, r_pow_two_pow_fk,NULL);
    mpz_powm(J_pow_m, J, *m, pk->N);
    // fk
    mpz_set_ui(fk, this->fk);
    // 2^fk
    mpz_set_ui(mpz_two, 2);
    mpz_powm(two_pow_fk, mpz_two, fk, pk->N);
    // r^(2^fk)
    mpz_powm(r_pow_two_pow_fk, *r, two_pow_fk, pk->N);
    // h = b (J^m) (r^(2^fk)) mod N
    mpz_mul(*h, J_pow_m, r_pow_two_pow_fk);
    mpz_mul(*h, *h, *b);
    mpz_mod(*h, *h, pk->N);

    mpz_clears(J_pow_m, fk, mpz_two,two_pow_fk, r_pow_two_pow_fk,NULL);
    mpz_clear(J);
    gmp_randclear(state);
}

/**
 * Hash function:  H:{0,1}*->ZN*[+1]
 */
void CH_KEF_F_CTZ_2010::H(mpz_t *m, mpz_t *res, mpz_t *n){
    Hm_n(*m, *res, *n);
}

/**
 * input: pk,sk, L, m, r, b, m_p
 * output: r_p, b_p
 */
void CH_KEF_F_CTZ_2010::Uforge(pk *pk,sk *sk, mpz_t *L, mpz_t *m, mpz_t *r, mpz_t *b, mpz_t *m_p, mpz_t *r_p, mpz_t *b_p) {
    mpz_t B,H_L,fk,two_pow_fk,tmp, mpz_two,m_sub_m_p,B_pow;
    mpz_inits(B,H_L,fk,two_pow_fk,tmp,mpz_two,m_sub_m_p,B_pow,NULL);

    // m - m_p
    mpz_sub(m_sub_m_p, *m, *m_p);

    // B = |H(L)|^(1/(2^f(k)))
    // H(L)
    this->H(L, &H_L, &pk->N);
    // judge if H(L) ∈ QRN
    int legendre = mpz_legendre(H_L, pk->N);
    printf("legendre = %d\n", legendre);
    if (legendre == 1) {
        // b_p = b
        mpz_set(*b_p, *b);
    } else {
        // H(L) = -H(L)
        mpz_neg(H_L, H_L);

        // b * (-1)^(m-m_p)

        // m_sub_m_p ∈ even
        if (mpz_even_p(m_sub_m_p)) {
            gmp_printf("m_sub_m_p = %Zd\n", m_sub_m_p);
            // b_p = b
            mpz_set(*b_p, *b);
        } else {
            // b_p = -b
            mpz_neg(*b_p, *b);
        }
    }

    // fk
    mpz_set_ui(fk, this->fk);
    // 2^fk
    mpz_set_ui(mpz_two, 2);
    mpz_powm(two_pow_fk, mpz_two, fk, pk->N);
    // 1/(2^fk)
    // TODO
    // !!! B = |H(L)|^(1/(2^f(k)))  , B^(2^(f(k))) != |H(L)|
    mpz_invert(tmp, two_pow_fk, pk->N);
    // B = |H(L)|^(1/(2^f(k)))
    mpz_powm(B, H_L, tmp, pk->N);

    // r_p = r * B^(m-m_p)  mod N
    // B^(m-m_p)
    mpz_powm(B_pow, B, m_sub_m_p, pk->N);
    // r_p = r * B^(m-m_p)  mod N
    mpz_mul(*r_p, *r, B_pow);
    mpz_mod(*r_p, *r_p, pk->N);

    mpz_clears(B,H_L,fk,two_pow_fk,tmp,mpz_two,m_sub_m_p,B_pow,NULL);
}

/**
 * input: pk, L, m, r, b, h
 * ouput: bool
 */
bool CH_KEF_F_CTZ_2010::Check(pk *pk, mpz_t *L, mpz_t *m, mpz_t *r, mpz_t *b, mpz_t *h){
    // J = H(L)
    mpz_t J;
    mpz_init(J);
    this->H(L, &J, &pk->N);

    // h = b (J^m) (r^(2^fk)) mod N
    mpz_t J_pow_m, fk, mpz_two,two_pow_fk, r_pow_two_pow_fk;
    mpz_inits(J_pow_m, fk, mpz_two,two_pow_fk, r_pow_two_pow_fk,NULL);
    mpz_powm(J_pow_m, J, *m, pk->N);
    // fk
    mpz_set_ui(fk, this->fk);
    // 2^fk
    mpz_set_ui(mpz_two, 2);
    mpz_powm(two_pow_fk, mpz_two, fk, pk->N);
    // r^(2^fk)
    mpz_powm(r_pow_two_pow_fk, *r, two_pow_fk, pk->N);
    // h = b (J^m) (r^(2^fk)) mod N
    mpz_t tmp_h;
    mpz_init(tmp_h);
    mpz_mul(tmp_h, J_pow_m, r_pow_two_pow_fk);
    mpz_mul(tmp_h, tmp_h, *b);
    mpz_mod(tmp_h, tmp_h, pk->N);

    gmp_printf("h = %Zd\n", *h);
    gmp_printf("tmp_h = %Zd\n", tmp_h);

    if (mpz_cmp(tmp_h, *h) == 0) {
        mpz_clears(J_pow_m, fk, mpz_two,two_pow_fk, r_pow_two_pow_fk,NULL);
        mpz_clear(J);
        mpz_clear(tmp_h);
        return true;
    } else {
        mpz_clears(J_pow_m, fk, mpz_two,two_pow_fk, r_pow_two_pow_fk,NULL);
        mpz_clear(J);
        mpz_clear(tmp_h);
        return false;
    }
}

/**
 * input: pk, L, m, r, b, h, m_p, r_p, b_p, m_pp
 * output: r_pp, b_pp
 */
void CH_KEF_F_CTZ_2010::Iforge(pk *pk, mpz_t *L, mpz_t *m, mpz_t *r, mpz_t *b, mpz_t *h, mpz_t *m_p, mpz_t *r_p, mpz_t *b_p, mpz_t *m_pp, mpz_t *r_pp, mpz_t *b_pp){
    // 2^s = gcd(m-m_p, 2^fk)
    mpz_t two_pow_s, m_sub_m_p, two_pow_fk,mpz_two,fk, two_pow_fk_sub_s,tmp_invert;
    mpz_inits(two_pow_s, m_sub_m_p, two_pow_fk, mpz_two,fk,two_pow_fk_sub_s,tmp_invert,NULL);
    // m-m_p
    mpz_sub(m_sub_m_p, *m, *m_p);
    // fk
    mpz_set_ui(fk, this->fk);
    // 2^fk
    mpz_set_ui(mpz_two, 2);
    mpz_powm(two_pow_fk, mpz_two, fk, pk->N);
    // 2^s = gcd(m-m_p, 2^fk)
    mpz_gcd(two_pow_s, m_sub_m_p, two_pow_fk);

    // theta = |H(L)|^(1/(2^(fk-s)))
    // (2^fk) / (2^s)
    mpz_div(two_pow_fk_sub_s, two_pow_fk, two_pow_s);
    // 1/(2^(fk-s))
    mpz_invert(tmp_invert, two_pow_fk_sub_s, pk->N);

    // H(L)
    mpz_t H_L;
    mpz_inits(H_L, NULL);
    this->H(L, &H_L, &pk->N);
    // judge if H(L) ∈ QRN
    int legendre = mpz_legendre(H_L, pk->N);
    if (legendre == 1) {
        // b_pp = b
        mpz_set(*b_pp, *b);
    } else {
        // H(L) = -H(L)
        mpz_neg(H_L, H_L);

        // b * (-1)^(m_p-m_pp)
        mpz_t m_p_sub_m_pp;
        mpz_init(m_p_sub_m_pp);
        mpz_sub(m_p_sub_m_pp, *m_p, *m_pp);
        // m_sub_m_p ∈ even
        if (mpz_even_p(m_p_sub_m_pp)) {
            // b_pp = b_p
            mpz_set(*b_pp, *b_p);
        } else {
            // b_pp = -b_p
            mpz_neg(*b_pp, *b_p);
        }
        mpz_clear(m_p_sub_m_pp);
    }
    
    mpz_t theta,m_p_sub_m_pp,mpz_tmp_2;
    mpz_inits(theta,m_p_sub_m_pp,mpz_tmp_2,NULL);
    // theta = |H(L)|^(1/(2^(fk-s)))
    mpz_powm(theta, H_L, tmp_invert, pk->N);

    // r_pp = r_p * theta^((2^(-s))*(m_p-m_pp)) mod N
    // 2^(-s)
    mpz_invert(two_pow_s, two_pow_s, pk->N);
    // (m_p-m_pp)
    mpz_sub(m_p_sub_m_pp, *m_p, *m_pp);
    // (2^(-s))*(m_p-m_pp)
    mpz_mul(mpz_tmp_2, two_pow_s, m_p_sub_m_pp);
    // r_pp = r_p * theta^((2^(-s))*(m_p-m_pp)) mod N
    mpz_powm(*r_pp, theta, mpz_tmp_2, pk->N);
    mpz_mul(*r_pp, *r_p, *r_pp);
    mpz_mod(*r_pp, *r_pp, pk->N);
}

/**
 * input: pk, L, m, r, b, h
 * output: bool
 */
bool CH_KEF_F_CTZ_2010::Verify(pk *pk, mpz_t *L, mpz_t *m, mpz_t *r, mpz_t *b, mpz_t *h){
    return this->Check(pk, L, m, r, b, h);
}

CH_KEF_F_CTZ_2010::~CH_KEF_F_CTZ_2010() {
 
}