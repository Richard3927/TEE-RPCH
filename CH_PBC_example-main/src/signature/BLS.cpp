#include <signature/BLS.h>

BLS::BLS(element_t *_G, element_t *_H, element_t *_GT, element_t *_Zn)
{
    this->G1 = _G;
    this->G2 = _H;
    this->GT = _GT;
    this->Zn = _Zn;

    element_init_same_as(this->tmp_G, *this->G1);
    element_init_same_as(this->tmp_G_2, *this->G1);
    element_init_same_as(this->tmp_G_3, *this->G1);
    element_init_same_as(this->tmp_G_4, *this->G1);
    element_init_same_as(this->tmp_H, *this->G2);
    element_init_same_as(this->tmp_H_2, *this->G2);
    element_init_same_as(this->tmp_H_3, *this->G2);
    element_init_same_as(this->tmp_GT, *this->GT);
    element_init_same_as(this->tmp_GT_2, *this->GT);
    element_init_same_as(this->tmp_GT_3, *this->GT);
    element_init_same_as(this->tmp_Zn, *this->Zn);
    element_init_same_as(this->tmp_Zn_2, *this->Zn);
    element_init_same_as(this->tmp_Zn_3, *this->Zn);
}

/**
 * @param pp: public parameters
 */
void BLS::Setup(pp *pp)
{
    element_random(pp->g);
}
/**
 * @param pp: public parameters
 * @param g: generator g
 */
void BLS::Setup(pp *pp, element_t *g)
{
    element_set(pp->g, *g);
}


/**
 * @param pp: public parameters
 * @param pk: public key
 * @param sk: secret key
 */
void BLS::KeyGen(pp *pp, pk *pk, sk *sk)
{
    element_random(sk->a);
    element_pow_zn(pk->y, pp->g, sk->a);
}

/**
 * @param m: message to hash
 * @param res: result of hash
 */
void BLS::H(std::string m, element_t *res)
{   
    Hm_1(m, *res);
}

/**
 * @param sk: secret key
 * @param message: message to sign
 * @param signature: signature of message
 */
void BLS::Sign(sk *sk, std::string message, signature *signature)
{   
    H(message, &tmp_H);
    element_pow_zn(signature->sigma, tmp_H, sk->a);
}

/**
 * @param pp: public parameters
 * @param pk: public key
 * @param message: message to verify
 * @param signature: signature of message
 */
bool BLS::Verify(pp *pp, pk *pk, std::string message, signature *signature)
{
    element_pairing(tmp_GT, pp->g, signature->sigma);
    H(message, &tmp_H);
    element_pairing(tmp_GT_2, pk->y, tmp_H);
    return element_cmp(tmp_GT, tmp_GT_2) == 0;
}

BLS::~BLS()
{
    element_clear(this->tmp_G);
    element_clear(this->tmp_G_2);
    element_clear(this->tmp_G_3);
    element_clear(this->tmp_G_4);
    element_clear(this->tmp_H);
    element_clear(this->tmp_H_2);
    element_clear(this->tmp_H_3);
    element_clear(this->tmp_GT);
    element_clear(this->tmp_GT_2);
    element_clear(this->tmp_GT_3);
    element_clear(this->tmp_Zn);
    element_clear(this->tmp_Zn_2);
    element_clear(this->tmp_Zn_3);
}
