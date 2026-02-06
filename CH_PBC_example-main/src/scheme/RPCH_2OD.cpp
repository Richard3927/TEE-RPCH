#include <scheme/RPCH_2OD.h>

RPCH_2OD::RPCH_2OD(mpz_t *_n,mpz_t *_e, mpz_t *_d, element_t *_G, element_t *_H, element_t *_Zn, element_t *_GT) 
    : rsa(_n, _e, _d), fame_2od(_G, _H, _GT, _Zn){
    
    this->G = _G;
    this->H = _H;
    this->GT = _GT;
    this->Zn = _Zn;

    element_init_same_as(this->tmp_G, *this->G);
    element_init_same_as(this->tmp_G_2, *this->G);
    element_init_same_as(this->tmp_G_3, *this->G);
    element_init_same_as(this->tmp_G_4, *this->G);
    element_init_same_as(this->tmp_H, *this->H);
    element_init_same_as(this->tmp_H_2, *this->H);
    element_init_same_as(this->tmp_H_3, *this->H);
    element_init_same_as(this->tmp_GT, *this->GT);
    element_init_same_as(this->tmp_GT_2, *this->GT);
    element_init_same_as(this->tmp_GT_3, *this->GT);
    element_init_same_as(this->tmp_Zn, *this->Zn);
    element_init_same_as(this->tmp_Zn_2, *this->Zn);
    element_init_same_as(this->tmp_Zn_3, *this->Zn);

    element_init_same_as(this->u1, *this->Zn);
    element_init_same_as(this->u2, *this->Zn);
    element_init_same_as(this->K, *this->GT);
   
}

/**
 * input : k
 * output: skPCH, pkPCH
 */
void RPCH_2OD::PG(int k, skPCH *skPCH, pkPCH *pkPCH) {
    this->k = k;
    // e > N
    this->rsa.rsa_generate_keys_2(k, 1);
    // set d1
    mpz_set(skPCH->skCHET.d1, *(this->rsa.getD()));
    // set N1,e
    mpz_set(pkPCH->pkCHET.N1, *(this->rsa.getN()));
    mpz_set(pkPCH->pkCHET.e, *(this->rsa.getE()));

    this->fame_2od.Setup(&skPCH->mskABE, &pkPCH->mpkABE);
}

/**
 * input : skPCH, pkPCH, attr_list
 * output: sksPCH
 */
void RPCH_2OD::KG(skPCH *skPCH, pkPCH *pkPCH, std::vector<std::string> *attr_list, sksPCH *sksPCH, HK *HK, TK *TK) {
    this->fame_2od.KeyGen(&skPCH->mskABE, &pkPCH->mpkABE, attr_list, &TK->TKABE, &HK->HKABE,&sksPCH->DK); 
    mpz_set(sksPCH->skCHET.d1, skPCH->skCHET.d1);
}

void RPCH_2OD::H1(mpz_t *m, mpz_t *N1, mpz_t *N2, mpz_t * n, mpz_t *res){
    Hgsm_n_2(*m, *N1, *N2, *n, *res);
}
void RPCH_2OD::H2(mpz_t *m, mpz_t *N1, mpz_t *N2, mpz_t * n, mpz_t *res){
    Hgsm_n_2(*m, *N1, *N2, *n, *res);
}
/**
 * (u1,u2)<-H4((r,A))
 */
void RPCH_2OD::H4(mpz_t *r, string A, element_t *u1, element_t *u2){
    // r -> string
    string r_str = mpz_get_str(NULL, 10, *r);
    // str -> element_t
    element_from_hash(this->tmp_Zn, (unsigned char *)r_str.c_str(), r_str.length());
    element_from_hash(this->tmp_Zn_2, (unsigned char *)A.c_str(), A.length());
    Hm_1(this->tmp_Zn, *u1);
    Hm_1(this->tmp_Zn_2, *u2);
}


/**
 * input : pkPCH, m, policy_str
 * output: h, r
 */
void RPCH_2OD::Hash(pkPCH *pkPCH, mpz_t *m, string policy_str, h *h,r *r) {
    mpz_t tmp1, tmp2, rr, kk;
    mpz_inits(tmp1, tmp2, rr, kk, NULL);
    this->rsa.rsa_generate_keys_with_e(this->k, &pkPCH->pkCHET.e);

    // h.N2
    mpz_set(h->N2, *this->rsa.getN());
    
    // r1 ∈ ZN1*
    GenerateRandomInZnStar(r->r1, pkPCH->pkCHET.N1);
    // r2 ∈ ZN2*
    GenerateRandomInZnStar(r->r2, *this->rsa.getN());

    // h1 = H1(m,N1,N2)* r1^e mod N1
    H1(m, &pkPCH->pkCHET.N1, this->rsa.getN(), &pkPCH->pkCHET.N1, &tmp1);
    // r1^e mod N1
    mpz_powm(tmp2, r->r1, pkPCH->pkCHET.e, pkPCH->pkCHET.N1);
    mpz_mul(h->h1, tmp1, tmp2);
    mpz_mod(h->h1, h->h1, pkPCH->pkCHET.N1);
    // h2 = H2(m,N1,N2)* r2^e mod N2
    H2(m, &pkPCH->pkCHET.N1, this->rsa.getN(), this->rsa.getN(), &tmp1);
    // r2^e mod N2
    mpz_powm(tmp2, r->r2, pkPCH->pkCHET.e, *this->rsa.getN());
    mpz_mul(h->h2, tmp1, tmp2);
    mpz_mod(h->h2, h->h2, *this->rsa.getN());

    this->aes.KGen(256, &this->K);
    // (u1,u2)<-H4((r,A))
    H4(&rr, policy_str, &u1, &u2);


    this->fame_2od.Encrypt(&pkPCH->mpkABE, &this->K, policy_str, &u1, &u2, &h->ct);

    // ct_
    this->aes.Enc(&this->K, this->rsa.getD(), &h->ct_);

    mpz_clears(tmp1, tmp2, rr, kk, NULL);
}

/**
 * input : pkPCH, m, h, r
 * output: bool
 */
bool RPCH_2OD::Check(pkPCH *pkPCH, mpz_t *m, h *h, r *r) {
    mpz_t tmp1, tmp2, tmp3;
    mpz_inits(tmp1, tmp2, tmp3, NULL);
    // h1 = H1(m,N1,N2)* r1^e mod N1
    H1(m, &pkPCH->pkCHET.N1, &h->N2, &pkPCH->pkCHET.N1, &tmp1);
    // r1^e mod N1
    mpz_powm(tmp2, r->r1, pkPCH->pkCHET.e, pkPCH->pkCHET.N1);
    mpz_mul(tmp3, tmp1, tmp2);
    mpz_mod(tmp3, tmp3, pkPCH->pkCHET.N1);
    if(mpz_cmp(tmp3, h->h1) != 0){
        mpz_clears(tmp1, tmp2,tmp3, NULL);
        return false;
    }
    // h2 = H2(m,N1,N2)* r2^e mod N2
    H2(m, &pkPCH->pkCHET.N1, &h->N2, &h->N2, &tmp1);
    // r2^e mod N2
    mpz_powm(tmp2, r->r2, pkPCH->pkCHET.e, h->N2);
    mpz_mul(tmp3, tmp1, tmp2);
    mpz_mod(tmp3, tmp3, h->N2);
    if(mpz_cmp(tmp3, h->h2) != 0){
        mpz_clears(tmp1, tmp2,tmp3, NULL);
        return false;
    }
    mpz_clears(tmp1, tmp2, tmp3, NULL);
    return true;
}

/**
 * input : tk, h
 * output: ptc
 */
void RPCH_2OD::Transform1(pkPCH * pkPCH, TK *TK, h *h, PTC *PTC){
    fame_2od.Transform1(&pkPCH->mpkABE, &h->ct, &TK->TKABE, &PTC->PTCABE);
}
/**
 * input : hk,h
 * output: tc(etd)
 */
void RPCH_2OD::Transform2(pkPCH * pkPCH, HK *HK,PTC *PTC, TC *TC){
    fame_2od.Transform2(&pkPCH->mpkABE, &PTC->PTCABE, &HK->HKABE, &TC->TCABE);
}

/**
 * input : pkPCH, sksPCH, m, m', h, r
 * output: r'
 */
void RPCH_2OD::Forge(pkPCH * pkPCH, sksPCH *sksPCH, mpz_t *m, mpz_t *m_p, h *h, RPCH_2OD::r *r, RPCH_2OD::r *r_p, TC *TC) {
    mpz_t kk,rr,d2,x1,x1_p,y1,x2,x2_p,y2;
    mpz_inits(kk,rr,d2,x1,x1_p,y1,x2,x2_p,y2,NULL);

    fame_2od.Decrypt(&pkPCH->mpkABE, &TC->TCABE , &sksPCH->DK, &this->K);

    // DecSE(K, ct_) -> d2
    this->aes.Dec(&this->K, &h->ct_, &d2);

    // x1 = H1(m, N1, N2)
    H1(m, &pkPCH->pkCHET.N1, &h->N2, &pkPCH->pkCHET.N1, &x1);
    // x1' = H1(m', N1, N2)
    H1(m_p, &pkPCH->pkCHET.N1, &h->N2, &pkPCH->pkCHET.N1, &x1_p);
    // y1 = x1 r1^e mod N1
    mpz_powm(y1, r->r1, pkPCH->pkCHET.e, pkPCH->pkCHET.N1);
    mpz_mul(y1, x1, y1);
    mpz_mod(y1, y1, pkPCH->pkCHET.N1);
    // x2 = H2(m, N1, N2)
    H2(m, &pkPCH->pkCHET.N1, &h->N2, &h->N2, &x2);
    // x2' = H2(m', N1, N2)
    H2(m_p, &pkPCH->pkCHET.N1, &h->N2, &h->N2, &x2_p);
    // y2 = x2 r2^e mod N2
    mpz_powm(y2, r->r2, pkPCH->pkCHET.e, h->N2);
    mpz_mul(y2, x2, y2);
    mpz_mod(y2, y2, h->N2);
    // r1' = (y1(x1'^(-1)))^d1 mod N1
    mpz_invert(x1_p, x1_p, pkPCH->pkCHET.N1);
    mpz_mul(r_p->r1, y1, x1_p);
    mpz_mod(r_p->r1, r_p->r1, pkPCH->pkCHET.N1);
    mpz_powm(r_p->r1, r_p->r1, sksPCH->skCHET.d1, pkPCH->pkCHET.N1);
    // r2' = (y2(x2'^(-1)))^d2 mod N2
    mpz_invert(x2_p, x2_p, h->N2);
    mpz_mul(r_p->r2, y2, x2_p);
    mpz_mod(r_p->r2, r_p->r2, h->N2);
    mpz_powm(r_p->r2, r_p->r2, d2, h->N2);
  

    mpz_clears(kk,rr,d2,x1,x1_p,y1,x2,x2_p,y2,NULL);
}

/**
 * input : pkPCH, m', h, r'
 * output: bool
 */
bool RPCH_2OD::Verify(pkPCH *pkPCH, mpz_t *m_p, h *h, r *r_p) {
    return this->Check(pkPCH, m_p, h, r_p);
}


RPCH_2OD::~RPCH_2OD() {
   
}