#include <ABE/FAME-OD.h>

#include <stdexcept>

FAME_OD::FAME_OD(element_t* _G, element_t* _H, element_t* _GT, element_t* _Zn) {
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
    element_init_same_as(this->tmp_D_1, *this->Zn);
    element_init_same_as(this->tmp_D_2, *this->Zn);
    element_init_same_as(this->tmp_D_3, *this->Zn);

    element_init_same_as(this->d1, *this->Zn);
    element_init_same_as(this->d2, *this->Zn);
    element_init_same_as(this->d3, *this->Zn);

    element_init_same_as(this->sigma, *this->Zn);
    element_init_same_as(this->sigma_y, *this->Zn);

    element_init_same_as(this->r1, *this->Zn);
    element_init_same_as(this->r2, *this->Zn);

    element_init_same_as(this->R_1, *this->GT);
    element_init_same_as(this->R_2, *this->GT);

    element_init_same_as(this->b1r1a1, *this->Zn);
    element_init_same_as(this->b1r1a2, *this->Zn);
    element_init_same_as(this->b2r2a1, *this->Zn);
    element_init_same_as(this->b2r2a2, *this->Zn);
    element_init_same_as(this->r1r2a1, *this->Zn);
    element_init_same_as(this->r1r2a2, *this->Zn);

    element_init_same_as(this->s1, *this->Zn);
    element_init_same_as(this->s2, *this->Zn);
}

/**
 * output: mpk, msk
 */
void FAME_OD::Setup(msk* msk, mpk* mpk) {
    element_random(msk->g);
    element_random(msk->h);
    element_random(msk->a1);
    element_random(msk->a2);
    element_random(msk->b1);
    element_random(msk->b2);

    element_random(this->d1);
    element_pow_zn(msk->g_pow_d1, msk->g, this->d1);
    element_random(this->d2);
    element_pow_zn(msk->g_pow_d2, msk->g, this->d2);
    element_random(this->d3);
    element_pow_zn(msk->g_pow_d3, msk->g, this->d3);

    element_set(mpk->h, msk->h);
    element_pow_zn(mpk->H1, msk->h, msk->a1);
    element_pow_zn(mpk->H2, msk->h, msk->a2);

    // T1 = e(g, h)^(d1*a1+d3)
    element_mul(this->tmp_Zn, this->d1, msk->a1);
    element_add(this->tmp_Zn_2, this->tmp_Zn, this->d3);
    element_pairing(this->tmp_GT, msk->g, msk->h);
    element_pow_zn(mpk->T1, this->tmp_GT, this->tmp_Zn_2);

    // T2 = e(g, h)^(d2*a2+d3)
    element_mul(this->tmp_Zn, this->d2, msk->a2);
    element_add(this->tmp_Zn_2, this->tmp_Zn, this->d3);
    element_pow_zn(mpk->T2, this->tmp_GT, this->tmp_Zn_2);
}

/**
 * Generate a key for a list of attributes.
 * input: msk, mpk, attr
 * output: (TK, DK)
 */
void FAME_OD::KeyGen(msk* msk, mpk* mpk, std::vector<std::string>* attr_list, TK* TK, DK* DK) {
    element_random(this->r1);
    element_random(this->r2);
    element_random(DK->beta);

    // sk0 = (h^(b1r1/β), h^(b2r2/β), h^((r1+r2)/β))
    element_mul(this->tmp_Zn, msk->b1, this->r1);
    element_div(this->tmp_Zn, this->tmp_Zn, DK->beta);
    element_pow_zn(TK->TK1->sk0.sk_1, mpk->h, this->tmp_Zn);
    // (b1 * r1) / (a1 β)
    element_div(this->b1r1a1, this->tmp_Zn, msk->a1);
    // (b1 * r1) / (a2 β)
    element_div(this->b1r1a2, this->tmp_Zn, msk->a2);

    element_mul(this->tmp_Zn, msk->b2, this->r2);
    element_div(this->tmp_Zn, this->tmp_Zn, DK->beta);
    element_pow_zn(TK->TK1->sk0.sk_2, mpk->h, this->tmp_Zn);
    // (b2 * r2) / (a1 β)
    element_div(this->b2r2a1, this->tmp_Zn, msk->a1);
    // (b2 * r2) / (a2 β)
    element_div(this->b2r2a2, this->tmp_Zn, msk->a2);

    element_add(this->tmp_Zn, this->r1, this->r2);
    element_div(this->tmp_Zn, this->tmp_Zn, DK->beta);
    element_pow_zn(TK->TK1->sk0.sk_3, mpk->h, this->tmp_Zn);
    // (r1 + r2) / (a1 β)
    element_div(this->r1r2a1, this->tmp_Zn, msk->a1);
    // (r1 + r2) / (a2 β)
    element_div(this->r1r2a2, this->tmp_Zn, msk->a2);

    // compute sk_y
    for (int i = 0; i < (int)attr_list->size(); i++) {
        attr_map[attr_list->at(i)] = i;
        element_random(this->sigma_y);

        // tmp_Zn = sigma_y / beta
        element_div(this->tmp_Zn, this->sigma_y, DK->beta);

        // t = 1
        std::string y11 = attr_list->at(i) + "1" + "1";
        this->Hash(y11, &this->tmp_G);
        element_pow_zn(this->tmp_G, this->tmp_G, this->b1r1a1);
        std::string y21 = attr_list->at(i) + "2" + "1";
        this->Hash(y21, &this->tmp_G_2);
        element_pow_zn(this->tmp_G_2, this->tmp_G_2, this->b2r2a1);
        std::string y31 = attr_list->at(i) + "3" + "1";
        this->Hash(y31, &this->tmp_G_3);
        element_pow_zn(this->tmp_G_3, this->tmp_G_3, this->r1r2a1);
        // g^(sigma_y / (a1 beta))
        element_div(this->tmp_Zn_2, this->tmp_Zn, msk->a1);
        element_pow_zn(this->tmp_G_4, msk->g, this->tmp_Zn_2);
        element_mul(TK->TK1->sk_y[i]->sk_1, this->tmp_G, this->tmp_G_2);
        element_mul(TK->TK1->sk_y[i]->sk_1, TK->TK1->sk_y[i]->sk_1, this->tmp_G_3);
        element_mul(TK->TK1->sk_y[i]->sk_1, TK->TK1->sk_y[i]->sk_1, this->tmp_G_4);

        // t = 2
        std::string y12 = attr_list->at(i) + "1" + "2";
        this->Hash(y12, &this->tmp_G);
        element_pow_zn(this->tmp_G, this->tmp_G, this->b1r1a2);
        std::string y22 = attr_list->at(i) + "2" + "2";
        this->Hash(y22, &this->tmp_G_2);
        element_pow_zn(this->tmp_G_2, this->tmp_G_2, this->b2r2a2);
        std::string y32 = attr_list->at(i) + "3" + "2";
        this->Hash(y32, &this->tmp_G_3);
        element_pow_zn(this->tmp_G_3, this->tmp_G_3, this->r1r2a2);
        // g^(sigma_y / (a2 beta))
        element_div(this->tmp_Zn_2, this->tmp_Zn, msk->a2);
        element_pow_zn(this->tmp_G_4, msk->g, this->tmp_Zn_2);
        element_mul(TK->TK1->sk_y[i]->sk_2, this->tmp_G, this->tmp_G_2);
        element_mul(TK->TK1->sk_y[i]->sk_2, TK->TK1->sk_y[i]->sk_2, this->tmp_G_3);
        element_mul(TK->TK1->sk_y[i]->sk_2, TK->TK1->sk_y[i]->sk_2, this->tmp_G_4);

        // sk_y3 = g^(-sigma_y / beta)
        element_neg(this->tmp_Zn, this->tmp_Zn);
        element_pow_zn(TK->TK1->sk_y[i]->sk_3, msk->g, this->tmp_Zn);
    }

    // sk_prime
    element_random(this->sigma);
    // tmp_Zn = sigma / beta
    element_div(this->tmp_Zn, this->sigma, DK->beta);

    // t = 1: g^(d1/beta) * H(0111)^{b1r1/(a1 beta)} * H(0121)^{b2r2/(a1 beta)} * H(0131)^{(r1+r2)/(a1 beta)} * g^{sigma/(a1 beta)}
    element_set(this->tmp_D_1, this->d1);
    element_div(this->tmp_D_1, this->tmp_D_1, DK->beta);
    element_pow_zn(TK->TK1->sk_prime.sk_1, msk->g, this->tmp_D_1);
    std::string y0111 = "0111";
    this->Hash(y0111, &this->tmp_G);
    element_pow_zn(this->tmp_G, this->tmp_G, this->b1r1a1);
    std::string y0121 = "0121";
    this->Hash(y0121, &this->tmp_G_2);
    element_pow_zn(this->tmp_G_2, this->tmp_G_2, this->b2r2a1);
    std::string y0131 = "0131";
    this->Hash(y0131, &this->tmp_G_3);
    element_pow_zn(this->tmp_G_3, this->tmp_G_3, this->r1r2a1);
    element_div(this->tmp_Zn_2, this->tmp_Zn, msk->a1);
    element_pow_zn(this->tmp_G_4, msk->g, this->tmp_Zn_2);
    element_mul(TK->TK1->sk_prime.sk_1, TK->TK1->sk_prime.sk_1, this->tmp_G);
    element_mul(TK->TK1->sk_prime.sk_1, TK->TK1->sk_prime.sk_1, this->tmp_G_2);
    element_mul(TK->TK1->sk_prime.sk_1, TK->TK1->sk_prime.sk_1, this->tmp_G_3);
    element_mul(TK->TK1->sk_prime.sk_1, TK->TK1->sk_prime.sk_1, this->tmp_G_4);

    // t = 2: g^(d2/beta) * ... * g^{sigma/(a2 beta)}
    element_set(this->tmp_D_2, this->d2);
    element_div(this->tmp_D_2, this->tmp_D_2, DK->beta);
    element_pow_zn(TK->TK1->sk_prime.sk_2, msk->g, this->tmp_D_2);
    std::string y0112 = "0112";
    this->Hash(y0112, &this->tmp_G);
    element_pow_zn(this->tmp_G, this->tmp_G, this->b1r1a2);
    std::string y0122 = "0122";
    this->Hash(y0122, &this->tmp_G_2);
    element_pow_zn(this->tmp_G_2, this->tmp_G_2, this->b2r2a2);
    std::string y0132 = "0132";
    this->Hash(y0132, &this->tmp_G_3);
    element_pow_zn(this->tmp_G_3, this->tmp_G_3, this->r1r2a2);
    element_div(this->tmp_Zn_2, this->tmp_Zn, msk->a2);
    element_pow_zn(this->tmp_G_4, msk->g, this->tmp_Zn_2);
    element_mul(TK->TK1->sk_prime.sk_2, TK->TK1->sk_prime.sk_2, this->tmp_G);
    element_mul(TK->TK1->sk_prime.sk_2, TK->TK1->sk_prime.sk_2, this->tmp_G_2);
    element_mul(TK->TK1->sk_prime.sk_2, TK->TK1->sk_prime.sk_2, this->tmp_G_3);
    element_mul(TK->TK1->sk_prime.sk_2, TK->TK1->sk_prime.sk_2, this->tmp_G_4);

    // sk_prime3 = g^(-sigma/beta) * g^(d3/beta)
    element_neg(this->tmp_Zn, this->tmp_Zn);
    element_pow_zn(TK->TK1->sk_prime.sk_3, msk->g, this->tmp_Zn);
    element_set(this->tmp_D_3, this->d3);
    element_div(this->tmp_D_3, this->tmp_D_3, DK->beta);
    element_pow_zn(this->tmp_G, msk->g, this->tmp_D_3);
    element_mul(TK->TK1->sk_prime.sk_3, TK->TK1->sk_prime.sk_3, this->tmp_G);
}

/**
 * hash function {0,1}* -> G
 */
void FAME_OD::Hash(std::string m, element_t* res) {
    element_from_hash(*res, (void*)m.c_str(), m.length());
    // SHA256
    Hm_1(*res, *res);
}

/**
 * hash function GT -> GT (modeled as a hash-to-group in GT).
 */
void FAME_OD::Hash2(element_t* m, element_t* res) { Hm_1(*res, *m); }

/**
 * Encrypt a message msg under a policy string.
 */
void FAME_OD::Encrypt(mpk* mpk, element_t* msg, std::string policy_str, ciphertext* ciphertext) {
    this->policy_str = policy_str;

    policy_resolution pr;
    policy_generation pg;
    element_random(this->tmp_Zn);

    std::vector<std::string>* postfix_expression = pr.infixToPostfix(policy_str);
#ifndef CH_PBC_QUIET
    for (int i = 0; i < (int)postfix_expression->size(); i++) {
        printf("%s \n", postfix_expression->at(i).c_str());
    }
#endif
    binary_tree* binary_tree_expression = pr.postfixToBinaryTree(postfix_expression, this->tmp_Zn);
    pg.generatePolicyInMatrixForm(binary_tree_expression);
    element_t_matrix* M = pg.getPolicyInMatrixFormFromTree(binary_tree_expression);

    unsigned long int rows = M->row();
    unsigned long int cols = M->col();

#ifndef CH_PBC_QUIET
    printf("rows: %ld, cols: %ld\n", rows, cols);
    for (int i = 0; i < (int)rows; i++) {
        for (int j = 0; j < (int)cols; j++) {
            element_printf("%B ", M->getElement(i, j));
        }
        printf("\n");
    }
#endif

    element_random(this->s1);
    element_random(this->s2);

    // ct0
    element_pow_zn(ciphertext->ct0.ct_1, mpk->H1, this->s1);
    element_pow_zn(ciphertext->ct0.ct_2, mpk->H2, this->s2);
    element_add(this->tmp_Zn_2, this->s1, this->s2);
    element_pow_zn(ciphertext->ct0.ct_3, mpk->h, this->tmp_Zn_2);

    // ct_prime = T1^s1 * T2^s2 * R_1
    element_random(this->R_1);
    element_random(this->R_2);
    element_pow_zn(this->tmp_GT, mpk->T1, this->s1);
    element_pow_zn(this->tmp_GT_2, mpk->T2, this->s2);
    element_mul(this->tmp_GT_3, this->tmp_GT, this->tmp_GT_2);
    element_mul(ciphertext->ct_prime, this->tmp_GT_3, this->R_1);

    // ct_prime2 = R2 / H(R1)
    this->Hash2(&this->tmp_GT, &this->R_1);
    element_invert(this->tmp_GT, this->tmp_GT);
    element_mul(ciphertext->ct_prime2, this->R_2, this->tmp_GT);

    // ct_prime3 = msg / H(R2)
    this->Hash2(&this->tmp_GT, &this->R_2);
    element_invert(this->tmp_GT, this->tmp_GT);
    element_mul(ciphertext->ct_prime3, this->tmp_GT, *msg);

    // ct_y
    for (unsigned long int i = 0; i < rows; i++) {
        std::string attr = M->getName(i);
        pai[i] = attr;

        // l = 1
        std::string attr_l_1 = attr + "1" + "1";
        this->Hash(attr_l_1, &this->tmp_G);
        element_pow_zn(this->tmp_G, this->tmp_G, this->s1);
        std::string attr_l_2 = attr + "1" + "2";
        this->Hash(attr_l_2, &this->tmp_G_2);
        element_pow_zn(this->tmp_G_2, this->tmp_G_2, this->s2);
        element_mul(ciphertext->ct_y[i]->ct_1, this->tmp_G, this->tmp_G_2);

        for (unsigned long int j = 0; j < cols; j++) {
            std::string str_0jl1 = "0" + std::to_string(j + 1) + "1" + "1";
            std::string str_0jl2 = "0" + std::to_string(j + 1) + "1" + "2";
            this->Hash(str_0jl1, &this->tmp_G);
            element_pow_zn(this->tmp_G, this->tmp_G, this->s1);
            this->Hash(str_0jl2, &this->tmp_G_2);
            element_pow_zn(this->tmp_G_2, this->tmp_G_2, this->s2);
            element_mul(this->tmp_G_3, this->tmp_G, this->tmp_G_2);
            element_pow_zn(this->tmp_G_4, this->tmp_G_3, M->getElement(i, j));
            element_mul(ciphertext->ct_y[i]->ct_1, ciphertext->ct_y[i]->ct_1, this->tmp_G_4);
        }

        // l = 2
        attr_l_1 = attr + "2" + "1";
        this->Hash(attr_l_1, &this->tmp_G);
        element_pow_zn(this->tmp_G, this->tmp_G, this->s1);
        attr_l_2 = attr + "2" + "2";
        this->Hash(attr_l_2, &this->tmp_G_2);
        element_pow_zn(this->tmp_G_2, this->tmp_G_2, this->s2);
        element_mul(ciphertext->ct_y[i]->ct_2, this->tmp_G, this->tmp_G_2);
        for (unsigned long int j = 0; j < cols; j++) {
            std::string str_0jl1 = "0" + std::to_string(j + 1) + "2" + "1";
            std::string str_0jl2 = "0" + std::to_string(j + 1) + "2" + "2";
            this->Hash(str_0jl1, &this->tmp_G);
            element_pow_zn(this->tmp_G, this->tmp_G, this->s1);
            this->Hash(str_0jl2, &this->tmp_G_2);
            element_pow_zn(this->tmp_G_2, this->tmp_G_2, this->s2);
            element_mul(this->tmp_G_3, this->tmp_G, this->tmp_G_2);
            element_pow_zn(this->tmp_G_4, this->tmp_G_3, M->getElement(i, j));
            element_mul(ciphertext->ct_y[i]->ct_2, ciphertext->ct_y[i]->ct_2, this->tmp_G_4);
        }

        // l = 3
        attr_l_1 = attr + "3" + "1";
        this->Hash(attr_l_1, &this->tmp_G);
        element_pow_zn(this->tmp_G, this->tmp_G, this->s1);
        attr_l_2 = attr + "3" + "2";
        this->Hash(attr_l_2, &this->tmp_G_2);
        element_pow_zn(this->tmp_G_2, this->tmp_G_2, this->s2);
        element_mul(ciphertext->ct_y[i]->ct_3, this->tmp_G, this->tmp_G_2);
        for (unsigned long int j = 0; j < cols; j++) {
            std::string str_0jl1 = "0" + std::to_string(j + 1) + "3" + "1";
            std::string str_0jl2 = "0" + std::to_string(j + 1) + "3" + "2";
            this->Hash(str_0jl1, &this->tmp_G);
            element_pow_zn(this->tmp_G, this->tmp_G, this->s1);
            this->Hash(str_0jl2, &this->tmp_G_2);
            element_pow_zn(this->tmp_G_2, this->tmp_G_2, this->s2);
            element_mul(this->tmp_G_3, this->tmp_G, this->tmp_G_2);
            element_pow_zn(this->tmp_G_4, this->tmp_G_3, M->getElement(i, j));
            element_mul(ciphertext->ct_y[i]->ct_3, ciphertext->ct_y[i]->ct_3, this->tmp_G_4);
        }
    }
}

/**
 * Encrypt with fixed (s1,s2) (used by some tests).
 */
void FAME_OD::Encrypt(mpk* mpk, element_t* msg, std::string policy_str, element_t* s1, element_t* s2, ciphertext* ciphertext) {
    this->policy_str = policy_str;
    element_set(this->s1, *s1);
    element_set(this->s2, *s2);

    policy_resolution pr;
    policy_generation pg;
    element_random(this->tmp_Zn);

    std::vector<std::string>* postfix_expression = pr.infixToPostfix(policy_str);
    binary_tree* binary_tree_expression = pr.postfixToBinaryTree(postfix_expression, this->tmp_Zn);
    pg.generatePolicyInMatrixForm(binary_tree_expression);
    element_t_matrix* M = pg.getPolicyInMatrixFormFromTree(binary_tree_expression);

    unsigned long int rows = M->row();
    unsigned long int cols = M->col();

    // ct0
    element_pow_zn(ciphertext->ct0.ct_1, mpk->H1, this->s1);
    element_pow_zn(ciphertext->ct0.ct_2, mpk->H2, this->s2);
    element_add(this->tmp_Zn_2, this->s1, this->s2);
    element_pow_zn(ciphertext->ct0.ct_3, mpk->h, this->tmp_Zn_2);

    element_random(this->R_1);
    element_random(this->R_2);
    element_pow_zn(this->tmp_GT, mpk->T1, this->s1);
    element_pow_zn(this->tmp_GT_2, mpk->T2, this->s2);
    element_mul(this->tmp_GT_3, this->tmp_GT, this->tmp_GT_2);
    element_mul(ciphertext->ct_prime, this->tmp_GT_3, this->R_1);

    this->Hash2(&this->tmp_GT, &this->R_1);
    element_invert(this->tmp_GT, this->tmp_GT);
    element_mul(ciphertext->ct_prime2, this->R_2, this->tmp_GT);

    this->Hash2(&this->tmp_GT, &this->R_2);
    element_invert(this->tmp_GT, this->tmp_GT);
    element_mul(ciphertext->ct_prime3, this->tmp_GT, *msg);

    for (unsigned long int i = 0; i < rows; i++) {
        std::string attr = M->getName(i);
        pai[i] = attr;

        // l = 1
        std::string attr_l_1 = attr + "1" + "1";
        this->Hash(attr_l_1, &this->tmp_G);
        element_pow_zn(this->tmp_G, this->tmp_G, this->s1);
        std::string attr_l_2 = attr + "1" + "2";
        this->Hash(attr_l_2, &this->tmp_G_2);
        element_pow_zn(this->tmp_G_2, this->tmp_G_2, this->s2);
        element_mul(ciphertext->ct_y[i]->ct_1, this->tmp_G, this->tmp_G_2);
        for (unsigned long int j = 0; j < cols; j++) {
            std::string str_0jl1 = "0" + std::to_string(j + 1) + "1" + "1";
            std::string str_0jl2 = "0" + std::to_string(j + 1) + "1" + "2";
            this->Hash(str_0jl1, &this->tmp_G);
            element_pow_zn(this->tmp_G, this->tmp_G, this->s1);
            this->Hash(str_0jl2, &this->tmp_G_2);
            element_pow_zn(this->tmp_G_2, this->tmp_G_2, this->s2);
            element_mul(this->tmp_G_3, this->tmp_G, this->tmp_G_2);
            element_pow_zn(this->tmp_G_4, this->tmp_G_3, M->getElement(i, j));
            element_mul(ciphertext->ct_y[i]->ct_1, ciphertext->ct_y[i]->ct_1, this->tmp_G_4);
        }

        // l = 2
        attr_l_1 = attr + "2" + "1";
        this->Hash(attr_l_1, &this->tmp_G);
        element_pow_zn(this->tmp_G, this->tmp_G, this->s1);
        attr_l_2 = attr + "2" + "2";
        this->Hash(attr_l_2, &this->tmp_G_2);
        element_pow_zn(this->tmp_G_2, this->tmp_G_2, this->s2);
        element_mul(ciphertext->ct_y[i]->ct_2, this->tmp_G, this->tmp_G_2);
        for (unsigned long int j = 0; j < cols; j++) {
            std::string str_0jl1 = "0" + std::to_string(j + 1) + "2" + "1";
            std::string str_0jl2 = "0" + std::to_string(j + 1) + "2" + "2";
            this->Hash(str_0jl1, &this->tmp_G);
            element_pow_zn(this->tmp_G, this->tmp_G, this->s1);
            this->Hash(str_0jl2, &this->tmp_G_2);
            element_pow_zn(this->tmp_G_2, this->tmp_G_2, this->s2);
            element_mul(this->tmp_G_3, this->tmp_G, this->tmp_G_2);
            element_pow_zn(this->tmp_G_4, this->tmp_G_3, M->getElement(i, j));
            element_mul(ciphertext->ct_y[i]->ct_2, ciphertext->ct_y[i]->ct_2, this->tmp_G_4);
        }

        // l = 3
        attr_l_1 = attr + "3" + "1";
        this->Hash(attr_l_1, &this->tmp_G);
        element_pow_zn(this->tmp_G, this->tmp_G, this->s1);
        attr_l_2 = attr + "3" + "2";
        this->Hash(attr_l_2, &this->tmp_G_2);
        element_pow_zn(this->tmp_G_2, this->tmp_G_2, this->s2);
        element_mul(ciphertext->ct_y[i]->ct_3, this->tmp_G, this->tmp_G_2);
        for (unsigned long int j = 0; j < cols; j++) {
            std::string str_0jl1 = "0" + std::to_string(j + 1) + "3" + "1";
            std::string str_0jl2 = "0" + std::to_string(j + 1) + "3" + "2";
            this->Hash(str_0jl1, &this->tmp_G);
            element_pow_zn(this->tmp_G, this->tmp_G, this->s1);
            this->Hash(str_0jl2, &this->tmp_G_2);
            element_pow_zn(this->tmp_G_2, this->tmp_G_2, this->s2);
            element_mul(this->tmp_G_3, this->tmp_G, this->tmp_G_2);
            element_pow_zn(this->tmp_G_4, this->tmp_G_3, M->getElement(i, j));
            element_mul(ciphertext->ct_y[i]->ct_3, ciphertext->ct_y[i]->ct_3, this->tmp_G_4);
        }
    }
}

/**
 * Transform (outsourced decryption): compute ct_p and output TC.
 */
void FAME_OD::Transform(mpk* mpk, ciphertext* ciphertext, TK* TK, TC* TC) {
    policy_resolution pr;
    policy_generation pg;
    element_random(this->tmp_Zn);

    std::vector<std::string>* postfix_expression = pr.infixToPostfix(this->policy_str);
    binary_tree* binary_tree_expression = pr.postfixToBinaryTree(postfix_expression, this->tmp_Zn);
    pg.generatePolicyInMatrixForm(binary_tree_expression);
    element_t_matrix* M = pg.getPolicyInMatrixFormFromTree(binary_tree_expression);

    // collect only rows whose attributes appear in the user's attribute set
    element_t_matrix* attributesMatrix = new element_t_matrix();
    const unsigned long int rows = ciphertext->ct_y.size();
    for (unsigned long int i = 0; i < rows; i++) {
        if (attr_map.find(pai[i]) == attr_map.end()) {
            continue;
        }
        element_t_vector* v = new element_t_vector();
        for (signed long int j = 0; j < M->col(); ++j) {
            v->pushBack(M->getElement(i, j));
        }
        attributesMatrix->pushBack(v);
    }

    element_t_matrix* inverse_attributesMatrix = inverse(attributesMatrix);
    element_t_vector* unit = getCoordinateAxisUnitVector(inverse_attributesMatrix);
    element_t_vector* x = new element_t_vector(inverse_attributesMatrix->col(), inverse_attributesMatrix->getElement(0, 0));

    signed long int type = gaussElimination(x, inverse_attributesMatrix, unit);
    if (-1 == type) {
        throw std::runtime_error("POLICY_NOT_SATISFIED");
    }

    // num
    element_t num, den;
    element_init_same_as(num, *this->GT);
    element_init_same_as(den, *this->GT);

    // num = e(prod ct_y[i]^x_i, sk0_*) ...
    element_set1(this->tmp_G);
    element_set1(this->tmp_G_2);
    element_set1(this->tmp_G_3);
    int count = 0;
    for (unsigned long int i = 0; i < rows; i++) {
        if (attr_map.find(pai[i]) == attr_map.end()) {
            continue;
        }
        element_pow_zn(this->tmp_G_4, ciphertext->ct_y[i]->ct_1, x->getElement(count));
        element_mul(this->tmp_G, this->tmp_G, this->tmp_G_4);
        element_pow_zn(this->tmp_G_4, ciphertext->ct_y[i]->ct_2, x->getElement(count));
        element_mul(this->tmp_G_2, this->tmp_G_2, this->tmp_G_4);
        element_pow_zn(this->tmp_G_4, ciphertext->ct_y[i]->ct_3, x->getElement(count));
        element_mul(this->tmp_G_3, this->tmp_G_3, this->tmp_G_4);
        count++;
    }

    element_pairing(this->tmp_GT, this->tmp_G, TK->TK1->sk0.sk_1);
    element_pairing(this->tmp_GT_2, this->tmp_G_2, TK->TK1->sk0.sk_2);
    element_pairing(this->tmp_GT_3, this->tmp_G_3, TK->TK1->sk0.sk_3);
    element_mul(num, this->tmp_GT, this->tmp_GT_2);
    element_mul(num, num, this->tmp_GT_3);

    // den
    element_set1(this->tmp_G);
    element_set1(this->tmp_G_2);
    element_set1(this->tmp_G_3);
    count = 0;
    for (unsigned long int i = 0; i < rows; i++) {
        if (attr_map.find(pai[i]) == attr_map.end()) {
            continue;
        }
        element_pow_zn(this->tmp_G_4, TK->TK1->sk_y[attr_map[pai[i]]]->sk_1, x->getElement(count));
        element_mul(this->tmp_G, this->tmp_G, this->tmp_G_4);
        element_pow_zn(this->tmp_G_4, TK->TK1->sk_y[attr_map[pai[i]]]->sk_2, x->getElement(count));
        element_mul(this->tmp_G_2, this->tmp_G_2, this->tmp_G_4);
        element_pow_zn(this->tmp_G_4, TK->TK1->sk_y[attr_map[pai[i]]]->sk_3, x->getElement(count));
        element_mul(this->tmp_G_3, this->tmp_G_3, this->tmp_G_4);
        count++;
    }
    element_mul(this->tmp_G, TK->TK1->sk_prime.sk_1, this->tmp_G);
    element_mul(this->tmp_G_2, TK->TK1->sk_prime.sk_2, this->tmp_G_2);
    element_mul(this->tmp_G_3, TK->TK1->sk_prime.sk_3, this->tmp_G_3);

    element_pairing(this->tmp_GT, this->tmp_G, ciphertext->ct0.ct_1);
    element_pairing(this->tmp_GT_2, this->tmp_G_2, ciphertext->ct0.ct_2);
    element_pairing(this->tmp_GT_3, this->tmp_G_3, ciphertext->ct0.ct_3);
    element_mul(den, this->tmp_GT, this->tmp_GT_2);
    element_mul(den, den, this->tmp_GT_3);

    // ct_p = num / den
    element_div(TC->ct_p, num, den);

    // carry remaining parts
    element_set(TC->ct_prime, ciphertext->ct_prime);
    element_set(TC->ct_prime2, ciphertext->ct_prime2);
    element_set(TC->ct_prime3, ciphertext->ct_prime3);

    element_clear(num);
    element_clear(den);
}

/**
 * User finalize decryption.
 */
void FAME_OD::Decrypt(mpk* mpk, TC* TC, DK* DK, element_t* res) {
    element_pow_zn(this->tmp_GT, TC->ct_p, DK->beta);
    element_mul(this->R_1, TC->ct_prime, this->tmp_GT);

    // recover R2: tmp_GT = H(R1)
    this->Hash2(&this->tmp_GT, &this->R_1);
    element_mul(this->R_2, this->tmp_GT, TC->ct_prime2);

    // recover msg: tmp_GT = H(R2)
    this->Hash2(&this->tmp_GT, &this->R_2);
    element_mul(*res, this->tmp_GT, TC->ct_prime3);
}

FAME_OD::~FAME_OD() {
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
    element_clear(this->tmp_D_1);
    element_clear(this->tmp_D_2);
    element_clear(this->tmp_D_3);

    element_clear(this->d1);
    element_clear(this->d2);
    element_clear(this->d3);

    element_clear(this->r1);
    element_clear(this->r2);

    element_clear(this->R_1);
    element_clear(this->R_2);

    element_clear(this->b1r1a1);
    element_clear(this->b1r1a2);
    element_clear(this->b2r2a1);
    element_clear(this->b2r2a2);
    element_clear(this->r1r2a1);
    element_clear(this->r1r2a2);

    element_clear(this->sigma_y);
    element_clear(this->sigma);

    element_clear(this->s1);
    element_clear(this->s2);
}

