#include <ABE/ABET.h>


ABET::ABET(element_t *_G, element_t *_H, element_t *_GT, element_t *_Zn){
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

    element_init_same_as(this->d1, *this->Zn);
    element_init_same_as(this->d2, *this->Zn);
    element_init_same_as(this->d3, *this->Zn);

    element_init_same_as(this->r1, *this->Zn);
    element_init_same_as(this->r2, *this->Zn);
    element_init_same_as(this->R, *this->Zn);

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
void ABET::Setup(msk *msk, mpk *mpk, int k){
    this->k = k;
    element_random(msk->a1);
    element_random(msk->a2);
    element_random(msk->b1);
    element_random(msk->b2);
    element_random(msk->a);
    element_random(msk->b);

    element_random(mpk->g);
    element_random(mpk->h);

    element_random(this->d1);
    // g_pow_d1 = g^d1
    element_pow_zn(msk->g_pow_d1, mpk->g, this->d1);
    element_random(this->d2);
    // g_pow_d2 = g^d2
    element_pow_zn(msk->g_pow_d2, mpk->g, this->d2);
    element_random(this->d3);
    // g_pow_d3 = g^d3
    element_pow_zn(msk->g_pow_d3, mpk->g, this->d3);

    for(int i=1;i <= k;i++){
        element_random(*msk->zk[i]);
    }

    // H1 = h^a1
    element_pow_zn(mpk->H1, mpk->h, msk->a1);
    // H2 = h^a2
    element_pow_zn(mpk->H2, mpk->h, msk->a2);
    // T1 = e(g, h)^(d1*a1+d3/a)
    element_mul(this->tmp_Zn, this->d1, msk->a1);
    element_div(this->tmp_Zn_2, this->d3, msk->a);
    element_add(this->tmp_Zn, this->tmp_Zn, this->tmp_Zn_2);
    element_pairing(this->tmp_GT, mpk->g, mpk->h);
    element_pow_zn(mpk->T1, this->tmp_GT, this->tmp_Zn);
    // T2 = e(g, h)^(d2*a2+d3/a)
    element_mul(this->tmp_Zn, this->d2, msk->a2);
    element_div(this->tmp_Zn_2, this->d3, msk->a);
    element_add(this->tmp_Zn, this->tmp_Zn, this->tmp_Zn_2);
    element_pow_zn(mpk->T2, this->tmp_GT, this->tmp_Zn);

    // gk, gk_pow_a, hk
    for(int i = 1;i <= k;i++){
        // gk = g^zk
        element_pow_zn(*mpk->gk[i], mpk->g, *msk->zk[i]);
        // gk_pow_a = gk^a
        element_pow_zn(*mpk->gk_pow_a[i], *mpk->gk[i], msk->a);
        // hk = h^zk
        element_pow_zn(*mpk->hk[i], mpk->h, *msk->zk[i]);
    }
    // g^a
    element_pow_zn(mpk->g_pow_a, mpk->g, msk->a);
    // h^(d/a)
    // d = d1 + d2 + d3
    element_add(this->tmp_Zn, this->d1, this->d2);
    element_add(this->tmp_Zn, this->tmp_Zn, this->d3);
    element_div(this->tmp_Zn, this->tmp_Zn, msk->a);
    element_pow_zn(mpk->h_pow_d_div_a, mpk->h, this->tmp_Zn);
    // h^(1/a)
    element_invert(this->tmp_Zn, msk->a);
    element_pow_zn(mpk->h_pow_1_div_a, mpk->h, this->tmp_Zn);
    // h^(b/a)
    element_div(this->tmp_Zn, msk->b, msk->a);
    element_pow_zn(mpk->h_pow_b_div_a, mpk->h, this->tmp_Zn);
}


/**
 * Generate a key for a list of attributes.
 * input: msk, mpk, attr , ID, i
 * output: sks
 */
void ABET::KeyGen(msk *msk, mpk *mpk, std::vector<std::string> *attr_list, ID *ID, int mi, sks *sks){
    element_random(this->r1);
    element_random(this->r2);
    element_random(this->R);
    // sk0 = (h^(b1r1), h^(b2r2), h^(r1+r2)/a, g^(1/a), g^(r/a), g^R) 
    element_mul(this->tmp_Zn, msk->b1, this->r1);
    element_pow_zn(sks->sk_0.sk0_1, mpk->h, this->tmp_Zn);
    // (b1 * r1) / a1
    element_div(this->b1r1a1, this->tmp_Zn, msk->a1);
    // (b1 * r1) / a2
    element_div(this->b1r1a2, this->tmp_Zn, msk->a2);
    element_mul(this->tmp_Zn, msk->b2, this->r2);
    element_pow_zn(sks->sk_0.sk0_2, mpk->h, this->tmp_Zn);
    // (b2 * r2) / a1
    element_div(this->b2r2a1, this->tmp_Zn, msk->a1);
    // (b2 * r2) / a2
    element_div(this->b2r2a2, this->tmp_Zn, msk->a2);
    element_add(this->tmp_Zn, this->r1, this->r2);
    element_div(this->tmp_Zn_2, this->tmp_Zn, msk->a);
    element_pow_zn(sks->sk_0.sk0_3, mpk->h, this->tmp_Zn_2);
    // (r1 + r2) / a1
    element_div(this->r1r2a1, this->tmp_Zn, msk->a1);
    // (r1 + r2) / a2
    element_div(this->r1r2a2, this->tmp_Zn, msk->a2);
    // g^(1/a)
    element_invert(this->tmp_Zn, msk->a);
    element_pow_zn(sks->sk_0.sk0_4, mpk->g, this->tmp_Zn);
    // g^(r/a)
    element_add(this->tmp_Zn, this->r1, this->r2);
    element_div(this->tmp_Zn, this->tmp_Zn, msk->a);
    element_pow_zn(sks->sk_0.sk0_5, mpk->g, this->tmp_Zn);
    // g^R
    element_pow_zn(sks->sk_0.sk0_6, mpk->g, this->R);

    // compute sk_y
    for(int i = 0;i < attr_list->size();i++){
        attr_map[attr_list->at(i)] = i;
        // sigma_y
        element_random(this->tmp_Zn);
        // t = 1
        // H(y11)^b1r1a1
        std::string y11 = attr_list->at(i) + "1" + "1";
        this->Hash(y11, &this->tmp_G);
        element_pow_zn(this->tmp_G, this->tmp_G, this->b1r1a1);
        // H(y21)^b2r2a1
        std::string y21 = attr_list->at(i) + "2" + "1";
        this->Hash(y21, &this->tmp_G_2);
        element_pow_zn(this->tmp_G_2, this->tmp_G_2, this->b2r2a1);
        // H(y31)^(r1r2a1/a)
        std::string y31 = attr_list->at(i) + "3" + "1";
        this->Hash(y31, &this->tmp_G_3);
        element_div(this->tmp_Zn_2, this->r1r2a1, msk->a);
        element_pow_zn(this->tmp_G_3, this->tmp_G_3, this->tmp_Zn_2);
        // g^(sigma_y / (a*a1))
        element_mul(this->tmp_Zn_2, msk->a, msk->a1);
        element_div(this->tmp_Zn_2, this->tmp_Zn, this->tmp_Zn_2);
        element_pow_zn(this->tmp_G_4, mpk->g, this->tmp_Zn_2);
        // sky1
        element_mul(sks->sk_y[i]->sk_1, this->tmp_G, this->tmp_G_2);
        element_mul(sks->sk_y[i]->sk_1, sks->sk_y[i]->sk_1, this->tmp_G_3);
        element_mul(sks->sk_y[i]->sk_1, sks->sk_y[i]->sk_1, this->tmp_G_4);

        // t = 2
        // H(y12)^b1r1a2
        std::string y12 = attr_list->at(i) + "1" + "2";
        this->Hash(y12, &this->tmp_G);
        element_pow_zn(this->tmp_G, this->tmp_G, this->b1r1a2);
        // H(y22)^b2r2a2
        std::string y22 = attr_list->at(i) + "2" + "2";
        this->Hash(y22, &this->tmp_G_2);
        element_pow_zn(this->tmp_G_2, this->tmp_G_2, this->b2r2a2);
        // H(y32)^(r1r2a2/a)
        std::string y32 = attr_list->at(i) + "3" + "2";
        this->Hash(y32, &this->tmp_G_3);
        element_div(this->tmp_Zn_2, this->r1r2a2, msk->a);
        element_pow_zn(this->tmp_G_3, this->tmp_G_3, this->tmp_Zn_2);
        // g^(sigma_y / (a*a2))
        element_mul(this->tmp_Zn_2, msk->a, msk->a2);
        element_div(this->tmp_Zn_2, this->tmp_Zn, this->tmp_Zn_2);
        element_pow_zn(this->tmp_G_4, mpk->g, this->tmp_Zn_2);
        // sky2
        element_mul(sks->sk_y[i]->sk_2, this->tmp_G, this->tmp_G_2);
        element_mul(sks->sk_y[i]->sk_2, sks->sk_y[i]->sk_2, this->tmp_G_3);
        element_mul(sks->sk_y[i]->sk_2, sks->sk_y[i]->sk_2, this->tmp_G_4);

        // sky3 = g^(-sigma_y)
        element_neg(this->tmp_Zn, this->tmp_Zn);
        element_pow_zn(sks->sk_y[i]->sk_3, mpk->g, this->tmp_Zn);
    }

    // sk_prime
    // sigma_prime
    element_random(this->tmp_Zn);
    // t = 1
    // g^d1
    element_set(sks->sk_prime.sk_1, msk->g_pow_d1);
    // H(0111)^b1r1a1
    std::string y0111 = "0111";
    this->Hash(y0111, &this->tmp_G);
    element_pow_zn(this->tmp_G, this->tmp_G, this->b1r1a1);
    // H(0121)^b2r2a1
    std::string y0121 = "0121";
    this->Hash(y0121, &this->tmp_G_2);
    element_pow_zn(this->tmp_G_2, this->tmp_G_2, this->b2r2a1);
    // H(0131)^(r1r2a1/a)
    std::string y0131 = "0131";
    this->Hash(y0131, &this->tmp_G_3);
    element_div(this->tmp_Zn_2, this->r1r2a1, msk->a);
    element_pow_zn(this->tmp_G_3, this->tmp_G_3, this->tmp_Zn_2);
    // g^(sigma_prime / (a*a1))
    element_mul(this->tmp_Zn_2, msk->a, msk->a1);
    element_div(this->tmp_Zn_2, this->tmp_Zn, this->tmp_Zn_2);
    element_pow_zn(this->tmp_G_4, mpk->g, this->tmp_Zn_2);
    // sk_prime1
    element_mul(sks->sk_prime.sk_1, sks->sk_prime.sk_1, this->tmp_G);
    element_mul(sks->sk_prime.sk_1, sks->sk_prime.sk_1, this->tmp_G_2);
    element_mul(sks->sk_prime.sk_1, sks->sk_prime.sk_1, this->tmp_G_3);
    element_mul(sks->sk_prime.sk_1, sks->sk_prime.sk_1, this->tmp_G_4);

    // t = 2
    // g^d2
    element_set(sks->sk_prime.sk_2, msk->g_pow_d2);
    // H(0112)^b1r1a2
    std::string y0112 = "0112";
    this->Hash(y0112, &this->tmp_G);
    element_pow_zn(this->tmp_G, this->tmp_G, this->b1r1a2);
    // H(0122)^b2r2a2
    std::string y0122 = "0122";
    this->Hash(y0122, &this->tmp_G_2);
    element_pow_zn(this->tmp_G_2, this->tmp_G_2, this->b2r2a2);
    // H(0132)^(r1r2a2/a)
    std::string y0132 = "0132";
    this->Hash(y0132, &this->tmp_G_3);
    element_div(this->tmp_Zn_2, this->r1r2a2, msk->a);
    element_pow_zn(this->tmp_G_3, this->tmp_G_3, this->tmp_Zn_2);
    // g^(sigma_prime / (a*a2))
    element_mul(this->tmp_Zn_2, msk->a, msk->a2);
    element_div(this->tmp_Zn_2, this->tmp_Zn, this->tmp_Zn_2);
    element_pow_zn(this->tmp_G_4, mpk->g, this->tmp_Zn_2);
    // sk_prime2
    element_mul(sks->sk_prime.sk_2, sks->sk_prime.sk_2, this->tmp_G);
    element_mul(sks->sk_prime.sk_2, sks->sk_prime.sk_2, this->tmp_G_2);
    element_mul(sks->sk_prime.sk_2, sks->sk_prime.sk_2, this->tmp_G_3);
    element_mul(sks->sk_prime.sk_2, sks->sk_prime.sk_2, this->tmp_G_4);
   
    // sk_prime3 = g^d3 * g ^ (-sigma_prime)
    element_neg(this->tmp_Zn, this->tmp_Zn);
    element_pow_zn(sks->sk_prime.sk_3, mpk->g, this->tmp_Zn);
    element_mul(sks->sk_prime.sk_3, sks->sk_prime.sk_3, msk->g_pow_d3);

    // sk1 = g^d * (IDi)^(a*r) * g^(b*R)
    // IDi
    this->GetID_(mpk, ID, mi, MODIFIER, &this->tmp_G);
    // IDi^(a*r)
    element_add(this->tmp_Zn, this->r1, this->r2);
    element_mul(this->tmp_Zn, msk->a, this->tmp_Zn);
    element_pow_zn(this->tmp_G, this->tmp_G, this->tmp_Zn);
    // g^(b*R)
    element_mul(this->tmp_Zn, msk->b, this->R);
    element_pow_zn(this->tmp_G_2, mpk->g, this->tmp_Zn);
    // g^d = g^d1 * g^d2 * g^d3
    element_mul(this->tmp_G_3, msk->g_pow_d1, msk->g_pow_d2);
    element_mul(this->tmp_G_3, this->tmp_G_3, msk->g_pow_d3);
    element_mul(sks->sk1, this->tmp_G_3, this->tmp_G);
    element_mul(sks->sk1, sks->sk1, this->tmp_G_2);

    // sk2 = {gi-1^(a*r), gi-2^(a*r), ..., g1^(a*r)}
    element_add(this->tmp_Zn, this->r1, this->r2);
    element_mul(this->tmp_Zn, msk->a, this->tmp_Zn);
    for(int i=mi-1;i>=1;i--){
        element_pow_zn(*sks->sk2[mi - i], *mpk->gk[i], this->tmp_Zn);
    }
}

/**
 * hash function {0,1}* -> G
 * input: m
 * output: res
 */
void ABET::Hash(std::string m, element_t *res){
    element_from_hash(*res, (void*)m.c_str(), m.length());
    // SHA256
    Hm_1(*res, *res);
}

/**
 * hash function {0,1}* -> Zq
 * input: m
 * output: res
 */
void ABET::Hash2(element_t *m, element_t *res){
    Hm_1(*m, *res);
}


/**
 * Encrypt a message msg under a policy string.
 * input: mpk, msk,msg(r,R), policy_str, ID, oj, s1, s2
 * output: ct
 */
void ABET::Encrypt(mpk *mpk, msk *msk, element_t *r, element_t *R, std::string policy_str, ID *ID, int oj, element_t *s1, element_t *s2, ciphertext *ciphertext){
    this->policy_str = policy_str;

    policy_resolution pr;
    policy_generation pg;
    element_random(this->tmp_Zn);

    vector<string>* postfix_expression = pr.infixToPostfix(policy_str);
    // 打印
    for(int i = 0;i < postfix_expression->size();i++){
        printf("%s \n", postfix_expression->at(i).c_str());
    }
    binary_tree* binary_tree_expression = pr.postfixToBinaryTree(postfix_expression, this->tmp_Zn);
    pg.generatePolicyInMatrixForm(binary_tree_expression);
    element_t_matrix* M = pg.getPolicyInMatrixFormFromTree(binary_tree_expression);

    unsigned long int rows = M->row();
    unsigned long int cols = M->col();

    printf("rows: %ld, cols: %ld\n", rows, cols);
    for(int i = 0;i < rows;i++){
        for(int j = 0;j < cols;j++){
            element_printf("%B ", M->getElement(i, j));
        }
        printf("\n");
    }

    // s1,s2
    element_set(this->s1, *s1);
    element_set(this->s2, *s2);

    // ct0
    // ct0_1 = H1^s1
    element_pow_zn(ciphertext->ct_0.ct0_1, mpk->H1, this->s1);
    // ct0_2 = H2^s2
    element_pow_zn(ciphertext->ct_0.ct0_2, mpk->H2, this->s2);
    // ct0_3 = h^((s1+s2)/a) = (h^(1/a))^(s1+s2)
    element_add(this->tmp_Zn_2, this->s1, this->s2);
    element_pow_zn(ciphertext->ct_0.ct0_3, mpk->h_pow_1_div_a, this->tmp_Zn_2);
    // ct0_4 = h^(b*s/a) = (h^(b/a))^(s1+s2)
    element_pow_zn(ciphertext->ct_0.ct0_4, mpk->h_pow_b_div_a, this->tmp_Zn_2);

    // ct_ = r xor G(T1^s1 * T2^s2)
    element_pow_zn(this->tmp_GT, mpk->T1, this->s1);
    element_pow_zn(this->tmp_GT_2, mpk->T2, this->s2);
    element_mul(this->tmp_GT, this->tmp_GT, this->tmp_GT_2);
    this->Hash2(&this->tmp_GT, &this->tmp_Zn);
    element_mul(ciphertext->ct_, *r, this->tmp_Zn);

    // ct_prime = (R || 0^(l-|R|)) xor H2(e(g,h^(d/a))^s)
    // H2(e(g,h^(d/a))^s)
    element_pairing(this->tmp_GT, mpk->g, mpk->h_pow_d_div_a);
    element_add(this->tmp_Zn, this->s1, this->s2);
    element_pow_zn(this->tmp_GT, this->tmp_GT, this->tmp_Zn);
    this->Hash2(&this->tmp_GT, &this->tmp_Zn);
    element_mul(ciphertext->ct_prime, *R, this->tmp_Zn);

    // ct1 = IDj^(a*s)
    // ct2 = IDj^s
    // ct3 = ct1^s
    this->GetID_(mpk, ID, oj, OWNER, &this->tmp_H);
    element_add(this->tmp_Zn, this->s1, this->s2);
    element_pow_zn(ciphertext->ct2, this->tmp_H, this->tmp_Zn);
    element_mul(this->tmp_Zn_2, msk->a, this->tmp_Zn);
    element_pow_zn(ciphertext->ct1, this->tmp_H, this->tmp_Zn_2);
    element_pow_zn(ciphertext->ct3, ciphertext->ct1, this->tmp_Zn);

    // ct_y
    // for i = 1,2,...,rows
    for(unsigned long int i=0; i<rows;i++){
        string attr = M->getName(i);
        pai[i] = attr;
        // printf("attr: %s\n", attr.c_str());

        // l = 1
        string attr_l_1 = attr + "1" + "1";
        // H(attr_l_1)^s1
        this->Hash(attr_l_1, &this->tmp_G);
        element_pow_zn(this->tmp_G, this->tmp_G, this->s1);
        string attr_l_2 = attr + "1" + "2";
        // H(attr_l_2)^s2
        this->Hash(attr_l_2, &this->tmp_G_2);
        element_pow_zn(this->tmp_G_2, this->tmp_G_2, this->s2);
        element_mul(ciphertext->ct_y[i]->ct_1, this->tmp_G, this->tmp_G_2);
        // for j = 1,2,...,cols
        string str_0jl1,str_0jl2;
        for(unsigned long int j=0; j<cols;j++){
            str_0jl1 = "0" + to_string(j+1) + "1" + "1";
            str_0jl2 = "0" + to_string(j+1) + "1" + "2";
            // H(0jl1)^s1
            this->Hash(str_0jl1, &this->tmp_G);
            element_pow_zn(this->tmp_G, this->tmp_G, this->s1);
            // H(0jl2)^s2
            this->Hash(str_0jl2, &this->tmp_G_2);
            element_pow_zn(this->tmp_G_2, this->tmp_G_2, this->s2);
            // H(0jl1)^s1 * H(0jl2)^s2
            element_mul(this->tmp_G_3, this->tmp_G, this->tmp_G_2);
            // (H(0jl1)^s1 * H(0jl2)^s2)^M[i][j]
            element_pow_zn(this->tmp_G_4, this->tmp_G_3, M->getElement(i, j));
            element_mul(ciphertext->ct_y[i]->ct_1, ciphertext->ct_y[i]->ct_1, this->tmp_G_4);
        }
    
        // l = 2
        attr_l_1 = attr + "2" + "1";
        // H(attr_l_1)^s1
        this->Hash(attr_l_1, &this->tmp_G);
        element_pow_zn(this->tmp_G, this->tmp_G, this->s1);
        attr_l_2 = attr + "2" + "2";
        // H(attr_l_2)^s2
        this->Hash(attr_l_2, &this->tmp_G_2);
        element_pow_zn(this->tmp_G_2, this->tmp_G_2, this->s2);
        element_mul(ciphertext->ct_y[i]->ct_2, this->tmp_G, this->tmp_G_2);
        // for j = 1,2,...,cols
        for(unsigned long int j=0; j<cols;j++){
            str_0jl1 = "0" + to_string(j+1) + "2" + "1";
            str_0jl2 = "0" + to_string(j+1) + "2" + "2";
            // H(0jl1)^s1
            this->Hash(str_0jl1, &this->tmp_G);
            element_pow_zn(this->tmp_G, this->tmp_G, this->s1);
            // H(0jl2)^s2
            this->Hash(str_0jl2, &this->tmp_G_2);
            element_pow_zn(this->tmp_G_2, this->tmp_G_2, this->s2);
            // H(0jl1)^s1 * H(0jl2)^s2
            element_mul(this->tmp_G_3, this->tmp_G, this->tmp_G_2);
            // (H(0jl1)^s1 * H(0jl2)^s2)^M[i][j]
            element_pow_zn(this->tmp_G_4, this->tmp_G_3, M->getElement(i, j));
            element_mul(ciphertext->ct_y[i]->ct_2, ciphertext->ct_y[i]->ct_2, this->tmp_G_4);
        }
        // l = 3
        attr_l_1 = attr + "3" + "1";
        // H(attr_l_1)^s1
        this->Hash(attr_l_1, &this->tmp_G);
        element_pow_zn(this->tmp_G, this->tmp_G, this->s1);
        attr_l_2 = attr + "3" + "2";
        // H(attr_l_2)^s2
        this->Hash(attr_l_2, &this->tmp_G_2);
        element_pow_zn(this->tmp_G_2, this->tmp_G_2, this->s2);
        element_mul(ciphertext->ct_y[i]->ct_3, this->tmp_G, this->tmp_G_2);
        // for j = 1,2,...,cols
        for(unsigned long int j=0; j<cols;j++){
            str_0jl1 = "0" + to_string(j+1) + "3" + "1";
            str_0jl2 = "0" + to_string(j+1) + "3" + "2";
            // H(0jl1)^s1
            this->Hash(str_0jl1, &this->tmp_G);
            element_pow_zn(this->tmp_G, this->tmp_G, this->s1);
            // H(0jl2)^s2
            this->Hash(str_0jl2, &this->tmp_G_2);
            element_pow_zn(this->tmp_G_2, this->tmp_G_2, this->s2);
            // H(0jl1)^s1 * H(0jl2)^s2
            element_mul(this->tmp_G_3, this->tmp_G, this->tmp_G_2);
            // (H(0jl1)^s1 * H(0jl2)^s2)^M[i][j]
            element_pow_zn(this->tmp_G_4, this->tmp_G_3, M->getElement(i, j));
            element_mul(ciphertext->ct_y[i]->ct_3, ciphertext->ct_y[i]->ct_3, this->tmp_G_4);
        }
    }
}

/**
 * Decrypt a ciphertext.
 * input: mpk, ciphertext, sks
 * output: res_R, res_r
 */
void ABET::Decrypt(mpk *mpk, ciphertext *ciphertext, sks *sks, element_t *res_R, element_t *res_r){
    // retrive R
    element_pairing(this->tmp_GT, sks->sk1, ciphertext->ct_0.ct0_3);
    element_pairing(this->tmp_GT_2, sks->sk_0.sk0_5, ciphertext->ct1);
    element_pairing(this->tmp_GT_3, sks->sk_0.sk0_6, ciphertext->ct_0.ct0_4);
    element_mul(this->tmp_GT_2, this->tmp_GT_2, this->tmp_GT_3);
    element_div(this->tmp_GT, this->tmp_GT, this->tmp_GT_2);
    this->Hash2(&this->tmp_GT, &this->tmp_Zn);
    element_div(*res_R, ciphertext->ct_prime, this->tmp_Zn);

    // compute Yi
    // get original matrix
    policy_resolution pr;
    policy_generation pg;
    element_random(this->tmp_Zn);
    vector<string>* postfix_expression = pr.infixToPostfix(this->policy_str);
    binary_tree* binary_tree_expression = pr.postfixToBinaryTree(postfix_expression, this->tmp_Zn);
    pg.generatePolicyInMatrixForm(binary_tree_expression);
    element_t_matrix* M = pg.getPolicyInMatrixFormFromTree(binary_tree_expression);
    // get matrix with attributes
    element_t_matrix* attributesMatrix = new element_t_matrix();
    unsigned long int rows = ciphertext->ct_y.size();
    for(unsigned long int i=0; i<rows;i++){
        // judge whether the attribute is in the policy
        if(attr_map.find(pai[i]) == attr_map.end()){
            continue;
        }
        element_t_vector *v = new element_t_vector();
        for (signed long int j = 0; j < M->col(); ++j) {
            v->pushBack(M->getElement(i, j));
        }
        attributesMatrix->pushBack(v);
    }
    // get inverse matrix
    element_t_matrix* inverse_attributesMatrix = inverse(attributesMatrix);

    unsigned long int r = inverse_attributesMatrix->row();
    unsigned long int c = inverse_attributesMatrix->col();
    printf("rows: %ld, cols: %ld\n", r, c);
    for(int i = 0;i < r;i++){
        for(int j = 0;j < c;j++){
            element_printf("%B ", inverse_attributesMatrix->getElement(i, j));
        }
        printf("\n");
    }
    element_t_vector* unit = getCoordinateAxisUnitVector(inverse_attributesMatrix);

    element_t_vector* x= new element_t_vector(inverse_attributesMatrix->col(), inverse_attributesMatrix->getElement(0, 0));

    signed long int type = gaussElimination(x, inverse_attributesMatrix, unit);
    if (-1 == type) {
        throw std::runtime_error("POLICY_NOT_SATISFIED");
    }
    printf("type: %ld\n", type);
    // print x
    printf("Yi:\n");
    x->printVector();

    // retrive r
    // num
    element_t num,den;
    element_init_same_as(num, *this->GT);
    element_init_same_as(den, *this->GT);
    
    element_set1(this->tmp_G);
    element_set1(this->tmp_G_2);
    element_set1(this->tmp_G_3);
    int count = 0;
    for(unsigned long int i=0; i<rows;i++){
        // judge whether the attribute is in the policy
        if(attr_map.find(pai[i]) == attr_map.end()){
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
    // ct_prime * e(tmp_G, sk0_1) * e(tmp_G_2, sk0_2) * e(tmp_G_3, sk0_3)
    element_pairing(this->tmp_GT, this->tmp_G, sks->sk_0.sk0_1);
    element_pairing(this->tmp_GT_2, this->tmp_G_2, sks->sk_0.sk0_2);
    element_pairing(this->tmp_GT_3, this->tmp_G_3, sks->sk_0.sk0_3);

    element_mul(num, this->tmp_GT, this->tmp_GT_2);
    element_mul(num, num, this->tmp_GT_3);

    // den
    element_set1(this->tmp_G);
    element_set1(this->tmp_G_2);
    element_set1(this->tmp_G_3);
    count = 0;
    for(unsigned long int i=0; i<rows;i++){
        // judge whether the attribute is in the policy
        if(attr_map.find(pai[i]) == attr_map.end()){
            continue;
        }
        element_pow_zn(this->tmp_G_4, sks->sk_y[attr_map[pai[i]]]->sk_1, x->getElement(count));
        element_mul(this->tmp_G, this->tmp_G, this->tmp_G_4);
        element_pow_zn(this->tmp_G_4, sks->sk_y[attr_map[pai[i]]]->sk_2, x->getElement(count));
        element_mul(this->tmp_G_2, this->tmp_G_2, this->tmp_G_4);
        element_pow_zn(this->tmp_G_4, sks->sk_y[attr_map[pai[i]]]->sk_3, x->getElement(count));
        element_mul(this->tmp_G_3, this->tmp_G_3, this->tmp_G_4);
        count++;
    }
    // sk_prime_1 * tmp_G
    element_mul(this->tmp_G, sks->sk_prime.sk_1, this->tmp_G);
    // sk_prime_2 * tmp_G_2
    element_mul(this->tmp_G_2, sks->sk_prime.sk_2, this->tmp_G_2);
    // sk_prime_3 * tmp_G_3
    element_mul(this->tmp_G_3, sks->sk_prime.sk_3, this->tmp_G_3);

    // e(tmp_G, ct01) * e(tmp_G_2, ct02) * e(tmp_G_3, ct03)
    element_pairing(this->tmp_GT, this->tmp_G, ciphertext->ct_0.ct0_1);
    element_pairing(this->tmp_GT_2, this->tmp_G_2, ciphertext->ct_0.ct0_2);
    element_pairing(this->tmp_GT_3, this->tmp_G_3, ciphertext->ct_0.ct0_3);

    element_mul(den, this->tmp_GT, this->tmp_GT_2);
    element_mul(den, den, this->tmp_GT_3);

    // res = - num / den
    element_div(num, num, den);
    element_neg(num, num);
    this->Hash2(&num, &this->tmp_Zn);

    element_div(*res_r, ciphertext->ct_, this->tmp_Zn);

    element_clear(num);
    element_clear(den);
}

/**
 * get ID^
 * input: mpk, ID, mi_oj, type
 * output: ID_
 */
void ABET::GetID_(mpk *mpk, ID *ID, int mi_oj, int type, element_t *ID_){
    if(type == MODIFIER){
        element_set(this->tmp_G, mpk->g);
        for(int i=1;i<=mi_oj;i++){
            element_pow_zn(this->tmp_G_2, *mpk->gk[k-i+1], *ID->Ik[i]);
            element_mul(this->tmp_G, this->tmp_G, this->tmp_G_2);
        }
        element_set(*ID_, this->tmp_G);
    }else if(type == OWNER){
        element_set(this->tmp_H, mpk->h);
        for(int i=1;i<=mi_oj;i++){
            element_pow_zn(this->tmp_H_2, *mpk->hk[k-i+1], *ID->Ik[i]);
            element_mul(this->tmp_H, this->tmp_H, this->tmp_H_2);
        }
        element_set(*ID_, this->tmp_H);
    }
    
}


ABET::~ABET(){
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

    element_clear(this->d1);
    element_clear(this->d2);
    element_clear(this->d3);

    element_clear(this->r1);
    element_clear(this->r2);

    element_clear(this->b1r1a1);
    element_clear(this->b1r1a2);
    element_clear(this->b2r2a1);
    element_clear(this->b2r2a2);
    element_clear(this->r1r2a1);
    element_clear(this->r1r2a2);

    element_clear(this->s1);
    element_clear(this->s2);
}