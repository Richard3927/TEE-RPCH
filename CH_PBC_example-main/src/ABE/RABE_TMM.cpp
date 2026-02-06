#include <ABE/RABE_TMM.h>

RABE_TMM::RABE_TMM(element_t *_G, element_t *_H, element_t *_GT, element_t *_Zn){
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
    element_init_same_as(this->tmp_GT_4, *this->GT);
    element_init_same_as(this->tmp_Zn, *this->Zn);
    element_init_same_as(this->tmp_Zn_2, *this->Zn);
    element_init_same_as(this->tmp_Zn_3, *this->Zn);

    element_init_same_as(this->d1, *this->Zn);
    element_init_same_as(this->d2, *this->Zn);
    element_init_same_as(this->d3, *this->Zn);

    element_init_same_as(this->r1, *this->Zn);
    element_init_same_as(this->r2, *this->Zn);

    element_init_same_as(this->b1r1a1, *this->Zn);
    element_init_same_as(this->b1r1a2, *this->Zn);
    element_init_same_as(this->b2r2a1, *this->Zn);
    element_init_same_as(this->b2r2a2, *this->Zn);
    element_init_same_as(this->r1r2a1, *this->Zn);
    element_init_same_as(this->r1r2a2, *this->Zn);

    element_init_same_as(this->s1, *this->Zn);
    element_init_same_as(this->s2, *this->Zn);



}

RABE_TMM::~RABE_TMM(){

}

/**
 * hash function {0,1}* -> G
 * input: m
 * output: res
 */
void RABE_TMM::Hash(std::string m, element_t *res){
    element_from_hash(*res, (void*)m.c_str(), m.length());
    // SHA256
    Hm_1(*res, *res);
}

/**
 * hash function {0,1}* -> Zn
 * input: m
 * output: res
 */
void RABE_TMM::Hash(element_t *m, element_t *res){
    // SHA256
    Hm_1(*m, *res);
}

/**
 * input: n
 * output: mpk, msk, st, rl
 */
void RABE_TMM::Setup(int n, mpk *mpk, msk *msk, vector<revokedPreson *> *rl, binary_tree_RABE *&st){
    element_random(mpk->g);
    element_random(mpk->h);
    element_random(msk->a1);
    element_random(msk->a2);
    element_random(msk->b1);
    element_random(msk->b2);

    element_random(this->d1);
    element_random(this->d2);
    element_random(this->d3);

    // g^d1, g^d2, g^d3
    element_pow_zn(msk->g_pow_d1, mpk->g, this->d1);
    element_pow_zn(msk->g_pow_d2, mpk->g, this->d2);
    element_pow_zn(msk->g_pow_d3, mpk->g, this->d3);

    element_pow_zn(mpk->H1, mpk->h, msk->a1);
    element_pow_zn(mpk->H2, mpk->h, msk->a2);

    // e(g,h)^(d1a1+d3)
    element_mul(this->tmp_Zn, this->d1, msk->a1);
    element_add(this->tmp_Zn, this->tmp_Zn, this->d3);
    element_pairing(this->tmp_GT, mpk->g, mpk->h);
    element_pow_zn(mpk->T1, this->tmp_GT, this->tmp_Zn);
    // e(g,h)^(d2a2+d3)
    element_mul(this->tmp_Zn, this->d2, msk->a2);
    element_add(this->tmp_Zn, this->tmp_Zn, this->d3);
    element_pairing(this->tmp_GT, mpk->g, mpk->h);
    element_pow_zn(mpk->T2, this->tmp_GT, this->tmp_Zn);

    // initialize rl
    rl->clear();
    
    // initialize st
    st = new binary_tree_RABE(n, this->G, this->Zn);
}

/**
 * input: mpk, msk, st, id, attr_list
 * output: skid, st
 */
void RABE_TMM::KGen(mpk *mpk, msk *msk, binary_tree_RABE *st, element_t *id, std::vector<std::string> *attr_list, skid *skid){
    element_random(this->r1);
    element_random(this->r2);
    // sk0 = (h^(b1r1), h^(b2r2), h^(r1+r2))
    element_mul(this->tmp_Zn, msk->b1, this->r1);
    element_pow_zn(skid->sk0.sk_1, mpk->h, this->tmp_Zn);
    // (b1 * r1) / a1
    element_div(this->b1r1a1, this->tmp_Zn, msk->a1);
    // (b1 * r1) / a2
    element_div(this->b1r1a2, this->tmp_Zn, msk->a2);
    element_mul(this->tmp_Zn, msk->b2, this->r2);
    element_pow_zn(skid->sk0.sk_2, mpk->h, this->tmp_Zn);
    // (b2 * r2) / a1
    element_div(this->b2r2a1, this->tmp_Zn, msk->a1);
    // (b2 * r2) / a2
    element_div(this->b2r2a2, this->tmp_Zn, msk->a2);
    element_add(this->tmp_Zn, this->r1, this->r2);
    element_pow_zn(skid->sk0.sk_3, mpk->h, this->tmp_Zn);
    // (r1 + r2) / a1
    element_div(this->r1r2a1, this->tmp_Zn, msk->a1);
    // (r1 + r2) / a2
    element_div(this->r1r2a2, this->tmp_Zn, msk->a2);

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
        // H(y31)^r1r2a1
        std::string y31 = attr_list->at(i) + "3" + "1";
        this->Hash(y31, &this->tmp_G_3);
        element_pow_zn(this->tmp_G_3, this->tmp_G_3, this->r1r2a1);
        // g^(sigma_y / a1)
        element_div(this->tmp_Zn_2, this->tmp_Zn, msk->a1);
        element_pow_zn(this->tmp_G_4, mpk->g, this->tmp_Zn_2);
        // sky1
        element_mul(skid->sk_y[i]->sk_1, this->tmp_G, this->tmp_G_2);
        element_mul(skid->sk_y[i]->sk_1, skid->sk_y[i]->sk_1, this->tmp_G_3);
        element_mul(skid->sk_y[i]->sk_1, skid->sk_y[i]->sk_1, this->tmp_G_4);

        // t = 2
        // H(y12)^b1r1a2
        std::string y12 = attr_list->at(i) + "1" + "2";
        this->Hash(y12, &this->tmp_G);
        element_pow_zn(this->tmp_G, this->tmp_G, this->b1r1a2);
        // H(y22)^b2r2a2
        std::string y22 = attr_list->at(i) + "2" + "2";
        this->Hash(y22, &this->tmp_G_2);
        element_pow_zn(this->tmp_G_2, this->tmp_G_2, this->b2r2a2);
        // H(y32)^r1r2a2
        std::string y32 = attr_list->at(i) + "3" + "2";
        this->Hash(y32, &this->tmp_G_3);
        element_pow_zn(this->tmp_G_3, this->tmp_G_3, this->r1r2a2);
        // g^(sigma_y / a2)
        element_div(this->tmp_Zn_2, this->tmp_Zn, msk->a2);
        element_pow_zn(this->tmp_G_4, mpk->g, this->tmp_Zn_2);
        // sky2
        element_mul(skid->sk_y[i]->sk_2, this->tmp_G, this->tmp_G_2);
        element_mul(skid->sk_y[i]->sk_2, skid->sk_y[i]->sk_2, this->tmp_G_3);
        element_mul(skid->sk_y[i]->sk_2, skid->sk_y[i]->sk_2, this->tmp_G_4);

        // sky3 = g^(-sigma_y)
        element_neg(this->tmp_Zn, this->tmp_Zn);
        element_pow_zn(skid->sk_y[i]->sk_3, mpk->g, this->tmp_Zn);
    }

    // sk_prime
    sk tmp_sk_prime;
    tmp_sk_prime.Init(this->G);

    // sigma_prime
    element_random(this->tmp_Zn);
    // t = 1
    // g^d1
    element_pow_zn(tmp_sk_prime.sk_1, mpk->g, this->d1);
    // H(0111)^b1r1a1
    std::string y0111 = "0111";
    this->Hash(y0111, &this->tmp_G);
    element_pow_zn(this->tmp_G, this->tmp_G, this->b1r1a1);
    // H(0121)^b2r2a1
    std::string y0121 = "0121";
    this->Hash(y0121, &this->tmp_G_2);
    element_pow_zn(this->tmp_G_2, this->tmp_G_2, this->b2r2a1);
    // H(0131)^r1r2a1
    std::string y0131 = "0131";
    this->Hash(y0131, &this->tmp_G_3);
    element_pow_zn(this->tmp_G_3, this->tmp_G_3, this->r1r2a1);
    // g^(sigma_prime / a1)
    element_div(this->tmp_Zn_2, this->tmp_Zn, msk->a1);
    element_pow_zn(this->tmp_G_4, mpk->g, this->tmp_Zn_2);
    // sk_prime1
    element_mul(tmp_sk_prime.sk_1, tmp_sk_prime.sk_1, this->tmp_G);
    element_mul(tmp_sk_prime.sk_1, tmp_sk_prime.sk_1, this->tmp_G_2);
    element_mul(tmp_sk_prime.sk_1, tmp_sk_prime.sk_1, this->tmp_G_3);
    element_mul(tmp_sk_prime.sk_1, tmp_sk_prime.sk_1, this->tmp_G_4);

    // t = 2
    // g^d2
    element_pow_zn(tmp_sk_prime.sk_2, mpk->g, this->d2);
    // H(0112)^b1r1a2
    std::string y0112 = "0112";
    this->Hash(y0112, &this->tmp_G);
    element_pow_zn(this->tmp_G, this->tmp_G, this->b1r1a2);
    // H(0122)^b2r2a2
    std::string y0122 = "0122";
    this->Hash(y0122, &this->tmp_G_2);
    element_pow_zn(this->tmp_G_2, this->tmp_G_2, this->b2r2a2);
    // H(0132)^r1r2a2
    std::string y0132 = "0132";
    this->Hash(y0132, &this->tmp_G_3);
    element_pow_zn(this->tmp_G_3, this->tmp_G_3, this->r1r2a2);
    // g^(sigma_prime / a2)
    element_div(this->tmp_Zn_2, this->tmp_Zn, msk->a2);
    element_pow_zn(this->tmp_G_4, mpk->g, this->tmp_Zn_2);
    // sk_prime2
    element_mul(tmp_sk_prime.sk_2, tmp_sk_prime.sk_2, this->tmp_G);
    element_mul(tmp_sk_prime.sk_2, tmp_sk_prime.sk_2, this->tmp_G_2);
    element_mul(tmp_sk_prime.sk_2, tmp_sk_prime.sk_2, this->tmp_G_3);
    element_mul(tmp_sk_prime.sk_2, tmp_sk_prime.sk_2, this->tmp_G_4);

    // sk_prime3 = g^d3 * g ^ (-sigma_prime)
    element_neg(this->tmp_Zn, this->tmp_Zn);
    element_pow_zn(tmp_sk_prime.sk_3, mpk->g, this->tmp_Zn);
    element_mul(tmp_sk_prime.sk_3, tmp_sk_prime.sk_3, msk->g_pow_d3);

    // pick an unassigned node in st
    // id
    element_random(*id);
    // time_t = 2025.12.31 0:00:00
    time_t target_time = TimeCast(2025, 12, 31, 0, 0, 0);
    
    // find and set an unassigned node
    binary_tree_node_RABE *node = st->setLeafNode(id, target_time);

    // set sk_theta
    while(node != NULL){
        element_set0(this->tmp_G);
        if(element_is0(*node->getGtheta())){
            // store gtheta in theta
            element_random(this->tmp_G);
            node->setGtheta(&this->tmp_G);
        }else{
            element_set(this->tmp_G, *node->getGtheta());
        }
        // sk'3 = g^d3 * g^(-sigma_prime) / gtheta
        element_div(this->tmp_G_2, tmp_sk_prime.sk_3, this->tmp_G);

        sk_prime *sk_theta = new sk_prime();
        sk_theta->Init(this->G);
        // sk_theta->theta = node;
        sk_theta->theta = node;
        element_set(sk_theta->sk_prime.sk_1, tmp_sk_prime.sk_1);
        element_set(sk_theta->sk_prime.sk_2, tmp_sk_prime.sk_2);
        element_set(sk_theta->sk_prime.sk_3, this->tmp_G_2);
        skid->sk_prime.push_back(sk_theta);

        node = node->getParent();
    }
}

vector<binary_tree_node_RABE *> RABE_TMM::KUNodes(binary_tree_RABE *st, vector<revokedPreson *> *rl, time_t t)
{
    // get rl_ids
    vector<element_t *> rl_ids; 
    for(int i = 0;i < rl->size();i++){
        rl_ids.push_back(&(rl->at(i)->id));
    }
    return st->KUNodes(rl_ids, t);
}

/**
 * input: mpk, st, rl, t
 * output: kut
 */
void RABE_TMM::KUpt(mpk *mpk, binary_tree_RABE *st, vector<revokedPreson *> *rl, time_t t, kut *kut){
    vector<binary_tree_node_RABE *> thetas = this->KUNodes(st, rl, t);

    kut->t = t;
    for(int i = 0;i < thetas.size();i++){
        // rtheta
        element_random(this->tmp_Zn);
        // gtheta * (H(t)^rtheta)
        string _t = to_string(t);
        this->Hash(_t, &this->tmp_G);
        element_pow_zn(this->tmp_G, this->tmp_G, this->tmp_Zn);
        element_mul(this->tmp_G, *thetas[i]->getGtheta(), this->tmp_G);
        // h^rtheta
        element_pow_zn(this->tmp_H, mpk->h, this->tmp_Zn);

        kuTheta *ku_theta = new kuTheta();
        ku_theta->Init(this->G, this->H);
        ku_theta->theta = thetas[i];
        element_set(ku_theta->ku_theta_1, this->tmp_G);
        element_set(ku_theta->ku_theta_2, this->tmp_H);

        kut->ku_theta.push_back(ku_theta);
    }
}

/**
 * input: mpk, skid, kut
 * output: dkidt
 */
void RABE_TMM::DKGen(mpk *mpk, skid *skid, kut *kut, dkidt *dkidt){
    // judge Path(id) ∩ KUNodes(st, rl, t) != NULL
    int index_skid = -1;
    int index_kut = -1;
    for(int i = 0;i<skid->sk_prime.size();i++){
        for(int j = 0;j<kut->ku_theta.size();j++){
            if(skid->sk_prime[i]->theta == kut->ku_theta[j]->theta){
                index_skid = i;
                index_kut = j;
                break;
            }
        }
    }
    if(index_skid == -1 || index_kut == -1){
        printf("ERROR: Path(id) ∩ KUNodes(st, rl, t) == NULL\n");
        return;
    }

    dkidt->t = kut->t;

    // sk' = (sk1', sk2', sk3')
    element_set(dkidt->sk_prime.sk_1, skid->sk_prime[index_skid]->sk_prime.sk_1);
    element_set(dkidt->sk_prime.sk_2, skid->sk_prime[index_skid]->sk_prime.sk_2);
    // sk3' = g^d3 * g^(-sigma_prime) * H(1t)^(rtheta + rtheta')
    element_mul(dkidt->sk_prime.sk_3, skid->sk_prime[index_skid]->sk_prime.sk_3, kut->ku_theta[index_kut]->ku_theta_1);
    // TODO kut 是公开的，先直接放入dkidt中
    element_set(dkidt->skt1, kut->ku_theta[index_kut]->ku_theta_2);

    // sk0 = (sk01, sk02, sk03)
    element_set(dkidt->sk0.sk_1, skid->sk0.sk_1);
    element_set(dkidt->sk0.sk_2, skid->sk0.sk_2);
    element_set(dkidt->sk0.sk_3, skid->sk0.sk_3);

    // sky
    for(int i = 0;i < skid->sk_y.size();i++){
        sk *tmp_sk_y = new sk();
        tmp_sk_y->Init(this->G);
        element_set(tmp_sk_y->sk_1, skid->sk_y[i]->sk_1);
        element_set(tmp_sk_y->sk_2, skid->sk_y[i]->sk_2);
        element_set(tmp_sk_y->sk_3, skid->sk_y[i]->sk_3);
        dkidt->sk_y.push_back(tmp_sk_y);
    }
}

/**
 * input: mpk, msg, policy_str, t, s1, s2
 * output: ciphertext
 */
void RABE_TMM::Enc(mpk *mpk, element_t *msg, std::string policy_str,time_t t, element_t *s1, element_t *s2, ciphertext *ciphertext)
{
    this->policy_str = policy_str;

    policy_resolution pr;
    policy_generation pg;
    element_random(this->tmp_Zn);

    vector<string>* postfix_expression = pr.infixToPostfix(policy_str);
#ifndef CH_PBC_QUIET
    for(int i = 0;i < postfix_expression->size();i++){
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
    for(int i = 0;i < rows;i++){
        for(int j = 0;j < cols;j++){
            element_printf("%B ", M->getElement(i, j));
        }
        printf("\n");
    }
#endif

    // s1,s2
    element_set(this->s1, *s1);
    element_set(this->s2, *s2);

    // t
    ciphertext->t = t;

    // ct0
    // ct0_1 = H1^s1
    element_pow_zn(ciphertext->ct0.ct0_1, mpk->H1, this->s1);
    // ct0_2 = H2^s2
    element_pow_zn(ciphertext->ct0.ct0_2, mpk->H2, this->s2);
    // ct0_3 = h^(s1+s2)
    element_add(this->tmp_Zn_2, this->s1, this->s2);
    element_pow_zn(ciphertext->ct0.ct0_3, mpk->h, this->tmp_Zn_2);
    // ct0_4 = H(t)^(s1+s2)
    string _t = to_string(ciphertext->t);
    this->Hash(_t, &this->tmp_G);
    element_pow_zn(ciphertext->ct0.ct0_4, this->tmp_G, this->tmp_Zn_2);

    // ct_prime = T1^s1 * T2^s2 * msg
    element_pow_zn(this->tmp_GT, mpk->T1, this->s1);
    element_pow_zn(this->tmp_GT_2, mpk->T2, this->s2);
    element_mul(this->tmp_GT_3, this->tmp_GT, this->tmp_GT_2);
    // H(T1^s1 * T2^s2)
    this->Hash(&this->tmp_GT_3, &this->tmp_Zn_3);
#ifndef CH_PBC_QUIET
    PrintElement("msg", *msg);
    PrintElement("tmp_Zn_3", this->tmp_Zn_3);
#endif
    element_mul(ciphertext->ct_prime, this->tmp_Zn_3, *msg);

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
 * input: mpk, ciphertext, dkidt, 
 * output: res
 */
void RABE_TMM::Dec(mpk *mpk, ciphertext *ciphertext, dkidt *dkidt, element_t *res)
{   
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
#ifndef CH_PBC_QUIET
    printf("rows: %ld, cols: %ld\n", r, c);
    for(int i = 0;i < r;i++){
        for(int j = 0;j < c;j++){
            element_printf("%B ", inverse_attributesMatrix->getElement(i, j));
        }
        printf("\n");
    }
#endif
    element_t_vector* unit = getCoordinateAxisUnitVector(inverse_attributesMatrix);

    element_t_vector* x= new element_t_vector(inverse_attributesMatrix->col(), inverse_attributesMatrix->getElement(0, 0));

    signed long int type = gaussElimination(x, inverse_attributesMatrix, unit);
    if (-1 == type) {
        throw std::runtime_error("POLICY_NOT_SATISFIED");
    }
#ifndef CH_PBC_QUIET
    printf("type: %ld\n", type);
    // print x
    printf("Yi:\n");
    x->printVector();
#endif


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
    // ct_prime * e(tmp_G, sk0_1) * e(tmp_G_2, sk0_2) * e(tmp_G_3, sk0_3) * e(ct0_4, sk0_4)
    element_pairing(this->tmp_GT, this->tmp_G, dkidt->sk0.sk_1);
    element_pairing(this->tmp_GT_2, this->tmp_G_2, dkidt->sk0.sk_2);
    element_pairing(this->tmp_GT_3, this->tmp_G_3, dkidt->sk0.sk_3);
    element_pairing(this->tmp_GT_4, ciphertext->ct0.ct0_4, dkidt->skt1);

    element_mul(num, this->tmp_GT, this->tmp_GT_2);
    element_mul(num, num, this->tmp_GT_3);
    element_mul(num, num, this->tmp_GT_4);

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
        element_pow_zn(this->tmp_G_4, dkidt->sk_y[attr_map[pai[i]]]->sk_1, x->getElement(count));
        element_mul(this->tmp_G, this->tmp_G, this->tmp_G_4);
        element_pow_zn(this->tmp_G_4, dkidt->sk_y[attr_map[pai[i]]]->sk_2, x->getElement(count));
        element_mul(this->tmp_G_2, this->tmp_G_2, this->tmp_G_4);
        element_pow_zn(this->tmp_G_4, dkidt->sk_y[attr_map[pai[i]]]->sk_3, x->getElement(count));
        element_mul(this->tmp_G_3, this->tmp_G_3, this->tmp_G_4);
        count++;
    }
    // sk_prime_1 * tmp_G
    element_mul(this->tmp_G, dkidt->sk_prime.sk_1, this->tmp_G);
    // sk_prime_2 * tmp_G_2
    element_mul(this->tmp_G_2, dkidt->sk_prime.sk_2, this->tmp_G_2);
    // sk_prime_3 * tmp_G_3
    element_mul(this->tmp_G_3, dkidt->sk_prime.sk_3, this->tmp_G_3);

    // e(tmp_G, ct01) * e(tmp_G_2, ct02) * e(tmp_G_3, ct03)
    element_pairing(this->tmp_GT, this->tmp_G, ciphertext->ct0.ct0_1);
    element_pairing(this->tmp_GT_2, this->tmp_G_2, ciphertext->ct0.ct0_2);
    element_pairing(this->tmp_GT_3, this->tmp_G_3, ciphertext->ct0.ct0_3);

    element_mul(den, this->tmp_GT, this->tmp_GT_2);
    element_mul(den, den, this->tmp_GT_3);

    // res = den / num
    element_div(this->tmp_GT, den, num);
    this->Hash(&this->tmp_GT, &this->tmp_Zn);
    // res = ct_prime / res
    element_div(*res, ciphertext->ct_prime, this->tmp_Zn);

    element_clear(num);
    element_clear(den);
}

/**
 * input: rl, id, t
 */
void RABE_TMM::Rev(vector<revokedPreson *> *rl, element_t *id, time_t t){
    revokedPreson *rp = new revokedPreson();
    rp->Init(this->Zn);
    element_set(rp->id, *id);
    rp->time = t;
    rl->push_back(rp);
}
