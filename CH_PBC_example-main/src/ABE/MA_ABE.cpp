#include <ABE/MA_ABE.h>


MA_ABE::MA_ABE(element_t *_G, element_t *_H, element_t *_GT, element_t *_Zn){
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

    element_init_same_as(this->z, *this->Zn);
}

/**
 * GlobalSetup() -> gp
 * @param gpk global public key
 */
void MA_ABE::GlobalSetup(gpk *gpk){
    element_random(gpk->g);
}
/**
 * GlobalSetup(g) -> gp
 * @param gpk global public key
 * @param g generator g
 */
void MA_ABE::GlobalSetup(gpk *gpk, element_t *g){
    element_set(gpk->g, *g);
}

/**
 * AuthSetup(theta) -> (pktheta, sktheta)
 * @param gpk global public key
 * @param A an attribute of the authority
 * @param pkTheta public key of theta
 * @param skTheta secret key of theta
 */
void MA_ABE::AuthSetup(gpk *gpk, string A, pkTheta *pkTheta, skTheta *skTheta){
    element_random(skTheta->aTheta);
    element_random(skTheta->yTheta);
    // pkTheta_1 = e(g,g)^aTheta
    element_pairing(pkTheta->pkTheta_1, gpk->g, gpk->g);
    element_pow_zn(pkTheta->pkTheta_1, pkTheta->pkTheta_1, skTheta->aTheta);
    // pkTheta_2 = g^yTheta
    element_pow_zn(pkTheta->pkTheta_2, gpk->g, skTheta->yTheta);

    pkTheta->A = A;
}

/**
 * HGID(bit, gid) -> G
 * @param bit 0 or 1
 * @param gid
 * @param res 
 */
void MA_ABE::HGID(bool bit, string gid, element_t *res){
    string m = to_string(bit) + gid;
    Hm_1(m, *res);
}

/**
 * Hu(u) -> G
 * @param u
 * @param res 
 */
void MA_ABE::Hu(string u, element_t *res){
    Hm_1(u, *res);
}

/**
 * KeyGen(gpk, skTheta, gid, A) -> skgidA
 * @param gpk global public key
 * @param skTheta secret key of theta
 * @param gid a global identifier
 * @param A an attribute
 * @param skgidA secret key of gid and A
 */
void MA_ABE::KeyGen(gpk *gpk, skTheta *skTheta, string gid, string A, skgidA *skgidA){
    // t
    element_random(this->tmp_Zn);
    // g^aTheta * HGID(0,gid)^yTheta * Hu(A)^t
    element_pow_zn(this->tmp_G, gpk->g, skTheta->aTheta);
    this->HGID(0, gid, &this->tmp_G_2);
    element_pow_zn(this->tmp_G_2, this->tmp_G_2, skTheta->yTheta);
    this->Hu(A, &this->tmp_G_3);
    element_pow_zn(this->tmp_G_3, this->tmp_G_3, this->tmp_Zn);
    element_mul(skgidA->skgidA_0, this->tmp_G, this->tmp_G_2);
    element_mul(skgidA->skgidA_0, skgidA->skgidA_0, this->tmp_G_3);

    // g^t
    element_pow_zn(skgidA->skgidA_1, gpk->g, this->tmp_Zn);

    skgidA->gid = gid;
    skgidA->A = A;
}

/**
 * Encrypt(gpk, pkThetas, polocy, m) -> c
 * @param gpk global public key
 * @param pkThetas public keys of the authorities
 * @param policy access policy
 * @param m message
 * @param C ciphertext
 */
void MA_ABE::Encrypt(gpk *gpk, vector<pkTheta *> *pkThetas, string policy, element_t *m, ciphertext *C){
    policy_resolution pr;
    policy_generation pg;
    element_random(this->tmp_Zn);

    vector<string>* postfix_expression = pr.infixToPostfix(policy);
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

    C->policy = policy;

    // z = H(policy)
    this->Hu(policy, &this->z);
    PrintElement("z", this->z);

    // c0 = m * e(g,g)^z
    element_pairing(C->c0, gpk->g, gpk->g);
    element_pow_zn(C->c0, C->c0, this->z);
    element_mul(C->c0, C->c0, *m);

    // compute ci
    // ti = H(policy, 0, i)
    vector<element_s *> ti;
    for(int i = 0;i<rows;i++){
        element_t *tmp_ti = new element_t[1];
        element_init_same_as(*tmp_ti, *this->Zn);
        string str_ti = policy + "0" + to_string(i);
        this->Hu(str_ti, tmp_ti);
        ti.push_back(*tmp_ti);
    }
    // vi = H(policy, 1, i), wi = H(policy, 2, i)
    vector<element_s *> vi;
    vector<element_s *> wi;
    for(int i = 0;i<cols;i++){
        element_t *tmp_vi = new element_t[1];
        element_init_same_as(*tmp_vi, *this->Zn);
        string str_vi = policy + "1" + to_string(i);
        this->Hu(str_vi, tmp_vi);
        vi.push_back(*tmp_vi);

        element_t *tmp_wi = new element_t[1];
        element_init_same_as(*tmp_wi, *this->Zn);
        string str_wi = policy + "2" + to_string(i);
        this->Hu(str_wi, tmp_wi);
        wi.push_back(*tmp_wi);
    }
    // v = (z, v2, ..., vl2)T
    vector<element_s *> v;
    for(int i=0;i<cols;i++){
        element_t *tmp_v = new element_t[1];
        element_init_same_as(*tmp_v, *this->Zn);
        if(i==0){
            element_set(*tmp_v, this->z);
        }else{
            element_set(*tmp_v, vi[i]);
        }
        v.push_back(*tmp_v);
    }
    // w = (0, w2, ..., wl2)T
    vector<element_s *> w;
    for(int i=0;i<cols;i++){
        element_t *tmp_w = new element_t[1];
        element_init_same_as(*tmp_w, *this->Zn);
        if(i==0){
            element_set0(*tmp_w);
        }else{
            element_set(*tmp_w, wi[i]);
        }
        w.push_back(*tmp_w);
    }
    // lamuda = M * v
    vector<element_s *> lamuda;
    for(int i=0;i<rows;i++){
        element_t *tmp_lamuda = new element_t[1];
        element_init_same_as(*tmp_lamuda, *this->Zn);
        element_set0(*tmp_lamuda);
        for(int j=0;j<cols;j++){
            element_mul(this->tmp_Zn, M->getElement(i, j), v[j]);
            element_add(*tmp_lamuda, *tmp_lamuda, this->tmp_Zn);
        }
        lamuda.push_back(*tmp_lamuda);
    }
    // w = M * w
    vector<element_s *> w_tmp;
    for(int i=0;i<rows;i++){
        element_t *tmp_w = new element_t[1];
        element_init_same_as(*tmp_w, *this->Zn);
        element_set0(*tmp_w);
        for(int j=0;j<cols;j++){
            element_mul(this->tmp_Zn, M->getElement(i, j), w[j]);
            element_add(*tmp_w, *tmp_w, this->tmp_Zn);
        }
        w_tmp.push_back(*tmp_w);
    }


    for(int i=0;i<rows;i++){
        // ci_1 = e(g,g)^lamuda_i * e(g,g)^(a*ti)
        string attr = M->getName(i);
        pai[i] = attr;
        element_pairing(tmp_GT, gpk->g, gpk->g);
        element_pow_zn(tmp_GT, tmp_GT, lamuda[i]);
        for(int j=0;j<pkThetas->size();j++){
            if(pkThetas->at(j)->A == attr){
                element_pow_zn(tmp_GT_2, pkThetas->at(j)->pkTheta_1, ti[i]);
                element_pow_zn(tmp_G, pkThetas->at(j)->pkTheta_2, ti[i]);
                break;
            }
        }
        element_mul(C->ci[i]->ci_1, tmp_GT, tmp_GT_2);

        // ci_2 = g^(-ti)
        element_neg(tmp_Zn, ti[i]);
        element_pow_zn(C->ci[i]->ci_2, gpk->g, tmp_Zn);

        // ci_3 = g^(y*ti) * g^wi
        element_pow_zn(C->ci[i]->ci_3, gpk->g, w_tmp[i]);
        element_mul(C->ci[i]->ci_3, C->ci[i]->ci_3, tmp_G);

        // ci_4 = Hu(π(i))^ti
        this->Hu(attr, &tmp_G);
        element_pow_zn(C->ci[i]->ci_4, tmp_G, ti[i]);
    }

    // free
    for(int i=0;i<rows;i++){
        element_clear(ti[i]);
        element_clear(lamuda[i]);
        element_clear(w_tmp[i]);
    }
    for(int i=0;i<cols;i++){
        element_clear(vi[i]);
        element_clear(wi[i]);
        element_clear(v[i]);
        element_clear(w[i]);
    }
}

/**
 * Decrypt(skgidAs, c) -> m
 * @param skgidAs secret keys of the authorities
 * @param C ciphertext
 * @param res message
 */
void MA_ABE::Decrypt(vector<MA_ABE::skgidA *> *skgidAs, ciphertext *C, element_t *res){
    // compute Yi
    // get original matrix
    policy_resolution pr;
    policy_generation pg;
    element_random(this->tmp_Zn);
    vector<string>* postfix_expression = pr.infixToPostfix(C->policy);
    binary_tree* binary_tree_expression = pr.postfixToBinaryTree(postfix_expression, this->tmp_Zn);
    pg.generatePolicyInMatrixForm(binary_tree_expression);
    element_t_matrix* M = pg.getPolicyInMatrixFormFromTree(binary_tree_expression);
    // get matrix with attributes
    element_t_matrix* attributesMatrix = new element_t_matrix();
    unsigned long int rows = C->ci.size();
    for(unsigned long int i=0; i<rows;i++){
        // judge whether the attribute of the policy is in the skgidAs
        for(int k=0;k<skgidAs->size();k++){
            if(skgidAs->at(k)->A == pai[i]){
                element_t_vector *v = new element_t_vector();
                for (signed long int j = 0; j < M->col(); ++j) {
                    v->pushBack(M->getElement(i, j));
                }
                attributesMatrix->pushBack(v);
                break;
            }
        }
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


    element_set1(tmp_GT_3);
    int count = 0;
    for(int i=0;i<rows;i++){
        // judge whether the attribute of the policy is in the skgidAs
        for(int k=0;k<skgidAs->size();k++){
            if(skgidAs->at(k)->A == pai[i]){
                element_set(tmp_GT, C->ci[i]->ci_1);
                // e(skgidA_0,ci_2)
                element_pairing(tmp_GT_2, skgidAs->at(k)->skgidA_0, C->ci[i]->ci_2);
                element_mul(tmp_GT, tmp_GT, tmp_GT_2);
                // e(HGID(0,gid),ci_3)
                this->HGID(0, skgidAs->at(k)->gid, &tmp_G);
                element_pairing(tmp_GT_2, tmp_G, C->ci[i]->ci_3);
                element_mul(tmp_GT, tmp_GT, tmp_GT_2);
                // e(skgidA_1,ci_4)
                element_pairing(tmp_GT_2, skgidAs->at(k)->skgidA_1, C->ci[i]->ci_4);
                element_mul(tmp_GT, tmp_GT, tmp_GT_2);

                // tmp_GT^yi
                element_pow_zn(tmp_GT, tmp_GT, x->getElement(count++));

                element_mul(tmp_GT_3, tmp_GT_3, tmp_GT);
                break;
            }
        }
    }
    // res = c0 / tmp_GT_3
    element_div(*res, C->c0, tmp_GT_3);
}

MA_ABE::~MA_ABE(){
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

    element_clear(this->z);
}