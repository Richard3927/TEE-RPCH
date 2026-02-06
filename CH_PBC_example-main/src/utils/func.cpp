#include "utils/func.h"
#include <openssl/sha.h>
#include <sys/time.h>


void Hm(element_t &m, element_t &res, element_t &tmp_Zp, element_t &g) {
    // 计算SHA-256哈希
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    unsigned char bytes1[element_length_in_bytes(m)];
    element_to_bytes(bytes1, m);
    SHA256_Update(&sha256, bytes1, sizeof(bytes1));
    SHA256_Final(hash, &sha256);
    element_from_hash(res, hash, SHA256_DIGEST_LENGTH);
}

void Hgsm(element_t &gs, element_t &m, element_t &res, element_t &tmp_Zp, element_t &g) {
    // 计算SHA-256哈希
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    unsigned char bytes1[element_length_in_bytes(gs)];
    element_to_bytes(bytes1, gs);
    SHA256_Update(&sha256, bytes1, sizeof(bytes1));
    unsigned char bytes2[element_length_in_bytes(m)];
    element_to_bytes(bytes2, m);
    SHA256_Update(&sha256, bytes2, sizeof(bytes2));
    SHA256_Final(hash, &sha256);
    element_from_hash(res, hash, SHA256_DIGEST_LENGTH);
}

/**
 * res = H(m)
 */
void Hm_1(element_t &m, element_t &res) {
    // 计算SHA-256哈希
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    unsigned char bytes1[element_length_in_bytes(m)];
    element_to_bytes(bytes1, m);
    SHA256_Update(&sha256, bytes1, sizeof(bytes1));
    SHA256_Final(hash, &sha256);
    element_from_hash(res, hash, SHA256_DIGEST_LENGTH);
}
void Hm_1(string m, element_t &res) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, m.c_str(), m.length());
    SHA256_Final(hash, &sha256);
    element_from_hash(res, hash, SHA256_DIGEST_LENGTH);
}

void Hgsm_1(element_t &gs, element_t &m, element_t &res) {
    // 计算SHA-256哈希
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    unsigned char bytes1[element_length_in_bytes(gs)];
    element_to_bytes(bytes1, gs);
    SHA256_Update(&sha256, bytes1, sizeof(bytes1));
    unsigned char bytes2[element_length_in_bytes(m)];
    element_to_bytes(bytes2, m);
    SHA256_Update(&sha256, bytes2, sizeof(bytes2));
    SHA256_Final(hash, &sha256);
    element_from_hash(res, hash, SHA256_DIGEST_LENGTH);
}


/**
 * FCR_CH_PreQA_DKS_2020
 */
void Hm_2(element_t &y, element_t &h, element_t &m,element_t &u1,element_t &u2, element_t &res) {
    // 计算SHA-256哈希
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    unsigned char bytes1[element_length_in_bytes(y)];
    element_to_bytes(bytes1, y);
    SHA256_Update(&sha256, bytes1, sizeof(bytes1));
    unsigned char bytes2[element_length_in_bytes(h)];
    element_to_bytes(bytes2, h);
    SHA256_Update(&sha256, bytes2, sizeof(bytes2));
    unsigned char bytes3[element_length_in_bytes(m)];
    element_to_bytes(bytes3, m);
    SHA256_Update(&sha256, bytes3, sizeof(bytes3));
    unsigned char bytes4[element_length_in_bytes(u1)];
    element_to_bytes(bytes4, u1);
    SHA256_Update(&sha256, bytes4, sizeof(bytes4));
    unsigned char bytes5[element_length_in_bytes(u2)];
    element_to_bytes(bytes5, u2);
    SHA256_Update(&sha256, bytes5, sizeof(bytes5));

    SHA256_Final(hash, &sha256);
    element_from_hash(res, hash, SHA256_DIGEST_LENGTH);
}

/**
 * CR_CH_DSS_2020
 */
void Hm_3(element_t &y, element_t &h1, element_t &h2, element_t &m,
            element_t &u11,element_t &u12, element_t &u2, 
            element_t &res) {
    // 计算SHA-256哈希
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    unsigned char bytes1[element_length_in_bytes(y)];
    element_to_bytes(bytes1, y);
    SHA256_Update(&sha256, bytes1, sizeof(bytes1));
    unsigned char bytes2[element_length_in_bytes(h1)];
    element_to_bytes(bytes2, h1);
    SHA256_Update(&sha256, bytes2, sizeof(bytes2));
    unsigned char bytes3[element_length_in_bytes(h2)];
    element_to_bytes(bytes3, h2);
    SHA256_Update(&sha256, bytes3, sizeof(bytes3));
    unsigned char bytes4[element_length_in_bytes(m)];
    element_to_bytes(bytes4, m);
    SHA256_Update(&sha256, bytes4, sizeof(bytes4));
    unsigned char bytes5[element_length_in_bytes(u11)];
    element_to_bytes(bytes5, u11);
    SHA256_Update(&sha256, bytes5, sizeof(bytes5));
    unsigned char bytes6[element_length_in_bytes(u12)];
    element_to_bytes(bytes6, u12);
    SHA256_Update(&sha256, bytes6, sizeof(bytes6));
    unsigned char bytes7[element_length_in_bytes(u2)];
    element_to_bytes(bytes7, u2);
    SHA256_Update(&sha256, bytes7, sizeof(bytes7));
    
    SHA256_Final(hash, &sha256);
    element_from_hash(res, hash, SHA256_DIGEST_LENGTH);
}

/**
 * input: m1,m2,m3
 * output: res
 */
void Hm_4(element_t &m1, element_t &m2, element_t &m3, element_t &res) {
    // 计算SHA-256哈希
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    unsigned char bytes1[element_length_in_bytes(m1)];
    element_to_bytes(bytes1, m1);
    SHA256_Update(&sha256, bytes1, sizeof(bytes1));
    unsigned char bytes2[element_length_in_bytes(m2)];
    element_to_bytes(bytes2, m2);
    SHA256_Update(&sha256, bytes2, sizeof(bytes2));
    unsigned char bytes3[element_length_in_bytes(m3)];
    element_to_bytes(bytes3, m3);
    SHA256_Update(&sha256, bytes3, sizeof(bytes3));
        
    SHA256_Final(hash, &sha256);
    element_from_hash(res, hash, SHA256_DIGEST_LENGTH);
}

/**
 * @param m1: message 1
 * @param m2: message 2
 * @param m3: message 3
 * @param m4: message 4
 * @param res: hash value
 */
void Hm_5(element_t &m1, element_t &m2, element_t &m3, element_t &m4, element_t &res) {
    // 计算SHA-256哈希
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    unsigned char bytes1[element_length_in_bytes(m1)];
    element_to_bytes(bytes1, m1);
    SHA256_Update(&sha256, bytes1, sizeof(bytes1));
    unsigned char bytes2[element_length_in_bytes(m2)];
    element_to_bytes(bytes2, m2);
    SHA256_Update(&sha256, bytes2, sizeof(bytes2));
    unsigned char bytes3[element_length_in_bytes(m3)];
    element_to_bytes(bytes3, m3);
    SHA256_Update(&sha256, bytes3, sizeof(bytes3));
    unsigned char bytes4[element_length_in_bytes(m4)];
    element_to_bytes(bytes4, m4);
    SHA256_Update(&sha256, bytes4, sizeof(bytes4));
        
    SHA256_Final(hash, &sha256);
    element_from_hash(res, hash, SHA256_DIGEST_LENGTH);
}

int CountSize(element_t &t) {
    return element_length_in_bytes(t);
}


void PrintElement(std::string element_name, element_t &element){
    printf("%s = ", element_name.c_str());
    element_printf("%B\n", element);
}
void PrintElementsize(std::string element_name, element_t &element){
    printf("size of %s = %d bytes\n", element_name.c_str(), CountSize(element));
}
void PrintElementAndSize(std::string element_name, element_t &element){
    PrintElement(element_name, element);
    PrintElementsize(element_name, element);
}
void PrintMpz(std::string mpz_name, mpz_t &mpz){
    gmp_printf("%s = %Zd\n", mpz_name.c_str(), mpz);
}
void PrintMpzsize(std::string mpz_name, mpz_t &mpz){
    printf("size of %s = %ld bytes\n", mpz_name.c_str(), (mpz_sizeinbase(mpz, 2) + 7) / 8);
}
void PrintMpzAndSize(std::string mpz_name, mpz_t &mpz){
    PrintMpz(mpz_name, mpz);
    PrintMpzsize(mpz_name, mpz);
}

/**
 * hash mod n
 */
void Hm_n(mpz_t &m, mpz_t &res,  mpz_t &n) {
    // 计算SHA-256哈希
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    size_t m_size = (mpz_sizeinbase(m, 2) + 7) / 8;   // 计算字节大小
    unsigned char* bytes1 = new unsigned char[m_size];
    mpz_export(bytes1, nullptr, 1, 1, 0, 0, m);       // 将 mpz_t 转换为字节数组
    SHA256_Update(&sha256, bytes1, m_size);           // 更新哈希值
    delete[] bytes1;  // 释放内存

  
    SHA256_Final(hash, &sha256);
    
    // 将哈希值转换为 mpz_t 并存储到 res 中
    mpz_import(res, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, hash);

    // 将结果映射到 n 的范围内，计算 res = res mod n
    mpz_mod(res, res, n);
}
/**
 * hash mod n
 */
void Hm_n(mpz_t &res, string m, mpz_t &n) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, m.c_str(), m.length());
    SHA256_Final(hash, &sha256);
    
    mpz_import(res, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, hash);

    mpz_mod(res, res, n);
}

/**
 * hash mod n
 */
void Hgsm_n(mpz_t &gs, mpz_t &m, mpz_t &res,  mpz_t &n) {
    // 计算SHA-256哈希
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    
    // 将第一个参数 gs 转换为字节数组
    size_t gs_size = (mpz_sizeinbase(gs, 2) + 7) / 8;  // 计算字节大小
    unsigned char* bytes1 = new unsigned char[gs_size];
    mpz_export(bytes1, nullptr, 1, 1, 0, 0, gs);  // 将 mpz_t 转换为字节数组
    SHA256_Update(&sha256, bytes1, gs_size);      // 更新哈希值
    delete[] bytes1;  // 释放内存

    // 将第二个参数 m 转换为字节数组
    size_t m_size = (mpz_sizeinbase(m, 2) + 7) / 8;   // 计算字节大小
    unsigned char* bytes2 = new unsigned char[m_size];
    mpz_export(bytes2, nullptr, 1, 1, 0, 0, m);       // 将 mpz_t 转换为字节数组
    SHA256_Update(&sha256, bytes2, m_size);           // 更新哈希值
    delete[] bytes2;  // 释放内存

    // 计算最终哈希值
    SHA256_Final(hash, &sha256);

    // 将哈希值转换为 mpz_t 并存储到 res 中
    mpz_import(res, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, hash);

    // 将结果映射到 n 的范围内，计算 res = res mod n
    mpz_mod(res, res, n);
}

/**
 * hash mod n
 * input: m1,m2,m3, n
 * output: res
 */
void Hgsm_n_2(mpz_t &m1, mpz_t &m2, mpz_t &m3, mpz_t &n, mpz_t &res) {
    // 计算SHA-256哈希
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    
    size_t m_size = (mpz_sizeinbase(m1, 2) + 7) / 8;  // 计算字节大小
    unsigned char* bytes1 = new unsigned char[m_size];
    mpz_export(bytes1, nullptr, 1, 1, 0, 0, m1);  // 将 mpz_t 转换为字节数组
    SHA256_Update(&sha256, bytes1, m_size);      // 更新哈希值
    delete[] bytes1;  // 释放内存

    m_size = (mpz_sizeinbase(m2, 2) + 7) / 8;   // 计算字节大小
    unsigned char* bytes2 = new unsigned char[m_size];
    mpz_export(bytes2, nullptr, 1, 1, 0, 0, m2);       // 将 mpz_t 转换为字节数组
    SHA256_Update(&sha256, bytes2, m_size);           // 更新哈希值
    delete[] bytes2;  // 释放内存

    m_size = (mpz_sizeinbase(m3, 2) + 7) / 8;   // 计算字节大小
    unsigned char* bytes3 = new unsigned char[m_size];
    mpz_export(bytes3, nullptr, 1, 1, 0, 0, m3);       // 将 mpz_t 转换为字节数组
    SHA256_Update(&sha256, bytes3, m_size);           // 更新哈希值
    delete[] bytes3;  // 释放内存

    // 计算最终哈希值
    SHA256_Final(hash, &sha256);

    // 将哈希值转换为 mpz_t 并存储到 res 中
    mpz_import(res, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, hash);

    // 将结果映射到 n 的范围内，计算 res = res mod n
    mpz_mod(res, res, n);
}


/**
 * generate random in length
 * @param res
 * @param length
 */
void GenerateRandomWithLength(mpz_t &res, int length){
    // 生成随机数
    gmp_randstate_t state;
    gmp_randinit_default(state);          
    
    struct timeval tv;
    gettimeofday(&tv, NULL);
    unsigned long long seed = tv.tv_sec * 1000000 + tv.tv_usec;

    gmp_randseed_ui(state, seed);
    mpz_urandomb(res, state, length); // 生成一个随机数，长度为 length 位
    gmp_randclear(state);
}

/**
 * 生成随机数 res，使得 0 <= res < max
 */
void GenerateRandomInN(mpz_t &res, mpz_t &max){
    // 生成随机数
    gmp_randstate_t state;
    gmp_randinit_default(state);          
    
    struct timeval tv;
    gettimeofday(&tv, NULL);
    unsigned long long seed = tv.tv_sec * 1000000 + tv.tv_usec;

    gmp_randseed_ui(state, seed);
    mpz_urandomm(res, state, max); // 生成一个随机数小于max
    gmp_randclear(state);
}

/**
 * generate random ∈ Zn*
 */
void GenerateRandomInZnStar(mpz_t &res, mpz_t &max){
    GenerateRandomInN(res, max);
    mpz_t gcd;
    mpz_inits(gcd, NULL);
    mpz_gcd(gcd, res, max);
    while(mpz_cmp_ui(gcd, 1) != 0) {
        GenerateRandomInN(res, max);
        mpz_gcd(gcd, res, max);
    }
    mpz_clears(gcd, NULL);
}

time_t TimeCast(int year, int month, int day, int hour, int minute, int second)
{
    // time_t = 2025.12.31 0:00:00
    struct tm timeinfo = {};
    timeinfo.tm_year = year - 1900;
    timeinfo.tm_mon = month - 1;
    timeinfo.tm_mday = day;           
    timeinfo.tm_hour = hour;        
    timeinfo.tm_min = minute;             
    timeinfo.tm_sec = second;     
    timeinfo.tm_isdst = -1;  
    return mktime(&timeinfo);
}

/**
 * @param M the matrix to be inverted
 * @return the inverse of the matrix
 */
element_t_matrix* inverse(element_t_matrix *M) {
    if (0 == M->row() || 0 == M->col()) {
        return NULL;
    }

    element_t_matrix *res = new element_t_matrix(M->col(), M->row(), M->getElement(0, 0));
    for (signed long int i = 0; i < M->row(); ++i) {
        for (signed long int j = 0; j < M->col(); ++j) {
            element_set(res->getElement(j, i), M->getElement(i, j));
        }
    }
    return res;
}

element_t_vector* getCoordinateAxisUnitVector(element_t_matrix *M) {
    if (0 == M->row() || 0 == M->col()) {
        return NULL;
    }

    element_t_vector *res = new element_t_vector(M->row(), M->getElement(0, 0));

    element_set1(res->getElement(0));
    for (signed long int i = 1; i < res->length(); ++i) {
        element_set0(res->getElement(i));
    }

    return res;
}


/**
 * @param x the solution vector of 'Ax=b'
 * @param A the coefficient matrix
 * @param b the constant vector
 * @return the return value indicates the kind of the solution,
 *         '-1' indicates there is no solution, '0' indicates there is the only solution,
 *         positive integer indicates there is innumberable solution, and marks the number of the free variable
 */
signed long int gaussElimination(element_t_vector *x, element_t_matrix *A, element_t_vector *b) {
    if (!(A->col() == x->length() && A->row() == b->length())) {
        return -1;
    }
    if (0 == A->col() || 0 == A->row()) {
        return -1;
    }

    // get the augmented matrix
    element_t_matrix augmented_matrix(A->row(), A->col() + 1, x->getElement(0));
    for (signed long int i = 0; i < A->row(); i++) {
        for (signed long int j = 0; j < A->col() + 1; j++) {
            if (j == A->col()) {
                augmented_matrix.setElement(i, j, b->getElement(i));
            } else {
                augmented_matrix.setElement(i, j, A->getElement(i, j));
            }
        }
    }

    // free_x marks whether the free variable
    num_vector* free_x = new num_vector(A->col());

    // initialization
    element_t zero_elem;
    element_init_same_as(zero_elem, x->getElement(0));
    element_set0(zero_elem);
    for (signed long int i = 0; i < x->length(); i++) {
        x->setElement(i, zero_elem);
        free_x->setElement(i, 1);
    }

    // the currently processed row
    signed long int current_row;
    // the currently processed column
    signed long int current_col;
    // the row of the augmented matrix
    signed long int row = augmented_matrix.row();
    // the column of the augmented matrix
    signed long int col = augmented_matrix.col();

    // the row with nonzero value of the currently processed column
    signed long int nonzero_row;

    // free x number
    signed long int free_x_num;

    // the temporary variable for swap
    element_t temp;
    element_init_same_as(temp, zero_elem);

    // the inverse of the key element
    element_t inverse;
    element_init_same_as(inverse, zero_elem);

    // the coefficient for elimination
    element_t temp_coefficient;
    element_t coefficient;
    element_init_same_as(temp_coefficient, zero_elem);
    element_init_same_as(coefficient, zero_elem);

    // the elimination element
    element_t elimination;
    element_init_same_as(elimination, zero_elem);
    element_t elimination_result;
    element_init_same_as(elimination_result, zero_elem);

    // convert to the echelon matrix
    current_col = 0;
    for (current_row = 0; (current_row < row) && (current_col < col - 1); current_row++, current_col++) {
        // find the row with the nonzero value of the currently processed column (from 'current_row' to 'row - 1'),
        // and swap the row with index 'current_row' and the row with index 'nonzero_row'
        // when necessary so that augmented_matrix[current_row][current_col] is a nonzero value
        for (signed long int i = current_row; i < row; i++) {
            nonzero_row = i;
            if (!element_is0(augmented_matrix.getElement(nonzero_row, current_col))) {
                break;
            }
        }
        // this indicates the row of the currently processed column after the index 'current_row' has a zero value,
        // so we should process the next column of the currently processed row
        if (element_is0(augmented_matrix.getElement(nonzero_row, current_col))) {
            current_row--;
            continue;
        }
        // swap
        if (nonzero_row != current_row) {
            for (signed long int j = current_col; j < col; j++) {
                element_set(temp, augmented_matrix.getElement(current_row, j));
                augmented_matrix.setElement(current_row, j, augmented_matrix.getElement(nonzero_row, j));
                augmented_matrix.setElement(nonzero_row, j, temp);
            }
        }
        // eliminate the rows of the currently processed column after the index 'current_row'
        for (signed long int i = current_row + 1; i < row; i++) {
            if (!element_is0(augmented_matrix.getElement(i, current_col))) {
                element_invert(inverse, augmented_matrix.getElement(current_row, current_col));
                element_mul(temp_coefficient, inverse, augmented_matrix.getElement(i, current_col));
                element_neg(coefficient, temp_coefficient);
                for (signed long int j = current_col; j < col; j++) {
                    element_mul(elimination, augmented_matrix.getElement(current_row, j), coefficient);
                    element_add(elimination_result, augmented_matrix.getElement(i, j), elimination);
                    augmented_matrix.setElement(i, j, elimination_result);
                }
            }
        }
    }

//    cout << "the echelon matrix is" << endl;
//    augmented_matrix.printMatrix();

    // no solution
    for (signed long int i = current_row; i < row; i++) {
        if (!element_is0(augmented_matrix.getElement(i, col - 1))) {
            return -1;
        }
    }

    // innumberable solution
    element_t random_value;
    element_init_same_as(random_value, zero_elem);
    element_t part_mul;
    element_init_same_as(part_mul, zero_elem);
    element_t inverse_part_mul;
    element_init_same_as(inverse_part_mul, zero_elem);
    element_t res;
    element_init_same_as(res, zero_elem);
    // free_index
    num_vector free_index(col - 1);
    if (current_row < col - 1) {
        for (signed long int i = current_row - 1; i >= 0; i--) {
            element_set(res, augmented_matrix.getElement(i, col - 1));
            free_x_num = 0;
            for (signed long int j = i; j < col - 1; j++) {
                if (0 == free_x_num) {
                    if ((!element_is0(augmented_matrix.getElement(i, j))) && free_x->getElement(j)) {
                        free_x_num++;
                        free_index.setElement(free_x_num - 1, j);
                    }
                } else {
                    if (free_x->getElement(j)) {
                        free_x_num++;
                        free_index.setElement(free_x_num - 1, j);
                    }
                }
            }
            if (free_x_num > 1) {
                for (signed long int k = free_x_num - 1; k > 0; k--) {
                    // set random value
                    element_random(random_value);
                    x->setElement(free_index.getElement(k), random_value);
                    free_x->setElement(free_index.getElement(k), 0);
                    element_mul(part_mul, augmented_matrix.getElement(i, free_index.getElement(k)), random_value);
                    element_neg(inverse_part_mul, part_mul);
                    element_add(res, res, inverse_part_mul);
                }
                for (signed long int k = col - 2; k > free_index.getElement(free_x_num - 1); k--) {
                    if (!element_is0(augmented_matrix.getElement(i, k))) {
                        element_mul(part_mul, augmented_matrix.getElement(i, k), x->getElement(k));
                        element_neg(inverse_part_mul, part_mul);
                        element_add(res, res, inverse_part_mul);
                    }
                }
                element_invert(inverse, augmented_matrix.getElement(i, free_index.getElement(0)));
                element_mul(res, inverse, res);
                x->setElement(free_index.getElement(0), res);
                free_x->setElement(free_index.getElement(0), 0);
            } else {
                for (signed long int k = col - 2; k > free_index.getElement(0); k--) {
                    if (!element_is0(augmented_matrix.getElement(i, k))) {
                        element_mul(part_mul, augmented_matrix.getElement(i, k), x->getElement(k));
                        element_neg(inverse_part_mul, part_mul);
                        element_add(res, res, inverse_part_mul);
                    }
                }
                element_invert(inverse, augmented_matrix.getElement(i, free_index.getElement(0)));
                element_mul(res, inverse, res);
                x->setElement(free_index.getElement(0), res);
                free_x->setElement(free_index.getElement(0), 0);
            }
        }
        return col - 1 - current_row;
    }

    // the only solution
    for (signed long int i = col - 2; i >= 0; i--) {
        element_set(res, augmented_matrix.getElement(i, col - 1));
        for (signed long int j = col - 2; j >= i + 1; j--) {
            if (!element_is0(augmented_matrix.getElement(i, j))) {
                element_mul(part_mul, augmented_matrix.getElement(i, j), x->getElement(j));
                element_neg(inverse_part_mul, part_mul);
                element_add(res, res, inverse_part_mul);
            }
        }
        element_invert(inverse, augmented_matrix.getElement(i, i));
        element_mul(res, inverse, res);
        x->setElement(i, res);
    }
    return 0;
}

/**
 * parse element_t to mpz_t
 * @param mpz mpz_t
 * @param element element_t
 */
void mpz_from_element(mpz_t &mpz, element_t &element){
    unsigned char *str = (unsigned char *)malloc(element_length_in_bytes(element));
    element_to_bytes(str, element);
    mpz_set_str(mpz, (char *)str, 10); 
    free(str);
    if(mpz_cmp_ui(mpz, 0) == 0){
        throw std::runtime_error("mpz_from_element: mpz = 0");
    }
}

/**
 * parse mpz_t to element_t
 * 
 */
void mpz_to_element(element_t &element, mpz_t &mpz){
    char *str = mpz_get_str(NULL, 10, mpz);
    element_from_bytes(element, (unsigned char *)str);
    free(str);
}