#ifndef UTIL_FUNC_H
#define UTIL_FUNC_H

#include <pbc/pbc.h>
#include <string>
#include <ABE/data_structure/element_t_matrix.h>
#include <ABE/data_structure/element_t_vector.h>
#include <ABE/data_structure/num_vector.h>

void Hm(element_t &m, element_t &res, element_t &tmp_Zp, element_t &g);

void Hgsm(element_t &gs, element_t &m, element_t &res, element_t &tmp_Zp, element_t &g);

void Hm_1(element_t &m, element_t &res);
void Hm_1(string m, element_t &res);

void Hgsm_1(element_t &gs, element_t &m, element_t &res);

void Hm_2(element_t &y, element_t &h, element_t &m,element_t &u1,element_t &u2, element_t &res);

void Hm_3(element_t &y, element_t &h1, element_t &h2, element_t &m,
            element_t &u11,element_t &u12, element_t &u2, 
            element_t &res);

void Hm_4(element_t &m1, element_t &m2, element_t &m3, element_t &res);

void Hm_5(element_t &m1, element_t &m2, element_t &m3, element_t &m4, element_t &res);

void PrintElement(std::string element_name, element_t &element);
void PrintElementsize(std::string element_name, element_t &element);
void PrintElementAndSize(std::string element_name, element_t &element);

void PrintMpz(std::string mpz_name, mpz_t &mpz);
void PrintMpzsize(std::string mpz_name, mpz_t &mpz);
void PrintMpzAndSize(std::string mpz_name, mpz_t &mpz);

int CountSize(element_t &t);

void Hm_n(mpz_t &m, mpz_t &res,  mpz_t &n);
void Hm_n(mpz_t &res, string m, mpz_t &n);
void Hgsm_n(mpz_t &gs, mpz_t &m, mpz_t &res,  mpz_t &n);
void Hgsm_n_2(mpz_t &m1, mpz_t &m2, mpz_t &m3, mpz_t &n, mpz_t &res);

void GenerateRandomWithLength(mpz_t &res, int length);
void GenerateRandomInN(mpz_t &res, mpz_t &max);
void GenerateRandomInZnStar(mpz_t &res, mpz_t &max);

time_t TimeCast(int year, int month, int day, int hour, int minute, int second);

element_t_matrix* inverse(element_t_matrix *M);

element_t_vector* getCoordinateAxisUnitVector(element_t_matrix *M);

signed long int gaussElimination(element_t_vector *x, element_t_matrix *A, element_t_vector *b);

void mpz_from_element(mpz_t &mpz, element_t &element);
void mpz_to_element(element_t &element, mpz_t &mpz);

#endif //UTIL_FUNC_H