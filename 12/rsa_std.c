#pragma once
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

/* 상수 정의 */
#define m 1024  // 모듈러 n의 비트 수
#define mp 512  // 비밀 소수 p의 비트 수
#define mq 512  // 비밀 소수 q의 비트 수
#define HASH 128
#define LEN_PS 8  // 패딩 스트링의 비트수
#define DHEX 32
#define OCT 8
#define Char_NUM 8                   // char 비트수
#define B_S m / Char_NUM             // 512바이트 ( 암호문 바이트 수 )
#define DATA_LEN (B_S - LEN_PS - 3)  // 평문 블록 길이
#define mb m / DHEX                  // 32
#define hmb mb / 2                   // 16
#define mpb mp / DHEX                // 16
#define mqb mq / DHEX                // 16
#define E_LENGTH 16

#define rdx 0x100000000

// 타입 정의
typedef unsigned int ulint;
typedef unsigned long int64;
typedef unsigned int int32;

// rsa의 연산과 관련된 함수들
static void convert_oct_to_binary(int64 *A, short *B, short mn);                  // octet을 binary로 변환하는 함수
static void convert_binary_to_oct(short *A, int64 *B, short mn);                  // binary를 octet로 변환하는 함수
static void convert_radix_to_binary(int64 *A, short *B, short mn);                // Radix를 binary로 변환하는 함수
static void convert_binary_to_radix(short *A, int64 *B, short mn);                // binary를 Radix로 변환하는 함수
static void rand_generator(short *out, short n);                                  // 랜덤 수를 생성하는 함수
static void modular(int64 *X, int64 *N, short mn);                                // 모듈러 연산을 수행하는 함수
static void convert_mma(int64 *A, int64 *B, int64 *C, int64 *N, short mn);        // 고전적인 모듈러 감소 연산을 수행하는 함수
static void left_to_right_pow(int64 *A, int64 *E, int64 *C, int64 *N, short mn);  // Left to Right 멱승을 수행하는 함수

/* 전역 변수 */
static int32 LAND = 0xFFFFFFFF;

// 공개키 파라미터
static int64 N[mb];  // 모듈러 n (= p * q)
static int64 E[mb];  // 공개키 e
static int64 D[mb];  // 비밀키 d

/********************************************************************/
/***********   Function name :  convert_binary_to_radix (a,B,mn)       **********/
/***********   Description   :  convert bin. into radix    **********/
/********************************************************************/
static int64 mask[DHEX] = {0x80000000, 0x40000000, 0x20000000, 0x10000000, 0x8000000,
                           0x4000000, 0x2000000, 0x1000000, 0x800000, 0x400000, 0x200000,
                           0x100000, 0x080000, 0x040000, 0x020000, 0x010000,
                           0x8000, 0x4000, 0x2000, 0x1000, 0x800,
                           0x400, 0x200, 0x100, 0x80, 0x40, 0x20,
                           0x10, 0x08, 0x04, 0x02, 0x01};

void convert_binary_to_radix(short *A, int64 *B, short mn) {
    register i, j, k;

    for (i = mn - 1; i >= 0; i--) B[i] = 0x00;

    i = mn * DHEX - 1;
    for (k = 0; k <= mn - 1; k++) {
        B[k] = 0x00;
        for (j = DHEX - 1; j >= 0; j--) {
            B[k] += A[i--] * mask[j];
            if (i < 0) break;
        }
        if (i < 0) break;
    }
}

/********************************************************************/
/***********   Function name :  convert_radix_to_binary (A,b,mn)       **********/
/***********   Description   :  convert radix into bin.    **********/
/********************************************************************/
void convert_radix_to_binary(int64 *A, short *B, short mn) {
    register i, j, k;

    for (i = 0; i < mn * DHEX; i++) B[i] = 0;
    k = mn * DHEX - 1;
    for (i = 0; i <= mn - 1; i++) {
        for (j = 0; j <= DHEX - 1; j++) {
            B[k--] = (A[i] >> j) & 0x01;
            if (k < 0) break;
        }
        if (k < 0) break;
    }
}

/********************************************************************/
/***********   Function name :  rand_generator (a,n)               **********/
/***********   Description   : n-bits random               **********/
/***********                   number generator.           **********/
/********************************************************************/
void rand_generator(short *out, short n) {
    register j, k;
    short x;
    long t;

    srand((unsigned)(time(NULL)));
    // delay(100);

    j = 0;
    while (1) {
        x = rand();
        for (k = 0; k < 15; k++) {
            out[n - 1 - j] = (x >> k) & 0x01;
            j++;
            if (j >= n) return;
        }
    }
}

/********************************************************************/
/*****     Function name : modular(C, N mn)                     *****/
/*****     Description   : C = C mod N                          *****/
/********************************************************************/
void modular(int64 *X, int64 *N, short mn) {
    register i, j, k;
    short shift, posit;
    int64 arryA[2 * mb + 1] = {
        0,
    },
                         arryN[2 * mb + 1] = {
                             0,
                         };
    int64 acumA, acumB, acumN, acumQ;
    int32 acumC;

    acumN = N[mn - 1] + 0x01;

    while (1) {
        for (k = 2 * mn - 1; k >= 0; k--)
            if (X[k] > 0x00)
                break;
        if (k <= mn - 1)
            break;

        acumA = X[k] * rdx + X[k - 1];
        acumQ = acumA / acumN;

        if (acumQ > (rdx - 1))
            acumQ = rdx - 1;

        shift = k - mn; /**  shift number **/

        acumC = 0x00;
        for (k = 0; k <= mn - 1; k++) {
            acumA = N[k] * acumQ + acumC;
            acumC = acumA >> DHEX;
            acumA = acumA & LAND;
            j = k + shift;
            if (X[j] < acumA) {
                X[j] += rdx;
                posit = j;
                while ((X[j + 1]) == 0 && (j < (mn + shift))) {
                    X[j + 1] += rdx - 1;
                    j++;
                }
                X[j + 1] -= 0x01;
                j = posit;
            }
            X[j] = (X[j] - acumA) & LAND;
        }
        X[mn + shift] = X[mn + shift] - acumC;
    }

    while (1) {
        for (i = mn - 1; i >= 0; i--) {
            if ((X[i] & LAND) != (N[i] & LAND)) {
                if ((X[i] & LAND) > (N[i] & LAND))
                    break;
                else
                    return (0);
            }
        }

        acumA = X[mn - 1];
        acumA = acumA / acumN;

        if (acumA == 0x00) {
            for (i = 0; i <= mn - 1; i++) {
                if (X[i] < N[i]) {
                    X[i] += rdx;
                    posit = i;
                    while ((X[i + 1] == 0) && (i < mn)) {
                        X[i + 1] += rdx - 1;
                        i++;
                    }
                    X[i + 1] -= 0x01;
                    i = posit;
                }
                X[i] = (X[i] - N[i]) & LAND;
            }
        }

        else {
            acumC = 0x00;
            for (i = 0; i <= mn - 1; i++) {
                acumB = N[i] * acumA + acumC;
                acumC = acumB >> DHEX;
                acumB = acumB & LAND;
                if (X[i] < acumB) {
                    X[i] += rdx;
                    posit = i;
                    while ((X[i + 1] == 0) && (i < mn)) {
                        X[i + 1] += rdx - 1;
                        i++;
                    }
                    X[i + 1] -= 0x01;
                    i = posit;
                }
                X[i] = (X[i] - acumB) & LAND;
            }
        }
    }
}

/********************************************************************/
/*****     Function name : convert_mma(A,B,C,N,mn) (Conventional)  *****/
/*****     Description   : C= A*B mod N                         *****/
/********************************************************************/
void convert_mma(int64 *A, int64 *B, int64 *C, int64 *N, short mn) {
    register i, j, k;
    int64 arryC[mb * 2], X[mb * 2]; /** temporary arrys **/
    int64 acumA;                    /** temporary acumulators **/
    int32 acumC;

    for (k = 2 * mn - 1; k >= 0; k--) arryC[k] = 0x00;

    for (i = 0; i <= mn - 1; i++) {
        if (A[i] > 0x00) {
            acumC = 0x00;
            for (j = 0; j <= mn - 1; j++) {
                acumA = A[i] * B[j] + arryC[i + j] + acumC;
                arryC[i + j] = acumA & LAND;
                acumC = acumA >> DHEX;
            }
            arryC[i + j] = acumC;
        }
    }

    for (i = 2 * mn - 1; i >= 0; i--)
        X[i] = arryC[i];

    modular(X, N, mn);

    for (i = 0; i <= mn - 1; i++)
        C[i] = X[i];
}

/********************************************************************/
/***********   Function name :  convert_binary_to_oct (a,B,mn)       **********/
/***********   Description   :  convert bin. into octet    **********/
/********************************************************************/
static int64 o_mask[8] = {0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01};

void convert_binary_to_oct(short *A, int64 *B, short mn) {
    register i, j, k;

    i = mn * OCT - 1;
    for (k = 0; k <= mn - 1; k++) {
        B[k] = 0x00;
        for (j = 7; j >= 0; j--) {
            B[k] += A[i--] * o_mask[j];
            if (i < 0) break;
        }
        if (i < 0) break;
    }
}

/********************************************************************/
/***********   Function name :  convert_oct_to_binary (A,b,mn)       **********/
/***********   Description   :  convert octet into bin.    **********/
/********************************************************************/
void convert_oct_to_binary(int64 *A, short *B, short mn) {
    register i, j, k;

    for (i = 0; i < mn * OCT; i++) B[i] = 0;
    k = mn * OCT - 1;
    for (i = 0; i <= mn - 1; i++) {
        for (j = 0; j <= 7; j++) {
            B[k--] = (A[i] >> j) & 0x01;
            if (k < 0) break;
        }
        if (k < 0) break;
    }
}

/********************************************************************/
/*****     Function name : WM_Left_Pow(A,E,C,N,mn)              *****/
/*****     Description   : C= A^E mod N                         *****/
/********************************************************************/
void left_to_right_pow(int64 *A, int64 *E, int64 *C, int64 *N, short mn) {
    register i;
    int64 arryC[mb] = {
        0,
    };
    short e[m] = {
        0,
    };

    for (i = 0; i < mn; i++)
        C[i] = 0x00;

    convert_radix_to_binary(E, e, mn);

    arryC[0] = 0x01;

    for (i = 0; i < mn * DHEX; i++) {
        convert_mma(arryC, arryC, arryC, N, mn);

        if (e[i] == 1)
            convert_mma(arryC, A, arryC, N, mn);
    }

    for (i = 0; i < mn; i++)
        C[i] = arryC[i];
}