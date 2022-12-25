#include "rsa_std.h"

void CONV_B_to_R(short *A, INT64 *B, short mn) {
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
/***********   Function name :  CONV_R_to_B (A,b,mn)       **********/
/***********   Description   :  convert radix into bin.    **********/
/********************************************************************/
void CONV_R_to_B(INT64 *A, short *B, short mn) {
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
/***********   Function name :  rand_g (a,n)               **********/
/***********   Description   : n-bits random               **********/
/***********                   number generator.           **********/
/********************************************************************/
void rand_g(short *out, short n) {
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
/*****     Function name : Modular(C, N mn)                     *****/
/*****     Description   : C = C mod N                          *****/
/********************************************************************/
void Modular(INT64 *X, INT64 *N, short mn) {
    register i, j, k;
    short shift, posit;
    INT64 arryA[2 * mb + 1] = {
        0,
    },
                         arryN[2 * mb + 1] = {
                             0,
                         };
    INT64 acumA, acumB, acumN, acumQ;
    INT32 acumC;

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
/*****     Function name : Conv_mma(A,B,C,N,mn) (Conventional)  *****/
/*****     Description   : C= A*B mod N                         *****/
/********************************************************************/
void Conv_mma(INT64 *A, INT64 *B, INT64 *C, INT64 *N, short mn) {
    register i, j, k;
    INT64 arryC[mb * 2], X[mb * 2]; /** temporary arrys **/
    INT64 acumA;                    /** temporary acumulators **/
    INT32 acumC;

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

    Modular(X, N, mn);

    for (i = 0; i <= mn - 1; i++)
        C[i] = X[i];
}

/********************************************************************/
/***********   Function name :  CONV_B_to_O (a,B,mn)       **********/
/***********   Description   :  convert bin. into octet    **********/
/********************************************************************/

void CONV_B_to_O(short *A, INT64 *B, short mn) {
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
/***********   Function name :  CONV_O_to_B (A,b,mn)       **********/
/***********   Description   :  convert octet into bin.    **********/
/********************************************************************/
void CONV_O_to_B(INT64 *A, short *B, short mn) {
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
void LeftTORight_Pow(INT64 *A, INT64 *E, INT64 *C, INT64 *N, short mn) {
    register i;
    INT64 arryC[mb] = {
        0,
    };
    short e[m] = {
        0,
    };

    for (i = 0; i < mn; i++)
        C[i] = 0x00;

    CONV_R_to_B(E, e, mn);

    arryC[0] = 0x01;

    for (i = 0; i < mn * DHEX; i++) {
        Conv_mma(arryC, arryC, arryC, N, mn);

        if (e[i] == 1)
            Conv_mma(arryC, A, arryC, N, mn);
    }

    for (i = 0; i < mn; i++)
        C[i] = arryC[i];
}