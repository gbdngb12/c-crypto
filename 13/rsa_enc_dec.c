#include "rsa_enc_dec.h"


void rsa_encryption(unsigned char* plain_text, unsigned char* result) {
    int i, count = 0;
    short check = 1;
    FILE* fptr;

    // 수신자의 공개키 파일을 연다.
    if ((fptr = fopen("public_key.txt", "rb")) == NULL) {
        printf("file open failed!!\n");
        exit(1);
    }

    // 파일로부터 공개키 e와 n을 저장한다.
    for (i = mb - 1; i >= 0; i--) {
        fscanf(fptr, "%I64x ", &N[i]);  // 공개키 N
    }
    for (i = mb - 1; i >= 0; i--) {
        fscanf(fptr, "%I64x ", &E[i]);  // 공개키 e
    }

    fclose(fptr);
    // 평문을 모두 암호화 할때 까지
    // 117바이트씩 암호를 수행한다.(11 바이트 = 패딩)
    while (check == 1) {
        // 평문을 읽어 이진 형태로 저장한다.
        check = get_from_message(plain_text + count * DATA_LEN, h, DATA_LEN);

        //
        if (check != -1) {
            convert_binary_to_oct(h, DATA, DATA_LEN);  // 이진 평문을 octet으로 변환

            // OAEP 암호문 블록 패딩 (EB1 <- [00|02|PS|00|DATA])
            rand_generator(ps, LEN_PS * 8);           // 패딩 스트링으로 사용할 랜덤 수 생성
            convert_binary_to_oct(ps, O_PS, LEN_PS);  // 생성한 이진 랜덤수를 octet으로 변환

            EB[mb * 4 - 1] = 0x00;
            EB[mb * 4 - 2] = 0x02;

            // PS padding
            for (i = mb * 4 - 3; i > DATA_LEN; i--) {
                EB[i] = O_PS[i - DATA_LEN - 1];
            }

            EB[DATA_LEN] = 0x00;

            // data
            for (i = DATA_LEN - 1; i >= 0; i--) {
                EB[i] = DATA[i];
            }

            for (i = mb * 4 - 1; i >= 0; i -= 4) {
                EB1[i / 4] = (EB[i] << (DHEX - OCT)) + (EB[i - 1] << (OCT + OCT)) + (EB[i - 2] << OCT) + EB[i - 3];
            }
            // 암호문 블록 패딩 종료

            // C = M^e mod N (M - bit)
            left_to_right_pow(EB1, E, S, N, mb);  // 수신자의 공개키로 암호화

            // radix 형태의 암호문을 이진 형태로 변환
            convert_radix_to_binary(S, s, mb);

            // 이진 형태의 암호문을 바이트 형태로 변화하여 저장
            put_to_message(result + count * B_S, s, B_S);

            count++;
        }
    }
}
void rsa_decryption(unsigned char* cipher_text, unsigned char* result) {
    int i, count = 0;
    short check = 1;
    FILE* fptr;

    // 사용자의 비밀키 파일을 연다
    if ((fptr = fopen("secret_key.txt", "rb")) == NULL) {
        printf("file open failed!!\n");
        exit(1);
    }

    // 파일로부터 공개키 d와 모듈러 n을 저장한다
    for (i = mb - 1; i >= 0; i--) fscanf(fptr, "%I64x ", &N[i]);
    for (i = mb - 1; i >= 0; i--) fscanf(fptr, "%I64x ", &D[i]);

    fclose(fptr);

    // 암호문을 모두 암호화 할 때까지
    // 128 바이트씩 암호를 수행한다(11 바이트 = 패딩 포함)
    while (check == 1 && count <= 2) {
        // 암호문을 읽어 이진 형태로 저장한다
        check = get_from_message(cipher_text + count * B_S, s, B_S);

        if (check != -1) {
            convert_binary_to_radix(s, S, mb);  // 이진 형태의 암호문을 Radix로 변환

            /*** M = C^d mod N (M-bit) ***/
            left_to_right_pow(S, D, H, N, mb);  // 사용자의 비밀키로 복호화

            convert_radix_to_binary(H, v_h, mb);       // 복호화된 데이터를 이진 형태로 변환
            convert_binary_to_oct(v_h, D_EB, mb * 4);  // 이진 형태의 데이터를 octet으로 변환

            // 패딩을 제외한 복호문을 추출한다
            for (i = DATA_LEN - 1; i >= 0; i--)
                D_DATA[i] = D_EB[i];

            // 추출한 복호문을 이진 형태로 변환
            convert_oct_to_binary(D_DATA, d_d, DATA_LEN);
            // 이진 형태의 복호문을 바이트 형태로 저장한다
            put_to_message(result + count * DATA_LEN, d_d, DATA_LEN);

            count++;
        }
    }
}
// 메시지를 읽어 이진 형태로 저장
int get_from_message(unsigned char* msg, short* a, short mn) {
    register i, j;
    short flag = 1, cnt = 0, mm;
    unsigned char b[m / Char_NUM] = {
        0,
    };

    mm = mn * Char_NUM;

    for (i = 0; i < mm; i++)
        a[i] = 0;

    // 메시지 버퍼에서 한 바이트씩 읽는다
    for (i = 0; i < mn; i++) {
        if (msg[i] == '\0') {
            if (i == 0)
                return -1;

            if (mn < B_S) {
                flag = 0;
                break;
            }
        }

        b[i] = msg[i];
    }

    cnt = 0;
    // 바이트 단위의 데이터를 이진 형태로 변환
    for (i = mn - 1; i >= 0; i--) {
        for (j = 0; j < Char_NUM; j++) {
            a[cnt++] = (b[i] >> j) & 0x01;
        }
    }

    return (flag);
}

// 이진 형태의 데이터를 바이트 형태로 저장
void put_to_message(unsigned char* msg, short* a, short mn) {
    register i, j;
    short cnt = 0;
    unsigned char b[m / Char_NUM] = {
        0,
    };
    unsigned char mask[Char_NUM] = {0x01, 0x02, 0x04, 0x08,
                                    0x10, 0x20, 0x40, 0x80};

    cnt = 0;
    // 이진 형태의 데이터를 바이트 형태로 변환한다
    for (i = mn - 1; i >= 0; i--) {
        for (j = 0; j < Char_NUM; j++) {
            b[i] = b[i] + a[cnt++] * mask[j];
        }
    }
    // 변환한 데이터를 메시지 버퍼에 저장한다
    for (i = 0; i < mn; i++)
        msg[i] = b[i];
}

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