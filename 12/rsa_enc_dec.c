#include "rsa_std.c"

// 서명과 검증에 사용되는 버퍼(이진(binary) 형태)
static short s[m];               // 암호문(암호)
static short h[DATA_LEN * 8];    // 평문 
static short v_h[m];             // 복호문(패딩 포함)
static short d_d[DATA_LEN * 8];  // 복호문(패딩 제외)
static short ps[LEN_PS * 8];     // 패딩 스트링

// 암호와 복호에 사용되는 버퍼(Radix와 octet 형태)
static int64 S[mb];             // 암호문, 서명 값(서명)
static int64 H[mb];             // 복호문(Radix)
static int64 DATA[DATA_LEN];    // 평문(octet)
static int64 EB[mb * 4];        // 암호문 블록(8 bit)
static int64 EB1[mb];           // 암호문 블록(16 bit)
static int64 D_EB[mb * 4];      // 복호문 블록(8 bit)
static int64 D_DATA[DATA_LEN];  // 복호 데이터(octet)
static int64 O_PS[OCT];         // 패딩 스트링(octet)

// RSA 암호화 함수
void rsa_encryption(unsigned char* plain_text, unsigned char* result);
// RSA 복호화 함수
void rsa_decryption(unsigned char* cipher_text, unsigned char* result);
// 메시지 버퍼에서 데이터를 읽어서 이진 형태로 저장하는 함수
int get_from_message(unsigned char* msg, short* a, short mn);
// 이진 형태의 데이터를 메시지 버퍼에 저장하는 함수
void put_to_message(unsigned char* msg, short* a, short mn);

int main() {
    int i, count = 0;
    unsigned char plain_text[512] = {0};    // 512바이트 평문
    unsigned char cipher_text[512] = {0};   // 512바이트 암호문
    unsigned char decrypt_text[512] = {0};  // 512바이트 복호문

    printf("Input Plain text : ");
    gets(plain_text);
    printf("\n");

    rsa_encryption(plain_text, cipher_text);

    printf("Encrypt text :\n");
    for (i = 0; i < B_S; i++) {
        printf("%x ", cipher_text[i]);
    }

    printf("\n\nThe encryption is completed.\n\n");

    rsa_decryption(cipher_text, decrypt_text);

    printf("Decrypt text :\n");
    for (i = 0; i < (int)strlen((char*)decrypt_text); i++) {
        printf("%c", decrypt_text[i]);
    }
    printf("\nThe decryption is completed.\n");
    return 0;
}

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
    while (check == 1) {
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