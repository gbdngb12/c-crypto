#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HASH_BLOCK 64  // 해쉬 블록 크기(512비트)(byte)
#define HASH_DATA 20   // 해쉬 출력 값의 크기(byte)
// 타입 정의
typedef unsigned char byte;
typedef unsigned int uint;
typedef unsigned long long uint64;

static int isAddpad = 0;
static uint init_reg[5];        // 초기 레지스터
static byte digest[HASH_DATA];  // 해쉬 값

#define H0 0x67452301
#define H1 0xefcdab89
#define H2 0x98badcfe
#define H3 0x10325476
#define H4 0xc3d2e1f0

// ���� ���
#define K0 0x00000000
#define K1 0x5a827999
#define K2 0x6ed9eba1
#define K3 0x8f1bbcdc

/* ��ũ�� �Լ� */
#define byte_to_word(a, b, c, d) (((a << 24) + (b << 16) + (c << 8) + d))  // byte���� word�� ��ȯ
#define circular_shift(x, n) (((x) << n) | ((x) >> (32 - n)))              // 32��Ʈ ���� ��ȯ �̵�

// ��� ���� �Լ�
#define F1(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define F2(x, y, z) (((x) ^ (y) ^ (z)))
#define F3(x, y, z) ((y ^ (x | (~z))))

void has_160_init();
void make_bit_160(uint a, uint b, uint c, uint d, uint e);
void has_160_digest(byte *in);
void has_160(FILE *fptr, byte *result);
void padding(byte *in, uint64 msg_len) {
    int i;
    byte *ptr = (byte *)&msg_len;

    if ((msg_len % HASH_BLOCK) < 56) {
        in[msg_len % HASH_BLOCK] = 0x80;
        msg_len *= 8;

        for (i = 0; i < 8; i++) {
            in[HASH_BLOCK - i - 1] = *(ptr + (7 - i));  // treat to little-endian
        }
    } else {
        in[msg_len % HASH_BLOCK] = 0x80;
        msg_len *= 8;

        for (i = 0; i < 8; i++) {
            in[HASH_BLOCK * 2 - i - 1] = *(ptr + (7 - i));  // treat to little-endian
        }
    }
}

void has_160_init() {
    init_reg[0] = H0;
    init_reg[1] = H1;
    init_reg[2] = H2;
    init_reg[3] = H3;
    init_reg[4] = H4;
}

static byte l[80] =
    {
        18, 0, 1, 2, 3, 19, 4, 5, 6, 7, 16, 8, 9, 10, 11, 17, 12, 13, 14, 15,
        18, 3, 6, 9, 12, 19, 15, 2, 5, 8, 16, 11, 14, 1, 4, 17, 7, 10, 13, 0,
        18, 12, 5, 14, 7, 19, 0, 9, 2, 11, 16, 4, 13, 6, 15, 17, 8, 1, 10, 3,
        18, 7, 2, 13, 8, 19, 3, 14, 9, 4, 16, 15, 10, 5, 0, 17, 11, 6, 1, 12};  // 각 단계별 라운드 xor index의 값

//
static byte s1[20] =  // 순환 shift 양
    {
        5, 11, 7, 15, 6, 13, 8, 14, 7, 12, 9, 11, 8, 15, 6, 12, 9, 14, 5, 13};

static byte s2[4] = {10, 17, 25, 30};  // 순환 shift양

void has_160_digest(byte *in) {
    int i, j, k;
    // input is 16 word
    uint x[20] = {0};  // expand to 20 word
    uint a, b, c, d, e, t /*temp*/;

    a = init_reg[0];
    b = init_reg[1];
    c = init_reg[2];
    d = init_reg[3];
    e = init_reg[4];

    for (i = 0; i < HASH_BLOCK; i += 4) {
        x[i / 4] = byte_to_word(in[i + 3], in[i + 2], in[i + 1], in[i]);
    }

    for (i = 0; i < 4; i++) {
        j = i * 20;  // j는 base Index

        // 공식에 의해 정의
        x[16] = x[l[j + 1]] ^ x[l[j + 2]] ^ x[l[j + 3]] ^ x[l[j + 4]];
        x[17] = x[l[j + 6]] ^ x[l[j + 7]] ^ x[l[j + 8]] ^ x[l[j + 9]];
        x[18] = x[l[j + 11]] ^ x[l[j + 12]] ^ x[l[j + 13]] ^ x[l[j + 14]];
        x[19] = x[l[j + 16]] ^ x[l[j + 17]] ^ x[l[j + 18]] ^ x[l[j + 19]];

        for (k = 0; k < 20; k++) {
            j = 20 * i + k;  // j는 단계

            if (i == 0) {  // Round 1
                t = circular_shift(a/*a*/, s1[j % 20]/*s1*/) + F1(b,c,d) + e/*e*/ + x[l[j]]/*x[16],x[17]...*/ + K0/*K0*/;
            } else if (i == 1) {  // Round 2
                t = circular_shift(a/*a*/, s1[j % 20]/*s1*/) + F2(b,c,d) + e/*e*/ + x[l[j]]/*x[16],x[17]...*/ + K1/*K0*/;

            } else if (i == 2) {  // Round 3
                t = circular_shift(a/*a*/, s1[j % 20]/*s1*/) + F3(b,c,d) + e/*e*/ + x[l[j]]/*x[16],x[17]...*/ + K2/*K0*/;

            } else {
                t = circular_shift(a/*a*/, s1[j % 20]/*s1*/) + F2(b,c,d) + e/*e*/ + x[l[j]]/*x[16],x[17]...*/ + K3/*K0*/;
            }

            e = d;
            d = c;
            c = circular_shift(b, s2[j / 20]);
            b = a;
            a = t;
        }
    }
    init_reg[0] += a;
    init_reg[1] += b;
    init_reg[2] += c;
    init_reg[3] += d;
    init_reg[4] += e;

    make_bit_160(init_reg[0], init_reg[1], init_reg[2], init_reg[3], init_reg[4]);
}

void make_bit_160(uint a, uint b, uint c, uint d, uint e) {//little-endian 방식으로 저장
    int i;
    byte *p;

    for (i = 0; i < 20; i++) {
        if (i < 4) {
            p = (byte *)&a;
            digest[i] = p[i];
        } else if (i < 8) {
            p = (byte *)&b;
            digest[i] = p[i % 4];
        } else if (i < 12) {
            p = (byte *)&c;
            digest[i] = p[i % 4];
        } else if (i < 16) {
            p = (byte *)&d;
            digest[i] = p[i % 4];
        } else {
            p = (byte *)&e;
            digest[i] = p[i % 4];
        }
    }
}

void has_160(FILE *fptr, byte *result) {
    int i, size = 0;
    byte msg[HASH_BLOCK * 2] = { 0 };
    uint64 f_size = 0;
    has_160_init();

    while((size = fread(msg, sizeof(byte),HASH_BLOCK, fptr))) {
        f_size += size;

        if(size < HASH_BLOCK) {
            padding(msg, f_size);
        }

        has_160_digest(msg);

        if(isAddpad) {
            has_160_digest(msg + HASH_BLOCK);
        }
        memset(msg, 0, HASH_BLOCK * 2);
    }

    for(i = 0; i < HASH_DATA; i++) {
        result[i] = digest[i];
    }
}

int main() {
    int i;
    char file_name[32] = { 0 };
    byte result[HASH_DATA] = { 0 };
    FILE *fp;

    //Input File Name
    printf("Input File Name: ");
    scanf("%s", file_name);

    //File Open
    if((fp = fopen(file_name, "rb")) == NULL) {
        printf("FIle open failed\n");
        exit(1);
    }

    has_160(fp, result);

    for(i = 0; i < HASH_DATA; i++) {
        printf("%3X", result[i]);
    }

    printf("\n");
    fclose(fp);
    return 0;
}