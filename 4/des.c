#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BLOCK_SIZE 8  // DES 블록사이즈
#define DES_ROUND 16  // DES 라운드 수

typedef unsigned char byte;
typedef unsigned int uint;

// DES 암호화 함수
void des_encryption(byte *plain_text, byte *result, byte *key);
// DES 복호화 함수
void des_decryption(byte *cipher_text, byte *result, byte *key);
// 초기 순열 함수
void initial_permutation(byte *in, byte *out);
// 역초기 순열 함수
void inverse_initial_permutation(byte *in, byte *out);
// 확장 순열 함수
void expand_permutation(uint r, byte *out);
// 순열 함수
uint permutation(uint in);
// 순열 선택 - 1 함수
void permuted_choice_1(byte *in, byte *out);
// 순열 선택 - 2 함수
void permuted_choice_2(uint c, uint d, byte *out);
// s-box 변환 함수
uint s_box_transfer(byte *in);
// f 함수
uint f(uint r, byte *rkey);
// 키 확장 함수
void key_expansion(byte *key, byte exp_key[16][6]);
// 자리 바꿈 함수
void swap(uint *x, uint *y);
// 56bit -> 28bit 로 나누는 함수
void make_bit_28(uint *c, uint *d, byte *data);
// 28bit 순환 시프트 함수
uint circular_shift(uint n, int r);
// byte를 word로 바꾸는 함수
void byte_to_word(byte *in, uint *x, uint *y);
// word를 byte로 바꾸는 함수
void word_to_byte(uint l, uint r, byte *out);

// 초기 순열 테이블
int initial_permutation_table[64] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7};
// 역초기 순열 테이블
int inverse_initial_permutation_table[64] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25};
// 확장 순열 테이블
int expansion_permutation_table[48] = {
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1};
// 순열 테이블
int p_box_table[32] = {
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25};
// 순열 선택 - 1 테이블
int pc1_table[56] = {
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4};
// 순열 선택 - 2 테이블
int pc2_table[48] = {
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32};

//S-Box
byte s_box_table[8][4][16] = {
    {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
     0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
     15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},

    {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
     3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
     13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},

    {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
     13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
     1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},

    {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
     13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
     3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},

    {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
     14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
     11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},

    {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
     10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
     4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},

    {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
     13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
     6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},

    {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
     1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
     2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11},
};

int main() {
    int i;
    int msg_len = 0, block_count = 0;  // 메시지 길이와 블록 수
    byte plain_text[128] = {0};        // 평문
    byte cipher_text[128] = {0};       // 암호문
    byte decrypt_text[128] = {0};      // 복호문
    byte key[9] = {0};                 // 비밀 키

    printf("Input plain text: ");
    gets(plain_text);

    printf("Input secret Key: ");
    scanf("%s", key);

    msg_len = (int)strlen((char *)plain_text);
    block_count = (msg_len % BLOCK_SIZE) ? (msg_len / BLOCK_SIZE + 1) : (msg_len / BLOCK_SIZE);

    for (i = 0; i < block_count; i++) {
        des_encryption(&plain_text[i * BLOCK_SIZE], &cipher_text[i * BLOCK_SIZE], key);
    }

    printf("\nCipher Text: ");
    for (i = 0; i < block_count * BLOCK_SIZE; i++) {
        printf("%x", cipher_text[i]);
    }
    printf("\n");

    for (i = 0; i < block_count; i++) {
        des_decryption(&cipher_text[i * BLOCK_SIZE], &decrypt_text[i * BLOCK_SIZE], key);
    }

    printf("\nDecrypt Text: ");
    for (i = 0; i < msg_len; i++) {
        printf("%c", decrypt_text[i]);
    }
    printf("\n");
}

// DES 암호화 함수
void des_encryption(byte *plain_text, byte *result, byte *key) {
    int i;
    byte data[BLOCK_SIZE] = {0};
    byte round_key[16][6] = {0};
    uint left_block = 0, right_block = 0;

    key_expansion(key, round_key);
    initial_permutation(plain_text, data);

    byte_to_word(data, &left_block, &right_block);

    for (i = 0; i < DES_ROUND; i++) {
        left_block = left_block ^ f(right_block, round_key[i]);

        if (i != DES_ROUND - 1) {
            swap(&left_block, &right_block);
        }
    }

    word_to_byte(left_block, right_block, data);
    inverse_initial_permutation(data, result);
}
// DES 복호화 함수
void des_decryption(byte *cipher_text, byte *result, byte *key) {
    int i;
    byte data[BLOCK_SIZE] = {0};
    byte round_key[16][6] = {0};
    uint left_block = 0, right_block = 0;

    key_expansion(key, round_key);
    initial_permutation(cipher_text, data);

    byte_to_word(data, &left_block, &right_block);

    for(i = 0; i < DES_ROUND; i++) {
        left_block = left_block ^ f(right_block, round_key[DES_ROUND - i - 1]);

        if(i != DES_ROUND - 1) {
            swap(&left_block,&right_block);
        }
    }

    word_to_byte(left_block, right_block, data);
    inverse_initial_permutation(data, result);
}

// 초기 순열 함수
void initial_permutation(byte *in, byte *out) {
    int i;
    byte index/*입력의 바이트 인덱스*/, bit/*입력의 비트 인덱스*/
    , mask = 0x80;//1000 0000

    for(i = 0; i < 64; i++) { //한개의 블록을 순회 한다.
        index = (initial_permutation_table[i] - 1) / 8; //바이트 배열의 몇번째 인덱스인지
        bit = (initial_permutation_table[i] - 1) % 8; //몇번째 비트인지

        if(in[index] & (mask >> bit)) { //바꾸려는 위치의 비트가 1이면
            out[i/8]/*해당 바이트 인덱스에*/ |= mask >> (i % 8); /*바꾸려는 비트 위치에 1을 쓴다.*/
        }
    }
}

// 역초기 순열 함수
void inverse_initial_permutation(byte *in, byte *out) {
    int i;
    byte index,/*입력의 바이트 인덱스*/ bit/*입력의 비트 인덱스*/
    , mask = 0x80;//1000 0000
    for(i = 0; i < 64; i++) { //한개의 블록을 순회한다.
        index = (inverse_initial_permutation_table[i] - 1) / 8; //바이트 배열의 몇번째 인덱스인지
        bit = (inverse_initial_permutation_table[i] - 1) % 8; //몇번째 비트인지

        if(in[index] & (mask >> bit)) {//바꾸려는 위치의 비트가 1이면
            out[i / 8]/*해당 바이트 인덱스에*/ |= mask >> (i % 8);/*바꾸려는 비트위치에 1을쓴다.*/
        }
    }
}
// 확장 순열 함수
void expand_permutation(uint r, byte *out) {
    int i;
    uint mask = 0x80000000; // 1000 0000 0000 0000 0000 0000 0000 0000

    for(i = 0; i < 48; i++) {//out에 48개의 비트를 채운다.
        if(r & (mask >> (expansion_permutation_table[i] - 1))) {//i번째 확장 순열 테이블을 확인후 mask를 그위치로 이동시켜서 그 값이 1이라면
            out[i/8] |= (byte)(0x80 >> (i%8));//i번째 위치에 1을 기록한다.
        }
    }
}

// 순열 함수
uint permutation(uint in) {
    int i;
    uint out = 0/*32bits output*/, mask = 0x80000000; //1000 0000 ... 32bits

    for(i = 0; i < 32; i++) {//32bit를 순회한다.
        if(in & (mask >> (p_box_table[i] - 1))) {//p_box_table위치의 값이 1이라면
            out |= (mask >> i); //그 위치에 1을쓴다.
        }
    }
    return out;
}

// 순열 선택 - 1 함수
void permuted_choice_1(byte *in, byte *out) {//64비트 -> 56비트
    int i, index, bit;
    uint mask = 0x00000080; //0000 0000 ... 1000 0000 : 32bits

    for(i = 0; i < 56; i++) {
        index = (pc1_table[i] - 1) / 8; //입력 배열의 바이트 인덱스
        bit = (pc1_table[i] - 1) % 8; //입력 배열의 비트 인덱스

        if(in[index] & (byte)(mask >> bit)) //입력 배열의 i비트에 값이 1이라면
            out[i/8] |= (byte)(mask >> (i%8)); //출력배열의 i비트에 1을 쓴다.
    }
}

// 순열 선택 - 2 함수
void permuted_choice_2(uint c, uint d, byte *out) {
    int i;
    uint mask = 0x08000000; //0000 1000 ... 0000 0000 : 32bits

    for(i = 0; i < 48;i++) {
        if((pc2_table[i] - 1) < 28) { //LK
            if(c & (mask >> (pc2_table[i] - 1))) { //i<28 번째 비트가 1이라면
                out[i/8] |= 0x80 >> (i % 8); // 1000 0000 : 8bits
            }
        } else { //RK
            if(d & (mask >> (pc2_table[i] -1 -28))) { //i >= 28 번째 비트가 1이라면
                out[i/8] |= 0x80 >> (i % 8); // 1000 0000 : 8bits
            }
        }
    }
}

// s-box 변환 함수
uint s_box_transfer(byte *in) {
    int i, row, column, shift = 28;
    uint temp = 0/*4bit temp*/, result = 0/*32bit output*/
    , mask = 0x00000080;// 0000 0000 ... 1000 0000
    
    for(i = 0; i < 48; i++) { //48bit -> 4, 4, 4, 4, 4, 4, 4, 4
        //4bit temp 값을 계산한다.
        if(in[i/8] & (byte)(mask >> (i % 8))) {
            temp |= 0x20 >> (i % 6);
        }

        //6bit가 된다면 temp값 완성이므로 s-box_i 수행
        if((i + 1) % 6 == 0) {
            row = ((temp & 0x20/*100000*/) >> 4)/*b_0*/ + (temp & 0x01)/*b_5*/;//b_0 b_5
            column = (temp & 0x1e/*11110*/) >> 1;//b_1 b_2 b_3 b_4
            result += ((uint)s_box_table[i/6][row][column] << shift); //make to result
            shift -= 4; // 4, 4, 4, 4, 4, 4, 4, 4
            temp = 0; //6bit값 초기화
        }
    }
    return result;
}

// f 함수
uint f(uint r, byte *rkey) {
    int i;
    byte data[6] = { 0 }; //48비트 확장 순열 저장 공간
    uint out;
    expand_permutation(r, data); //확장 순열

    for(i = 0; i < 6; i++) { //확장된 순열 순회
        data[i] = data[i] ^ rkey[i]; //라운드키와 xor
    }
    out = permutation(s_box_transfer(data));//최종 출력은 s-box결과를 p-box에 입력한 결과
    return out;
}

// 키 확장 함수
void key_expansion(byte *key, byte exp_key[16][6]) {
    int i;
    byte permuted_choice_1_result[7] = {0};
    uint c = 0, d = 0;

    permuted_choice_1(key, permuted_choice_1_result);

    make_bit_28(&c, &d, permuted_choice_1_result);

    for(i = 0; i < 16; i++) {
        c = circular_shift(c, i);
        d = circular_shift(d, i);

        permuted_choice_2(c,d, exp_key[i]);
    }
}

// 자리 바꿈 함수
void swap(uint *x, uint *y) {
    uint temp = *x;
    *x = *y;
    *y = temp;
}

// 56bit -> 28bit 로 나누는 함수
void make_bit_28(uint *c, uint *d, byte *data) {
    int i;
    byte mask = 0x80;

    for(i = 0; i < 56; i++) {//모든 56비트를 검사
        if(i < 28) { //left
            if(data[i/8] & (mask >> (i%8))) {
                *c |= 0x08000000 >> i;//0000 1000 ... 0000 0000 : 32bit
                                      //     ^28bit시작지점
            }
        } else { //right
            if(data[i/8] & (mask >> (i % 8))) {
                *d |= 0x08000000 >> (i - 28); //0000 1000 ... 0000 0000 : 32bit
                                              //     ^28bit 시작지점
            }
        }
    }
}

// 28bit 순환 시프트 함수
uint circular_shift(uint n/*LK(28bit), RK(28bit)*/, int r) {
    int number_shift[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

    if(number_shift[r] == 1) { //1비트 만큼 좌측 순환 시프트
        n = ((n << 1) + (n >> 27)) & 0xFFFFFFF;
    } else {//2비트 만큼 좌측 순환 시프트
        n = ((n << 2) + (n >> 26)) & 0xFFFFFFF;
    }

    return n;
}

// byte를 word로 바꾸는 함수
void byte_to_word(byte *in, uint *x, uint *y) {
    int i;
    for(i = 0; i < 8; i++) {
        if(i < 4) {
            *x |= (uint)in[i] << (24 - (i*8));
        } else {
            *y |= (uint)in[i] << (56 - (i*8));
        }
    }
}

// word를 byte로 바꾸는 함수
void word_to_byte(uint l, uint r, byte *out) {
    int i;
    uint mask = 0xFF000000;
    
    for(i = 0; i < 8; i++) {
        if(i < 4) {
            out[i] = (l & (mask >> i*8)) >> (24 - (i*8));
        } else {
            out[i] = (r & (mask >> (i-4)*8)) >> (56-(i*8));
        }
    }
}