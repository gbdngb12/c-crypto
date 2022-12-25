#include "x9_17.h"

// DES 암호화 함수
void des_encryption(byte *plain_text, byte *result, byte *key) {
    int i;
    byte data[DES_BLOCK_SIZE] = {0};
    byte round_key[16][6] = {0};
    uint left_block = 0, right_block = 0;

    des_key_expansion(key, round_key);
    des_initial_des_permutation(plain_text, data);

    des_byte_to_word(data, &left_block, &right_block);

    for (i = 0; i < DES_ROUND; i++) {
        left_block = left_block ^ des_f(right_block, round_key[i]);

        if (i != DES_ROUND - 1) {
            des_swap(&left_block, &right_block);
        }
    }

    des_word_to_byte(left_block, right_block, data);
    inverse_des_initial_des_permutation(data, result);
}
// DES 복호화 함수
void des_decryption(byte *cipher_text, byte *result, byte *key) {
    int i;
    byte data[DES_BLOCK_SIZE] = {0};
    byte round_key[16][6] = {0};
    uint left_block = 0, right_block = 0;

    des_key_expansion(key, round_key);
    des_initial_des_permutation(cipher_text, data);

    des_byte_to_word(data, &left_block, &right_block);

    for (i = 0; i < DES_ROUND; i++) {
        left_block = left_block ^ des_f(right_block, round_key[DES_ROUND - i - 1]);

        if (i != DES_ROUND - 1) {
            des_swap(&left_block, &right_block);
        }
    }

    des_word_to_byte(left_block, right_block, data);
    inverse_des_initial_des_permutation(data, result);
}

// 초기 순열 함수
void des_initial_des_permutation(byte *in, byte *out) {
    int i;
    byte index /*입력의 바이트 인덱스*/, bit /*입력의 비트 인덱스*/
        ,
        mask = 0x80;  // 1000 0000

    for (i = 0; i < 64; i++) {                           // 한개의 블록을 순회 한다.
        index = (des_initial_des_permutation_table[i] - 1) / 8;  // 바이트 배열의 몇번째 인덱스인지
        bit = (des_initial_des_permutation_table[i] - 1) % 8;    // 몇번째 비트인지

        if (in[index] & (mask >> bit)) {                            // 바꾸려는 위치의 비트가 1이면
            out[i / 8] /*해당 바이트 인덱스에*/ |= mask >> (i % 8); /*바꾸려는 비트 위치에 1을 쓴다.*/
        }
    }
}

// 역초기 순열 함수
void inverse_des_initial_des_permutation(byte *in, byte *out) {
    int i;
    byte index, /*입력의 바이트 인덱스*/ bit /*입력의 비트 인덱스*/
        ,
        mask = 0x80;                                             // 1000 0000
    for (i = 0; i < 64; i++) {                                   // 한개의 블록을 순회한다.
        index = (inverse_des_initial_des_permutation_table[i] - 1) / 8;  // 바이트 배열의 몇번째 인덱스인지
        bit = (inverse_des_initial_des_permutation_table[i] - 1) % 8;    // 몇번째 비트인지

        if (in[index] & (mask >> bit)) {                            // 바꾸려는 위치의 비트가 1이면
            out[i / 8] /*해당 바이트 인덱스에*/ |= mask >> (i % 8); /*바꾸려는 비트위치에 1을쓴다.*/
        }
    }
}
// 확장 순열 함수
void des_expand_des_permutation(uint r, byte *out) {
    int i;
    uint mask = 0x80000000;  // 1000 0000 0000 0000 0000 0000 0000 0000

    for (i = 0; i < 48; i++) {                                     // out에 48개의 비트를 채운다.
        if (r & (mask >> (expansion_des_permutation_table[i] - 1))) {  // i번째 확장 순열 테이블을 확인후 mask를 그위치로 이동시켜서 그 값이 1이라면
            out[i / 8] |= (byte)(0x80 >> (i % 8));                 // i번째 위치에 1을 기록한다.
        }
    }
}

// 순열 함수
uint des_permutation(uint in) {
    int i;
    uint out = 0 /*32bits output*/, mask = 0x80000000;  // 1000 0000 ... 32bits

    for (i = 0; i < 32; i++) {                      // 32bit를 순회한다.
        if (in & (mask >> (p_box_table[i] - 1))) {  // p_box_table위치의 값이 1이라면
            out |= (mask >> i);                     // 그 위치에 1을쓴다.
        }
    }
    return out;
}

// 순열 선택 - 1 함수
void des_permuted_choice_1(byte *in, byte *out) {  // 64비트 -> 56비트
    int i, index, bit;
    uint mask = 0x00000080;  // 0000 0000 ... 1000 0000 : 32bits

    for (i = 0; i < 56; i++) {
        index = (pc1_table[i] - 1) / 8;  // 입력 배열의 바이트 인덱스
        bit = (pc1_table[i] - 1) % 8;    // 입력 배열의 비트 인덱스

        if (in[index] & (byte)(mask >> bit))        // 입력 배열의 i비트에 값이 1이라면
            out[i / 8] |= (byte)(mask >> (i % 8));  // 출력배열의 i비트에 1을 쓴다.
    }
}

// 순열 선택 - 2 함수
void des_permuted_choice_2(uint c, uint d, byte *out) {
    int i;
    uint mask = 0x08000000;  // 0000 1000 ... 0000 0000 : 32bits

    for (i = 0; i < 48; i++) {
        if ((pc2_table[i] - 1) < 28) {               // LK
            if (c & (mask >> (pc2_table[i] - 1))) {  // i<28 번째 비트가 1이라면
                out[i / 8] |= 0x80 >> (i % 8);       // 1000 0000 : 8bits
            }
        } else {                                          // RK
            if (d & (mask >> (pc2_table[i] - 1 - 28))) {  // i >= 28 번째 비트가 1이라면
                out[i / 8] |= 0x80 >> (i % 8);            // 1000 0000 : 8bits
            }
        }
    }
}

// s-box 변환 함수
uint des_s_box_transfer(byte *in) {
    int i, row, column, shift = 28;
    uint temp = 0 /*4bit temp*/, result = 0 /*32bit output*/
        ,
         mask = 0x00000080;  // 0000 0000 ... 1000 0000

    for (i = 0; i < 48; i++) {  // 48bit -> 4, 4, 4, 4, 4, 4, 4, 4
        // 4bit temp 값을 계산한다.
        if (in[i / 8] & (byte)(mask >> (i % 8))) {
            temp |= 0x20 >> (i % 6);
        }

        // 6bit가 된다면 temp값 완성이므로 s-box_i 수행
        if ((i + 1) % 6 == 0) {
            row = ((temp & 0x20 /*100000*/) >> 4) /*b_0*/ + (temp & 0x01) /*b_5*/;  // b_0 b_5
            column = (temp & 0x1e /*11110*/) >> 1;                                  // b_1 b_2 b_3 b_4
            result += ((uint)s_box_table[i / 6][row][column] << shift);             // make to result
            shift -= 4;                                                             // 4, 4, 4, 4, 4, 4, 4, 4
            temp = 0;                                                               // 6bit값 초기화
        }
    }
    return result;
}

// f 함수
uint des_f(uint r, byte *rkey) {
    int i;
    byte data[6] = {0};  // 48비트 확장 순열 저장 공간
    uint out;
    des_expand_des_permutation(r, data);  // 확장 순열

    for (i = 0; i < 6; i++) {         // 확장된 순열 순회
        data[i] = data[i] ^ rkey[i];  // 라운드키와 xor
    }
    out = des_permutation(des_s_box_transfer(data));  // 최종 출력은 s-box결과를 p-box에 입력한 결과
    return out;
}

// 키 확장 함수
void des_key_expansion(byte *key, byte exp_key[16][6]) {
    int i;
    byte des_permuted_choice_1_result[7] = {0};
    uint c = 0, d = 0;

    des_permuted_choice_1(key, des_permuted_choice_1_result);

    des_make_bit_28(&c, &d, des_permuted_choice_1_result);

    for (i = 0; i < 16; i++) {
        c = des_circular_shift(c, i);
        d = des_circular_shift(d, i);

        des_permuted_choice_2(c, d, exp_key[i]);
    }
}

// 자리 바꿈 함수
void des_swap(uint *x, uint *y) {
    uint temp = *x;
    *x = *y;
    *y = temp;
}

// 56bit -> 28bit 로 나누는 함수
void des_make_bit_28(uint *c, uint *d, byte *data) {
    int i;
    byte mask = 0x80;

    for (i = 0; i < 56; i++) {  // 모든 56비트를 검사
        if (i < 28) {           // left
            if (data[i / 8] & (mask >> (i % 8))) {
                *c |= 0x08000000 >> i;  // 0000 1000 ... 0000 0000 : 32bit
                                        //      ^28bit시작지점
            }
        } else {  // right
            if (data[i / 8] & (mask >> (i % 8))) {
                *d |= 0x08000000 >> (i - 28);  // 0000 1000 ... 0000 0000 : 32bit
                                               //      ^28bit 시작지점
            }
        }
    }
}

// 28bit 순환 시프트 함수
uint des_circular_shift(uint n /*LK(28bit), RK(28bit)*/, int r) {
    int number_shift[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

    if (number_shift[r] == 1) {  // 1비트 만큼 좌측 순환 시프트
        n = ((n << 1) + (n >> 27)) & 0xFFFFFFF;
    } else {  // 2비트 만큼 좌측 순환 시프트
        n = ((n << 2) + (n >> 26)) & 0xFFFFFFF;
    }

    return n;
}

// byte를 word로 바꾸는 함수
void des_byte_to_word(byte *in, uint *x, uint *y) {
    int i;
    for (i = 0; i < 8; i++) {
        if (i < 4) {
            *x |= (uint)in[i] << (24 - (i * 8));
        } else {
            *y |= (uint)in[i] << (56 - (i * 8));
        }
    }
}

// word를 byte로 바꾸는 함수
void des_word_to_byte(uint l, uint r, byte *out) {
    int i;
    uint mask = 0xFF000000;

    for (i = 0; i < 8; i++) {
        if (i < 4) {
            out[i] = (l & (mask >> i * 8)) >> (24 - (i * 8));
        } else {
            out[i] = (r & (mask >> (i - 4) * 8)) >> (56 - (i * 8));
        }
    }
}

// ANSI X9.17 의사 난수 생성 함수
void des_x9_17_random_generator(byte *random_number, byte *key1, byte *key2, int random_number_size) {
    int i, j;
    byte v[8] = {0};
    byte dt[8] = {0};
    byte input[8] = {0};
    byte triple_des_result[8] = {0};

    des_set_vector(v);

    for (i = 0; i < random_number_size; i += DES_BLOCK_SIZE) {
        des_get_date_time(dt);

        triple_des_encryption(dt, triple_des_result, key1, key2);  // EDE(DT)

        for (j = 0; j < DES_BLOCK_SIZE; j++) {
            input[j] = v[j] ^ triple_des_result[j];  // EDE(DT) ^ V
        }

        triple_des_encryption(input, &random_number[i], key1, key2);  // EDE(마지막 안의 값(input))

        // 다음 초기 벡터 계산 V_{i+1}
        for (j = 0; j < DES_BLOCK_SIZE; j++)
            input[j] = triple_des_result[j] ^ random_number[i + j];  // EDE(DT) ^ R
        triple_des_encryption(input, v, key1, key2);                 // EDE(마지막 안의 값(input))
    }
}
// 날짜와 시간을 얻는 함수
void des_get_date_time(byte *dt) {
    int i;
    time_t current_time;
    time(&current_time);  // get current time

    for (i = 0; i < DES_BLOCK_SIZE; i += 4) {
        dt[i] = (byte)((current_time  && 0xff000000) >> 24);
        dt[i + 1] = (byte)((current_time && 0x00ff0000) >> 16);
        dt[i + 2] = (byte)((current_time && 0x0000ff00) >> 8);
        dt[i + 3] = (byte)(current_time && 0x000000ff);
    }
}
// 초기 벡터 값 설정 함수
void des_set_vector(byte *v) {
    int i;
    srand(time(NULL));

    for (i = 0; i < DES_BLOCK_SIZE; i++) {
        v[i] = (byte)(rand() % 256);
    }
}
// 삼중 DES 암호화 함수
void triple_des_encryption(byte *plain_text, byte *result, byte *key1, byte *key2) {
    byte middle_text1[DES_BLOCK_SIZE] = { 0 };
    byte middle_text2[DES_BLOCK_SIZE] = { 0 };

    //EDE
    des_encryption(plain_text, middle_text1, key1);
    des_decryption(middle_text1, middle_text2, key2);
    des_encryption(middle_text2, result, key1);
}
// 삼중 DES 복호화 함수
void triple_des_decryption(byte *cipher_text, byte *result, byte *key1, byte *key2) {
    byte middle_text1[DES_BLOCK_SIZE] = { 0 };
    byte middle_text2[DES_BLOCK_SIZE] = { 0 };

    //DED
    des_decryption(cipher_text, middle_text1, key1);
    des_encryption(middle_text1, middle_text2, key2);
    des_decryption(middle_text2, result, key1);
}