#include "aes.h"
byte aes_hi_hex(byte x) {
    return (x >> 4);
}

//8bit에서 하위 4bit값을 구하는 함수
byte aes_low_hex(byte x) {
    return (x & 0x0F);
}

word aes_byte_to_word(byte b0,byte b1,byte b2,byte b3) {
    return (((word)b0 << 24) | ((word)b1 << 16) | ((word)b2 << 8) | ((word)b3));
}

void aes_sub_bytes(byte state[][4]) { //subbytes 
    int i,j;

    for(i = 0; i < 4; i++) {
        for(j = 0; j < 4;j++) {
            state[i][j] = aes_s_box_table[aes_hi_hex(state[i][j])][aes_low_hex(state[i][j])];//s_box_table에서 상위 4비트 하위 4비트값 조합해서 상태로 저장
        }
    }
}
void aes_inverse_sub_bytes(byte state[][4]) { //inverse subbytes
    int i,j;

    for(i = 0; i < 4; i++) {
        for(j = 0; j < 4;j++) {
            state[i][j] = aes_inverse_s_box_table[aes_hi_hex(state[i][j])][aes_low_hex(state[i][j])];//inverse_s_box_table에서 상위 4비트 하위 4비트값 조합해서 상태 복구
        }
    }
}
void aes_shift_rows(byte state[][4]) {//shiftrows
    int i, j;
    for(i = 1; i < 4; i++) {
        for(j = 0; j < i; j++) {
            aes_circular_shift_rows(state[i]);
        }
    }
}
void aes_inverse_shift_rows(byte state[][4]) { //inverse shiftrows
    int i, j;
    for(i = 1; i < 4;i++) {
        for(j = 0; j < i; j++) {
            aes_inverse_circular_shift_rows(state[i]);
        }
    }
}
void aes_mix_columns(byte state[][4]) {//mixcolumms
    int i,j,k;
    byte a[4][4] = {
        0x02, 0x03, 0x01, 0x01,
        0x01, 0x02, 0x03, 0x01,
        0x01, 0x01, 0x02, 0x03,
        0x03, 0x01, 0x01, 0x02};
    byte b[4][4] = { 0 };

    for(i = 0; i < 4; i++) {
        for(j = 0; j < 4; j++) {
            for(k = 0; k < 4; k++) {
                b[i][j] ^= aes_x_time(a[i][k], state[k][j]);
            }
        }
    }

    for(i = 0; i < 4; i++) {
        for(j = 0; j < 4; j++) {
            state[i][j] = b[i][j];
        }
    }
}
void aes_inverse_mix_columns(byte state[][4]) {//inverse columns
    int i,j,k;
    byte a[4][4] = {0x0e, 0x0b, 0x0d, 0x09,
                    0x09, 0x0e, 0x0b, 0x0d,
                    0x0d, 0x09, 0x0e, 0x0b,
                    0x0b, 0x0d, 0x09, 0x0e};
    
    byte b[4][4] = { 0 };

    for(i = 0; i < 4; i++) {
        for(j = 0; j < 4; j++) {
            for(k = 0; k < 4; k++) {
                b[i][j] ^= aes_x_time(a[i][k], state[k][j]);
            }
        }
    }

    for(i = 0;i < 4; i++) {
        for(j = 0; j < 4; j++) {
            state[i][j] = b[i][j];
        }
    }
}
void aes_add_round_key(byte state[][4], word* r_key) {//AddRoundKey
    int i, j;
    word mask, shift;

    for(i = 0; i < 4; i++) {
        shift = 24;
        mask = 0xff000000;

        for(j = 0; j < 4; j++) {
            state[j][i] = ((r_key[i] & mask) >> shift) ^ state[j][i]; //S_00 ^ k_00, S_10 ^ k_01 ...
            mask >>= 8;
            shift -= 8;
        }
    }
}
void aes_key_expansion(byte *key, word* w) { //AES 키 확장 함수
    word temp;
    int i = 0;

    while(i < AES_Nk) {
        w[i] = aes_byte_to_word(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]);
        i++;
    }

    i = AES_Nk;

    while(i < (AES_Nb * (aes_number_of_round + 1))) {
        temp = w[i - 1];
        if(i % AES_Nk == 0) {
            temp = aes_sub_word(aes_rot_word(temp)) ^ aes_Rcon[i/AES_Nk - 1];
        } else if((AES_Nk > 6) && (i % AES_Nk == 4)) {
            temp = aes_sub_word(temp);
        }

        w[i] = w[i - AES_Nk] ^ temp;
        i++;
    }
}

void aes_circular_shift_rows(byte* row) { //state의 한행을 1회 왼쪽으로 순환 시프트
    byte temp = row[0];
    row[0] = row[1];
    row[1] = row[2];
    row[2] = row[3];
    row[3] = temp;
}
void aes_inverse_circular_shift_rows(byte *row) {//state의 한행을 1회 오른쪽으로 순환 시프트
    byte temp = row[3];
    row[3] = row[2];
    row[2] = row[1];
    row[1] = row[0];
    row[0] = temp;
}
word aes_sub_word(word w) { //SubWord
    int i;
    word out = 0, mask = 0xff000000;
    byte shift = 24;

    for(i = 0; i < 4; i++) {
        out += (word)aes_s_box_table[aes_hi_hex((w & mask) >> shift)][aes_low_hex((w & mask) >> shift)] << shift;
        mask >>= 8;
        shift -= 8;
    }
    return out;
}
word aes_rot_word(word w) { //RotWord
    return ((w & 0xff000000) >> 24) | (w << 8);
}
byte aes_x_time(byte n/*a 상수*/, byte b/*state*/){ //GF(2^8) 상에서 곱셈 연산 함수
    //n은 2, 3, 1, 1
    //10, 11, 01 밖에 없음
    // 2 -> 10
    // 3 -> 10 xor 01

    int i;
    byte temp= 0, mask = 0x01;// 0000 0001
    //2로 곱할때는 왼쪽으로 한칸 쉬프트지만 GF(2^8)상에서 2를 곱할때 왼쪽 최상위 비트가 1인경우 왼쪽으로 한칸 쉬프트후 0001 1011을 xor하고 곱셈을 마무리한다.

    for(i = 0; i < 8; i++) {
        if(n & mask)
            temp ^= b;  
        
        if(b & 0x80)//1000 0000 최상위 비트가 1인경우
            b = (b << 1) ^ 0x1b; //
        else
            b <<= 1;

        mask <<= 1;
    }

    return temp;
}

void aes_encrypt(byte *in, byte *out, byte *key) {//AES 암호화
    int i, j;
    byte state[4][4];
    word *w;

    if(AES_Nk == 4) {
        aes_number_of_round = 10;
        w = (word *)malloc(sizeof(word) * AES_Nb * (aes_number_of_round + 1));//확장 키 사이즈 할당
    }

    if(AES_Nk == 6) {
        aes_number_of_round = 12;
        w = (word *)malloc(sizeof(word)* AES_Nb * (aes_number_of_round + 1));
    }

    if(AES_Nk == 8) {
        aes_number_of_round = 14;
        w = (word *)malloc(sizeof(word) * AES_Nb * (aes_number_of_round + 1));
    }

    for(i = 0; i < 4; i++) {
        for(j = 0; j < 4; j++) {
            state[j][i] = in[i*4 + j];
        }
    }

    aes_key_expansion(key, w);

    aes_add_round_key(state ,w);

    for(i = 0; i < aes_number_of_round - 1; i++) {
        aes_sub_bytes(state);
        aes_shift_rows(state);
        aes_mix_columns(state);
        aes_add_round_key(state, &w[(i + 1)*4]);
    }

    aes_sub_bytes(state);
    aes_shift_rows(state);
    aes_add_round_key(state, &w[(i + 1)*4]);

    for(i = 0; i < 4; i++) {
        for(j = 0; j < 4; j++) {
            out[i*4 + j] = state[j][i];
        }
    }

    free(w);
}
void aes_decrypt(byte *in, byte *out, byte *key) {//AES 복호화
    int i, j;
    byte state[4][4];
    word *w;

    if(AES_Nk == 4) {
        aes_number_of_round = 10;
        w = (word *)malloc(sizeof(word) * AES_Nb * (aes_number_of_round + 1));//확장 키 사이즈 할당
    }

    if(AES_Nk == 6) {
        aes_number_of_round = 12;
        w = (word *)malloc(sizeof(word)* AES_Nb * (aes_number_of_round + 1));
    }

    if(AES_Nk == 8) {
        aes_number_of_round = 14;
        w = (word *)malloc(sizeof(word) * AES_Nb * (aes_number_of_round + 1));
    }

    for(i = 0; i < 4; i++) {
        for(j = 0; j < 4; j++) {
            state[j][i] = in[i*4 + j];
        }
    }

    aes_key_expansion(key, w);

    aes_add_round_key(state, &w[aes_number_of_round*AES_Nb]);

    for(i = 0; i < aes_number_of_round - 1; i++) {
        aes_inverse_shift_rows(state);
        aes_inverse_sub_bytes(state);
        aes_add_round_key(state, &w[(aes_number_of_round-i-1)* AES_Nb]);
        aes_inverse_mix_columns(state);
    }

    aes_inverse_shift_rows(state);
    aes_inverse_sub_bytes(state);
    aes_add_round_key(state, &w[(aes_number_of_round -i - 1)* AES_Nb]);

    for(i = 0; i < 4; i++) {
        for(j = 0; j < 4; j++) {
            out[i*4 + j] = state[j][i];
        }
    }
    free(w);
}