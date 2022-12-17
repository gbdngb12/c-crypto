#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define Nb 4 //AES 평문 워드수(4word) (128비트 / 32비트(word)-> 4word) 
#define Nk 4 //AES 키의 워드수(4word) (128비트 / 32비트(word)-> 4word)

typedef unsigned int word;
typedef unsigned char byte;

/*매크로 함수*/
//#define hi_hex(x) (x >> 4) //8bit에서 상위 4bit값을 구하는 함수
//#define hi_hex(x) ( x >> 4)
//#define low_hex(x) ( x & 0x0F )
//#define byte_to_word(b0, b1, b2, b3) ( ((word)b0 << 24) | ((word)b1 << 16) | ((word)b2 << 8) | (word)b3 )	// BYTE를 WORD로 변환하는 함수
byte hi_hex(byte x) {
    return (x >> 4);
}

//8bit에서 하위 4bit값을 구하는 함수
byte low_hex(byte x) {
    return (x & 0x0F);
}

word byte_to_word(byte b0,byte b1,byte b2,byte b3) {
    return (((word)b0 << 24) | ((word)b1 << 16) | ((word)b2 << 8) | ((word)b3));
}

//함수 선언
void aes_encrypt(byte *in, byte *out, byte *key);//AES 암호화
void aes_decrypt(byte *in, byte *out, byte *key);//AES 복호화
void sub_bytes(byte state[][4]); //subbytes
void inverse_sub_bytes(byte state[][4]);//inverse subbytes
void shift_rows(byte state[][4]);//shiftrows
void inverse_shift_rows(byte state[][4]);//inverse shiftrows
void mix_columns(byte state[][4]);//mixcolumms
void inverse_mix_columns(byte state[][4]);//inverse columns
void add_round_key(byte state[][4], word*);//AddRoundKey
void key_expansion(byte *key, word* w);//AES 키 확장 함수
//이거 뭔가 잘못된듯
void circular_shift_rows(byte* row); //state의 한행을 1회 오른쪽으로 순환 시프트
void inverse_circular_shift_rows(byte *row);//state의 한행을 1회 왼쪽으로 순환 시프트
word sub_word(word w); //SubWord
word rot_word(word w); //RotWord
byte x_time(byte n, byte b); //GF(2^8) 상에서 곱셈 연산 함수

//암호화 s-box
byte s_box_table[16][16] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

//복호화 s-box
byte inverse_s_box_table[16][16] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

//Rcon 상수
static word Rcon[11] = {0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
                        0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000};

static int number_of_round;//라운드 수

int main() {
    int i;
    int msg_len = 0, block_count = 0;
    byte plain_text[128] = { 0 }; //128비트 평문
    byte key[Nk*4 + 1] = { 0 }; //128비트 키
    byte cipher_text[128] = { 0 };//128비트 암호문
    byte inverse_cipher_text[128] = { 0 };//128비트 복호문

    printf("Input Plain Text: ");
    gets(plain_text);

    printf("Input Secret Key: ");
    scanf("%s", key);

    msg_len = (int)strlen((char*)plain_text);
    block_count = (msg_len % (Nb*4))/*16바이트(128비트)(AES 블록의 크기)*/ ? (msg_len / (Nb*4) + 1) : (msg_len / (Nb*4));

    for(i = 0; i < block_count; i++) {
        aes_encrypt(&plain_text[i*Nb*4], &cipher_text[i*Nb*4/*16 bytes*/], key);//암호화
    }

    printf("\nEncrypt Text: ");
    for(i = 0; i < block_count*Nb*4/*block_count*16*/; i++) {
        printf("%x", cipher_text[i]);
    }
    printf("\n");

    for(i = 0; i < block_count; i++) {
        aes_decrypt(&cipher_text[i*Nb*4], &inverse_cipher_text[i*Nb*4], key);//복호화
    }

    printf("\nDecrypt Text: ");
    for(i = 0; i < msg_len; i++) {
        printf("%c", inverse_cipher_text[i]);
    }
    printf("\n");
    return 0;
}


void sub_bytes(byte state[][4]) { //subbytes 
    int i,j;

    for(i = 0; i < 4; i++) {
        for(j = 0; j < 4;j++) {
            state[i][j] = s_box_table[hi_hex(state[i][j])][low_hex(state[i][j])];//s_box_table에서 상위 4비트 하위 4비트값 조합해서 상태로 저장
        }
    }
}
void inverse_sub_bytes(byte state[][4]) { //inverse subbytes
    int i,j;

    for(i = 0; i < 4; i++) {
        for(j = 0; j < 4;j++) {
            state[i][j] = inverse_s_box_table[hi_hex(state[i][j])][low_hex(state[i][j])];//inverse_s_box_table에서 상위 4비트 하위 4비트값 조합해서 상태 복구
        }
    }
}
void shift_rows(byte state[][4]) {//shiftrows
    int i, j;
    for(i = 1; i < 4; i++) {
        for(j = 0; j < i; j++) {
            circular_shift_rows(state[i]);
        }
    }
}
void inverse_shift_rows(byte state[][4]) { //inverse shiftrows
    int i, j;
    for(i = 1; i < 4;i++) {
        for(j = 0; j < i; j++) {
            inverse_circular_shift_rows(state[i]);
        }
    }
}
void mix_columns(byte state[][4]) {//mixcolumms
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
                b[i][j] ^= x_time(a[i][k], state[k][j]);
            }
        }
    }

    for(i = 0; i < 4; i++) {
        for(j = 0; j < 4; j++) {
            state[i][j] = b[i][j];
        }
    }
}
void inverse_mix_columns(byte state[][4]) {//inverse columns
    int i,j,k;
    byte a[4][4] = {0x0e, 0x0b, 0x0d, 0x09,
                    0x09, 0x0e, 0x0b, 0x0d,
                    0x0d, 0x09, 0x0e, 0x0b,
                    0x0b, 0x0d, 0x09, 0x0e};
    
    byte b[4][4] = { 0 };

    for(i = 0; i < 4; i++) {
        for(j = 0; j < 4; j++) {
            for(k = 0; k < 4; k++) {
                b[i][j] ^= x_time(a[i][k], state[k][j]);
            }
        }
    }

    for(i = 0;i < 4; i++) {
        for(j = 0; j < 4; j++) {
            state[i][j] = b[i][j];
        }
    }
}
void add_round_key(byte state[][4], word* r_key) {//AddRoundKey
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
void key_expansion(byte *key, word* w) { //AES 키 확장 함수
    word temp;
    int i = 0;

    while(i < Nk) {
        w[i] = byte_to_word(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]);
        i++;
    }

    i = Nk;

    while(i < (Nb * (number_of_round + 1))) {
        temp = w[i - 1];
        if(i % Nk == 0) {
            temp = sub_word(rot_word(temp)) ^ Rcon[i/Nk - 1];
        } else if((Nk > 6) && (i % Nk == 4)) {
            temp = sub_word(temp);
        }

        w[i] = w[i - Nk] ^ temp;
        i++;
    }
}

void circular_shift_rows(byte* row) { //state의 한행을 1회 왼쪽으로 순환 시프트
    byte temp = row[0];
    row[0] = row[1];
    row[1] = row[2];
    row[2] = row[3];
    row[3] = temp;
}
void inverse_circular_shift_rows(byte *row) {//state의 한행을 1회 오른쪽으로 순환 시프트
    byte temp = row[3];
    row[3] = row[2];
    row[2] = row[1];
    row[1] = row[0];
    row[0] = temp;
}
word sub_word(word w) { //SubWord
    int i;
    word out = 0, mask = 0xff000000;
    byte shift = 24;

    for(i = 0; i < 4; i++) {
        out += (word)s_box_table[hi_hex((w & mask) >> shift)][low_hex((w & mask) >> shift)] << shift;
        mask >>= 8;
        shift -= 8;
    }
    return out;
}
word rot_word(word w) { //RotWord
    return ((w & 0xff000000) >> 24) | (w << 8);
}
byte x_time(byte n/*a 상수*/, byte b/*state*/){ //GF(2^8) 상에서 곱셈 연산 함수
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

    if(Nk == 4) {
        number_of_round = 10;
        w = (word *)malloc(sizeof(word) * Nb * (number_of_round + 1));//확장 키 사이즈 할당
    }

    if(Nk == 6) {
        number_of_round = 12;
        w = (word *)malloc(sizeof(word)* Nb * (number_of_round + 1));
    }

    if(Nk == 8) {
        number_of_round = 14;
        w = (word *)malloc(sizeof(word) * Nb * (number_of_round + 1));
    }

    for(i = 0; i < 4; i++) {
        for(j = 0; j < 4; j++) {
            state[j][i] = in[i*4 + j];
        }
    }

    key_expansion(key, w);

    add_round_key(state ,w);

    for(i = 0; i < number_of_round - 1; i++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &w[(i + 1)*4]);
    }

    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &w[(i + 1)*4]);

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

    if(Nk == 4) {
        number_of_round = 10;
        w = (word *)malloc(sizeof(word) * Nb * (number_of_round + 1));//확장 키 사이즈 할당
    }

    if(Nk == 6) {
        number_of_round = 12;
        w = (word *)malloc(sizeof(word)* Nb * (number_of_round + 1));
    }

    if(Nk == 8) {
        number_of_round = 14;
        w = (word *)malloc(sizeof(word) * Nb * (number_of_round + 1));
    }

    for(i = 0; i < 4; i++) {
        for(j = 0; j < 4; j++) {
            state[j][i] = in[i*4 + j];
        }
    }

    key_expansion(key, w);

    add_round_key(state, &w[number_of_round*Nb]);

    for(i = 0; i < number_of_round - 1; i++) {
        inverse_shift_rows(state);
        inverse_sub_bytes(state);
        add_round_key(state, &w[(number_of_round-i-1)* Nb]);
        inverse_mix_columns(state);
    }

    inverse_shift_rows(state);
    inverse_sub_bytes(state);
    add_round_key(state, &w[(number_of_round -i - 1)* Nb]);

    for(i = 0; i < 4; i++) {
        for(j = 0; j < 4; j++) {
            out[i*4 + j] = state[j][i];
        }
    }
    free(w);
}