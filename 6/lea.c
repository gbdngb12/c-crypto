#include <stdio.h>
#include <string.h>

/*상수 정의*/
#define BLOCK_SIZE 16  // LEA 블록 사이즈(128비트)(16바이트)

/*type 정의*/
typedef unsigned char byte;
typedef unsigned int uint;

static const uint delta[8] = {
    0xc3efe9db,
    0x44626b02,
    0x79e27c8a,
    0x78df30ec,
    0x715ea49e,
    0xc785da0a,
    0xe04ef22a,
    0xe5c40957};

/*함수 선언*/
// 128비트 키를 입력 받아서 192비트 라운드키 생성
void keyschedule_128(byte *key, uint *round_key);
// 암호화 라운드
void encrypt_round(uint *out, uint *in, uint *round_Key);
// 복호화 라운드
void encrypt_round(uint *out, uint *in, uint *round_Key);
// LEA 암호화 함수
void lea_encrypt(int nr, uint *round_key, byte *plain_text, byte *cipher_text);
// LEA 복호화 함수
void lea_decrypt(int nr, uint *round_key, byte *decrypt_text, byte *cipher_text);

/*간단한 매크로 함수 정의*/

// 32bit값 w를 i비트 만큼 좌측 순환 시프트
#define ROL(i, w) (((w) << (i)) | ((w) >> (32 - (i))))
// 32bit값 w를 i비트 만큼 우측 순환 시프트
#define ROR(i, w) (((w) >> (i)) | ((w) << (32 - (i))))
// 두 word x,y를 더한다
#define addition(x, y) (x + y)
// 두 word x,y를 뺀다.
#define subtraction(x, y) (x - y)

int main() {
    int i;
    int msg_len = 0, block_count = 0;
    byte plain_text[128] = {0};
    byte key[33] = {0};            // 16바이트(128비트 키) (마지막 NULL 바이트)
    byte cipher_text[128] = {0};   // 암호문
    byte decrypt_text[128] = {0};  // 복호문

    int Nk = 16 /*비밀키의 바이트 수*/, Nr = 24 /*라운드 수*/;

    // 128비트 비밀키의 경우 -> 192비트(6바이트) * 24개
    // 192비트 비밀키의 경우 -> 192비트(6바이트) * 28개
    // 256비트 비밀키의 경우 -> 192비트(6바이트) * 32개
    uint round_key[192] = {0};  // 최대 갯수로 설정
    // 6byte(192bit) round_key[24];

    // Input Plain Text
    printf("Input Plain Text: ");
    gets(plain_text);

    // Input Secret Key
    printf("Input Secret Key(128bit)(16byte): ");
    scanf("%s", key);

    keyschedule_128(key, round_key);  // 128비트 키스케쥴링

    // 메시지 길이와 블록 수 계산
    msg_len = (int)strlen((char *)plain_text);
    block_count = (msg_len % BLOCK_SIZE) ? (msg_len / BLOCK_SIZE + 1) : (msg_len / BLOCK_SIZE);

    for (i = 0; i < block_count; i++) {
        lea_encrypt(Nr, round_key, &plain_text[i*BLOCK_SIZE], &cipher_text[i*BLOCK_SIZE]);  // LEA 암호화
    }

    printf("\nEncrypt Text: ");
    for (i = 0; i < block_count * BLOCK_SIZE; i++) {
        printf("%x", cipher_text[i]);
    }

    for (i = 0; i < block_count; i++) {
        lea_decrypt(Nr, round_key, &decrypt_text[i*BLOCK_SIZE], &cipher_text[i*BLOCK_SIZE]);  // LEA 복호화
    }

    printf("\nDecrypt Text: ");
    for (i = 0; i < msg_len; i++) {
        printf("%c", decrypt_text[i]);
    }
    printf("\n");

    return 0;
}

// 128비트 키를 입력 받아서 192비트 라운드키 생성
void keyschedule_128(byte *key /*16바이트 키*/, uint *round_key /*192비트(24바이트)*/) {
    int i;
    uint t[4] = {0};  // T[0], T[1], T[2], T[3]
    // k0 k1 k2 k3 | k4 k5 k6 k7 | k8 k9 ...
    //^--T[0]--^    ^--T[1]--^
    // 최초 T[0], T[1], T[2], T[3]은 128비트 키
    for (i = 0; i < 4; i++) {
        t[i] = (key[i * 4 + 3] << 24) | (key[i * 4 + 2] << 16) | (key[i * 4 + 1] << 8) | (key[i * 4]);
    }

    for (i = 0; i < 24; i++) {
        t[0] = ROL(1, addition(t[0], ROL(i, delta[i % 4])));
        t[1] = ROL(3, addition(t[1], ROL(i + 1, delta[i % 4])));
        t[2] = ROL(6, addition(t[2], ROL(i + 2, delta[i % 4])));
        t[3] = ROL(11, addition(t[3], ROL(i + 3, delta[i % 4])));

        // 24바이트(192비트) 라운드 키
        round_key[i * 6 + 0] = t[0];
        round_key[i * 6 + 1] = t[1];
        round_key[i * 6 + 2] = t[2];
        round_key[i * 6 + 3] = t[1];
        round_key[i * 6 + 4] = t[3];
        round_key[i * 6 + 5] = t[1];
    }
}

// 암호화 라운드
void encrypt_round(uint *out, uint *in, uint *round_Key) {
    out[0] = ROL(9, addition((in[0] ^ round_Key[0]), (in[1] ^ round_Key[1])));
    out[1] = ROR(5, addition((in[1] ^ round_Key[2]), (in[2] ^ round_Key[3])));
    out[2] = ROR(3, addition((in[2] ^ round_Key[4]), (in[3] ^ round_Key[5])));
    out[3] = in[0];
}

// 복호화 라운드
void decrypt_round(uint *out, uint *in, uint *round_Key) {
    out[0] = in[3];
    out[1] = subtraction((ROR(9, in[0])), (out[0] ^ round_Key[0]) ) ^ round_Key[1];
    out[2] = subtraction((ROL(5, in[1])), (out[1] ^ round_Key[2]) ) ^ round_Key[3];
    out[3] = subtraction((ROL(3, in[2])), (out[2] ^ round_Key[4]) ) ^ round_Key[5];
}

// LEA 암호화 함수
void lea_encrypt(int nr, uint *round_key, byte *plain_text, byte *cipher_text) {
    int i, j;
    uint x_in[4];
    uint x_out[4];

    // x_in에 plain Text 저장한다.
    // plain_text p0 p1 p2 p3
    // x_in[0] : p3 p2 p1 p0
    // x_in[1] : p7 p6 p5 p4
    // x_in[2] : p11 p10 p9 p8
    // x_in[3] : p15 p14 p13 p12
    for (i = 0; i < 4; i++) {
        x_in[i] = (plain_text[i * 4 + 3] << 24) | (plain_text[i * 4 + 2] << 16) + (plain_text[i * 4 + 1] << 8) | (plain_text[i * 4]);
    }

    // 라운드 순회
    for (i = 0; i < nr; i++) {
        encrypt_round(x_out, x_in, &round_key[i * 6]);  // 라운드 함수 실행
        for (j = 0; j < 4; j++) {
            x_in[j] = x_out[j];  // 라운드 함수 결과를 저장
        }
    }

    // x_in[0] : a0 a1 a2 a3
    // cipher_text[0] : a3
    // cipher_text[1] : a2
    // cipher_text[2] : a1
    // cipher_text[3] : a0
    for (i = 0; i < 4; i++) {
        cipher_text[i * 4] = (x_in[i]) & 0xff;            // 1111 1111
        cipher_text[i * 4 + 1] = (x_in[i] >> 8) & 0xff;   // 1111 1111
        cipher_text[i * 4 + 2] = (x_in[i] >> 16) & 0xff;  // 1111 1111
        cipher_text[i * 4 + 3] = (x_in[i] >> 24) & 0xff;  // 1111 1111
    }
}

// LEA 복호화 함수
void lea_decrypt(int nr, uint *round_key, byte *decrypt_text, byte *cipher_text) {
    int i, j;
    uint x_in[4];
    uint x_out[4];

    // x_in에 cipher Text 저장한다.
    // cipher_text c0 c1 c2 c3
    // x_in[0] : c3  c2  c1  c0
    // x_in[1] : c7  c6  c5  c4
    // x_in[2] : c11 c10 c9  c8
    // x_in[3] : c15 c14 c13 c12
    for (i = 0; i < 4; i++) {
        x_in[i] = (cipher_text[i * 4 + 3] << 24) | (cipher_text[i * 4 + 2] << 16) | (cipher_text[i * 4 + 1] << 8) | (cipher_text[i * 4]);
    }

    for (i = 0; i < nr; i++) {
        decrypt_round(x_out, x_in, &round_key[(nr - i - 1) * 6]);
        for (j = 0; j < 4; j++) {
            x_in[j] = x_out[j];
        }
    }

    // x_in[0] : a0 a1 a2 a3
    // plain_text[0] : a3
    // plain_text[1] : a2
    // plain_text[2] : a1
    // plain_text[3] : a0
    for (i = 0; i < 4; i++) {
        decrypt_text[i * 4] = (x_in[i]) & 0xff;
        decrypt_text[i * 4 + 1] = (x_in[i] >> 8) & 0xff;
        decrypt_text[i * 4 + 2] = (x_in[i] >> 16) & 0xff;
        decrypt_text[i * 4 + 3] = (x_in[i] >> 24) & 0xff;
    }
}