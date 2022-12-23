#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HASH_BLOCK 64  // 해쉬 블록 크기(512비트)(byte)
#define HASH_DATA 16   // 해쉬 출력 값의 크기(byte)

// 순환이동 횟수
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

// 타입 정의
typedef unsigned char byte;
typedef unsigned int uint;
typedef unsigned long long uint64;

static int isAddpad = 0;
static uint init_reg[4];        // 초기 레지스터
static byte digest[HASH_DATA];  // 해쉬 값

//기약 논리함수
#define F(X,y,z) ( ((X)&(y)) | ((~X)&(z)) )
#define G(X,y,z) ( ((X)&(z)) | ((y)&(~(z))) )
#define H(X,y,z) ( ((X)^(y)^(z)) )
#define I(X,y,z) ( (y) ^ ((X)|(~(z))) )

void padding(byte *in, uint64 msg_len);
void md_5_init();
void md_5_digest(byte *in);
void md_5(FILE *fptr, byte *result);
#define byte_to_word(a,b,c,d) ( ((a << 24) + (b << 16) + (c << 8) + d) )
#define circular_shift(X,n) ( ((X) << n) | ((X) >> (32-n)) )			

void make_bit_128(byte in[16],uint a, uint b, uint c, uint d);//word단위 해쉬 값을 byte단위로 변환 하는 함수

void ff(uint* a,uint b, uint c, uint d, uint m, int s, uint t) {
    *a = b + circular_shift((*a + F(b,c,d) + m + t), s);
}

void gg(uint* a,uint b, uint c, uint d, uint m, int s, uint t) {
    *a = b + circular_shift((*a + G(b,c,d) + m + t), s);
}

void hh(uint* a,uint b, uint c, uint d, uint m, int s, uint t) {
    *a = b + circular_shift((*a + H(b,c,d) + m + t), s);
}

void ii(uint* a,uint b, uint c, uint d, uint m, int s, uint t) {
    *a = b + circular_shift((*a + I(b,c,d) + m + t), s);
}

void padding(byte *in, uint64 msg_len) {
    int i;
    byte *ptr = (byte *)&msg_len;

    if ((msg_len % HASH_BLOCK) < 56) {    // 56바이트 보다 작다면
        in[msg_len % HASH_BLOCK] = 0x80;  // 메시지의 끝 한비트 뒤에 1을 적음
        msg_len *= 8;                     // 메시지의 길이값(바이트)를 비트로 변환 (16byte -> 128bit)

        for (i = 0; i < 8; i++) {
            in[HASH_BLOCK - i - 1] = *(ptr + (7 - i));  //msg_len값이 little-endian일 경우!  8byte Data -> 8byte Array로 저장함
        }
    } else {
        in[msg_len % HASH_BLOCK] = 0x80;
        msg_len *= 8;
        isAddpad = 1;
        for (i = 0; i < 8; i++) {
            in[HASH_BLOCK * 2 - i - 1] = *(ptr + (7 - i));  // little endian방식으로 저장함
        }
    }
}

// little endian 컴퓨터 이므로 순서를 정확히 지켜야함
void md_5_init() {
    init_reg[0] = 0x67452301;  // 실제 컴퓨터에 저장 순서 0x01234567
    init_reg[1] = 0xefcdab89;  // 0x89abcdef
    init_reg[2] = 0x98badcfe;  // 0xfedcba98
    init_reg[3] = 0x10325476;  // 0x76543210
}

void md_5_digest(byte *in) {
    int i;
    uint a,b,c,d;
    uint x[16] = { 0 };//중간과정에서 처리되는 32비트 * 4 => 128비트 값
    
    for(i = 0; i < 64; i += 4) {//message -> x로 저장
        x[i/4] = byte_to_word(in[i + 3], in[i + 2], in[i + 1], in[i]);//save to little-endian
    }

    a = init_reg[0]; b = init_reg[1]; c = init_reg[2]; d = init_reg[3];

    /*Round 1*/
    ff(&a, b, c, d, x[ 0], S11, 0xd76aa478); /* 1회*/
	ff(&d, a, b, c, x[ 1], S12, 0xe8c7b756); /* 2회*/
	ff(&c, d, a, b, x[ 2], S13, 0x242070db); /* 3회*/
	ff(&b, c, d, a, x[ 3], S14, 0xc1bdceee); /* 4회*/
	ff(&a, b, c, d, x[ 4], S11, 0xf57c0faf); /* 5회*/
	ff(&d, a, b, c, x[ 5], S12, 0x4787c62a); /* 6회*/
	ff(&c, d, a, b, x[ 6], S13, 0xa8304613); /* 7회*/
	ff(&b, c, d, a, x[ 7], S14, 0xfd469501); /* 8회*/
	ff(&a, b, c, d, x[ 8], S11, 0x698098d8); /* 9회*/
	ff(&d, a, b, c, x[ 9], S12, 0x8b44f7af); /* 10회 */
	ff(&c, d, a, b, x[10], S13, 0xffff5bb1); /* 11회 */
	ff(&b, c, d, a, x[11], S14, 0x895cd7be); /* 12회 */
	ff(&a, b, c, d, x[12], S11, 0x6b901122); /* 13회 */
	ff(&d, a, b, c, x[13], S12, 0xfd987193); /* 14회 */
	ff(&c, d, a, b, x[14], S13, 0xa679438e); /* 15회 */
	ff(&b, c, d, a, x[15], S14, 0x49b40821); /* 16회 */

    /*Round 2*/
    gg(&a, b, c, d, x[ 1], S21, 0xf61e2562); /* 17회 */
	gg(&d, a, b, c, x[ 6], S22, 0xc040b340); /* 18회 */
	gg(&c, d, a, b, x[11], S23, 0x265e5a51); /* 19회 */
	gg(&b, c, d, a, x[ 0], S24, 0xe9b6c7aa); /* 20회 */
	gg(&a, b, c, d, x[ 5], S21, 0xd62f105d); /* 21회 */
	gg(&d, a, b, c, x[10], S22,  0x2441453); /* 22회 */
	gg(&c, d, a, b, x[15], S23, 0xd8a1e681); /* 23회 */
	gg(&b, c, d, a, x[ 4], S24, 0xe7d3fbc8); /* 24회 */
	gg(&a, b, c, d, x[ 9], S21, 0x21e1cde6); /* 25회 */
	gg(&d, a, b, c, x[14], S22, 0xc33707d6); /* 26회 */
	gg(&c, d, a, b, x[ 3], S23, 0xf4d50d87); /* 27회 */
	gg(&b, c, d, a, x[ 8], S24, 0x455a14ed); /* 28회 */
	gg(&a, b, c, d, x[13], S21, 0xa9e3e905); /* 29회 */
	gg(&d, a, b, c, x[ 2], S22, 0xfcefa3f8); /* 30회 */
	gg(&c, d, a, b, x[ 7], S23, 0x676f02d9); /* 31회 */
	gg(&b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32회 */

    /*Round 3*/
	hh(&a, b, c, d, x[ 5], S31, 0xfffa3942); /* 33 */
	hh(&d, a, b, c, x[ 8], S32, 0x8771f681); /* 34 */
	hh(&c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
	hh(&b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
	hh(&a, b, c, d, x[ 1], S31, 0xa4beea44); /* 37 */
	hh(&d, a, b, c, x[ 4], S32, 0x4bdecfa9); /* 38 */
	hh(&c, d, a, b, x[ 7], S33, 0xf6bb4b60); /* 39 */
	hh(&b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
	hh(&a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
	hh(&d, a, b, c, x[ 0], S32, 0xeaa127fa); /* 42 */
	hh(&c, d, a, b, x[ 3], S33, 0xd4ef3085); /* 43 */
	hh(&b, c, d, a, x[ 6], S34,  0x4881d05); /* 44 */
	hh(&a, b, c, d, x[ 9], S31, 0xd9d4d039); /* 45 */
	hh(&d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
	hh(&c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
	hh(&b, c, d, a, x[ 2], S34, 0xc4ac5665); /* 48 */
	
	/*Round 4*/
	ii(&a, b, c, d, x[ 0], S41, 0xf4292244); /* 49 */
	ii(&d, a, b, c, x[ 7], S42, 0x432aff97); /* 50 */
	ii(&c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
	ii(&b, c, d, a, x[ 5], S44, 0xfc93a039); /* 52 */
	ii(&a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
	ii(&d, a, b, c, x[ 3], S42, 0x8f0ccc92); /* 54 */
	ii(&c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
	ii(&b, c, d, a, x[ 1], S44, 0x85845dd1); /* 56 */
	ii(&a, b, c, d, x[ 8], S41, 0x6fa87e4f); /* 57 */
	ii(&d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
	ii(&c, d, a, b, x[ 6], S43, 0xa3014314); /* 59 */
	ii(&b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
	ii(&a, b, c, d, x[ 4], S41, 0xf7537e82); /* 61 */
	ii(&d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
	ii(&c, d, a, b, x[ 2], S43, 0x2ad7d2bb); /* 63 */
	ii(&b, c, d, a, x[ 9], S44, 0xeb86d391); /* HASH_BLOCK */

    init_reg[0] += a;
    init_reg[1] += b;
    init_reg[2] += c;
    init_reg[3] += d;
    
    make_bit_128(digest, init_reg[0], init_reg[1], init_reg[2], init_reg[3]);
}

void make_bit_128(byte in[16],uint a, uint b, uint c, uint d) { //little-endian 으로 다루었으므로 그대로저장
    int i;

	for(i=0;i<16;i++)
	{
		if(i < 4)
			in[i] = ((a & ((uint)0x000000FF << (i*8))) >> (i*8));
		else if(i < 8)
			in[i] = ((b & ((uint)0x000000FF << ((i%4)*8))) >> ((i%4)*8));
		else if(i < 12)
			in[i] = ((c & ((uint)0x000000Ff << ((i%4)*8))) >> ((i%4)*8));
		else
			in[i] = ((d & ((uint)0x000000FF << ((i%4)*8))) >> ((i%4)*8));
	}
}

void md_5(FILE *fptr, byte *result) {
    int i, size = 0;
    byte msg[HASH_BLOCK * 2] = { 0 };//추가될수도 있으므로 두개의 블록을 할당한다.
    uint64 f_size = 0;

    md_5_init();

    while((size = fread(msg, sizeof(byte), HASH_BLOCK, fptr))) {
        f_size += size;

        if(size < HASH_BLOCK) {
            padding(msg, f_size);
        }

        md_5_digest(msg);
        if(isAddpad) md_5_digest(msg+HASH_BLOCK);//블록이 추가되었다면 추가된 블록도 작업 수행
        memset(msg, 0, HASH_BLOCK * 2);//다음 해쉬를 위해 메모리 초기화
    }
    for(i = 0; i < HASH_DATA; i++) {
        result[i] = digest[i];//해쉬 결과 값 저장
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

    md_5(fp, result);

    for(i = 0; i < HASH_DATA; i++) {
        printf("%3X", result[i]);
    }
    printf("\n");
    fclose(fp);
    return 0;
}