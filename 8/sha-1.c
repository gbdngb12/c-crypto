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
void sha_1_init();
void sha_1_digest(byte *in);
void make_bit_160(uint a,uint b,uint c,uint d,uint e);

#define byte_to_word(a,b,c,d) ( ((a << 24) + (b << 16) + (c << 8) + d) )
#define circular_shift(x,n) ( ((x) << n) | ((x) >> (32-n)) )			

#define F1(b,c,d) ( ((b)&(c)) | ((~b)&(d)) )
#define F2(b,c,d) ( ((b) ^ (c) ^ (d)) )
#define F3(b,c,d) ( ((b)&(c)) | ((b)&(d)) | ((c)&(d)) )

#define H0 0x67452301
#define H1 0xefcdab89
#define H2 0x98badcfe
#define H3 0x10325476
#define H4 0xc3d2e1f0

#define K0 0x5a827999
#define K1 0x6ed9eba1
#define K2 0x8f1bbcdc
#define K3 0xca62c1d6

void padding(byte *in, uint64 msg_len) {
    int i;
    byte *ptr = (byte *)&msg_len;

    if(msg_len % HASH_BLOCK < 56) {
        in[msg_len % HASH_BLOCK] = 0x80;
        msg_len *= 8;

        for(i = 0; i < 8; i++) {
            in[HASH_BLOCK -i - 1] = *(ptr + i);//msg_len값을 big-endian으로 처리함
        }
    } else {
        in[msg_len % HASH_BLOCK] = 0x80;
        msg_len *= 8;
        isAddpad = 1;
        for(i = 0; i < 8; i++) {
            in[HASH_BLOCK*2 - i - 1] = *(ptr + i);
        }
    }
}

void sha_1_init() {
    init_reg[0] = H0;
    init_reg[1] = H1;
    init_reg[2] = H2;
    init_reg[3] = H3;
    init_reg[4] = H4;
}

void sha_1_digest(byte *in) {
    int i;
    uint m[16] = { 0 };//512bit -> 16byte Message
    uint w[80] = { 0 };
    uint reg[5];

    reg[0] = init_reg[0]; reg[1] = init_reg[1]; reg[2] = init_reg[2]; 
    reg[3] = init_reg[3]; reg[4] = init_reg[4]; 

    for(i = 0; i < 64; i += 4) {
        m[i / 4] = byte_to_word(in[i], in[i + 1], in[i + 2], in[i + 3]);
    }

    for(i = 0; i < 80; i++) {
        if(i < 16) { //w0 ~ w15 까지는 word m값 그대로 이용
            w[i] = m[i];
        } else { //w1 ~ w79는 공식 이용
            w[i] = circular_shift(w[i - 16] ^ w[i - 14] ^ w[i - 8] ^ w[i - 3], 1);
        }
    }

    for(i = 0; i < 80; i++) {
        uint temp;
        //Round 1
        if(i < 20) {
            temp = circular_shift(reg[0], 5)/*CLS5(A)*/ + reg[4]/*E*/
             + F1(reg[1]/*B*/,reg[2]/*C*/,reg[3]/*D*/)+w[i]/*w*/+K0/*k0*/;
            reg[4] = reg[3];//E<-D
            reg[3] = reg[2];//D<-C
            reg[2] = circular_shift(reg[1], 30);//C<-CLS30(B)
            reg[1] = reg[0];//B<-A
            reg[0] = temp;//A값 대입
        } else if(i < 40) { //Round 2
            temp = circular_shift(reg[0], 5)/*CLS5(A)*/ + reg[4]/*E*/
             + F2(reg[1]/*B*/,reg[2]/*C*/,reg[3]/*D*/)+w[i]/*w*/+K1/*k1*/;
            reg[4] = reg[3];//E<-D
            reg[3] = reg[2];//D<-C
            reg[2] = circular_shift(reg[1], 30);//C<-CLS30(B)
            reg[1] = reg[0];//B<-A
            reg[0] = temp;//A값 대입
        } else if(i < 60) { //Round 3
            temp = circular_shift(reg[0], 5)/*CLS5(A)*/ + reg[4]/*E*/
             + F3(reg[1]/*B*/,reg[2]/*C*/,reg[3]/*D*/)+w[i]/*w*/+K2/*k*/;
            reg[4] = reg[3];//E<-D
            reg[3] = reg[2];//D<-C
            reg[2] = circular_shift(reg[1], 30);//C<-CLS30(B)
            reg[1] = reg[0];//B<-A
            reg[0] = temp;//A값 대입
        } else { // ROund 4
            temp = circular_shift(reg[0], 5)/*CLS5(A)*/ + reg[4]/*E*/
             + F2(reg[1]/*B*/,reg[2]/*C*/,reg[3]/*D*/)+w[i]/*w*/+K3/*k*/;
            reg[4] = reg[3];//E<-D
            reg[3] = reg[2];//D<-C
            reg[2] = circular_shift(reg[1], 30);//C<-CLS30(B)
            reg[1] = reg[0];//B<-A
            reg[0] = temp;//A값 대입
        }
    }

    init_reg[0] += reg[0];
    init_reg[1] += reg[1];
    init_reg[2] += reg[2];
    init_reg[3] += reg[3];
    init_reg[4] += reg[4];

    make_bit_160(init_reg[0], init_reg[1], init_reg[2], init_reg[3],init_reg[4]);
}

void make_bit_160(uint a,uint b,uint c,uint d,uint e) {//big-endian으로 다루었으므로 반대로 저장
int i;
	byte* p;

	for(i=0;i<20;i++)
	{
		if(i < 4)
		{
			p = (byte*)&a;
			digest[i] = p[3-i];
		}
		else if(i < 8)
		{
			p = (byte*)&b;
			digest[i] = p[7-i];
		}
		else if(i < 12)
		{
			p = (byte*)&c;
			digest[i] = p[11-i];
		}
		else if(i < 16)
		{
			p = (byte*)&d;
			digest[i] = p[15-i];
		}
		else
		{
			p = (byte*)&e;
			digest[i] = p[19-i];
		}
	}
}

void sha_1(FILE *fptr, byte *result) {
    int i, size = 0;
    byte msg[HASH_BLOCK * 2] = { 0 };
    uint64 f_size = 0;
    sha_1_init();

    while((size = fread(msg, sizeof(byte),HASH_BLOCK, fptr))) {
        f_size += size;

        if(size < HASH_BLOCK) {
            padding(msg, f_size);
        }

        sha_1_digest(msg);

        if(isAddpad) {
            sha_1_digest(msg + HASH_BLOCK);
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

    sha_1(fp, result);

    for(i = 0; i < HASH_DATA; i++) {
        printf("%3X", result[i]);
    }

    printf("\n");
    fclose(fp);
    return 0;
}