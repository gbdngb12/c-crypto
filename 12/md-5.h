#pragma once
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
#define byte_to_word(a,b,c,d) ( ((a << 24) + (b << 16) + (c << 8) + d) )
#define circular_shift(X,n) ( ((X) << n) | ((X) >> (32-n)) )			

void padding(byte *in, uint64 msg_len);
void md_5_init();
void md_5_digest(byte *in);
void md_5(FILE *fptr, byte *result);
void make_bit_128(byte in[16],uint a, uint b, uint c, uint d);//word단위 해쉬 값을 byte단위로 변환 하는 함수
void ff(uint* a,uint b, uint c, uint d, uint _m, int s, uint t);
void gg(uint* a,uint b, uint c, uint d, uint _m, int s, uint t);
void hh(uint* a,uint b, uint c, uint d, uint _m, int s, uint t);
void ii(uint* a,uint b, uint c, uint d, uint _m, int s, uint t);
void padding(byte *in, uint64 msg_len);
void md_5_init();

// little endian 컴퓨터 이므로 순서를 정확히 지켜야함

void md_5_digest(byte *in);
void make_bit_128(byte in[16],uint a, uint b, uint c, uint d);

void md_5(FILE *fptr, byte *result);