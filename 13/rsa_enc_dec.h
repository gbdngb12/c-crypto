#pragma once

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

/* 상수 정의 */
#define m 1024  // 모듈러 n의 비트 수
#define mp 512  // 비밀 소수 p의 비트 수
#define mq 512  // 비밀 소수 q의 비트 수
#define HASH 128
#define LEN_PS 8  // 패딩 스트링의 비트수
#define DHEX 32
#define OCT 8
#define Char_NUM 8                   // char 비트수
#define B_S m / Char_NUM             // 1024/ 8 => 128
#define DATA_LEN (B_S - LEN_PS - 3)  // 평문 블록 길이
#define mb m / DHEX                  // 32
#define hmb mb / 2                   // 16
#define mpb mp / DHEX                // 16
#define mqb mq / DHEX                // 16
#define E_LENGTH 16

#define rdx 0x100000000

// 타입 정의
typedef unsigned int ulint;
typedef unsigned long int64;
typedef unsigned int int32;
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

/* 전역 변수 */
static int32 LAND = 0xFFFFFFFF;

// 공개키 파라미터
static int64 N[mb];  // 모듈러 n (= p * q)
static int64 E[mb];  // 공개키 e
static int64 D[mb];  // 비밀키 d

/********************************************************************/
/***********   Function name :  convert_binary_to_radix (a,B,mn)       **********/
/***********   Description   :  convert bin. into radix    **********/
/********************************************************************/
static int64 mask[DHEX] = {0x80000000, 0x40000000, 0x20000000, 0x10000000, 0x8000000,
                           0x4000000, 0x2000000, 0x1000000, 0x800000, 0x400000, 0x200000,
                           0x100000, 0x080000, 0x040000, 0x020000, 0x010000,
                           0x8000, 0x4000, 0x2000, 0x1000, 0x800,
                           0x400, 0x200, 0x100, 0x80, 0x40, 0x20,
                           0x10, 0x08, 0x04, 0x02, 0x01};
static int64 o_mask[8] = {0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01};

// RSA 암호화 함수
void rsa_encryption(unsigned char* plain_text, unsigned char* result);
// RSA 복호화 함수
void rsa_decryption(unsigned char* cipher_text, unsigned char* result);
// 메시지 버퍼에서 데이터를 읽어서 이진 형태로 저장하는 함수
int get_from_message(unsigned char* msg, short* a, short mn);
// 이진 형태의 데이터를 메시지 버퍼에 저장하는 함수
void put_to_message(unsigned char* msg, short* a, short mn);

// rsa의 연산과 관련된 함수들
static void convert_oct_to_binary(int64 *A, short *B, short mn);                  // octet을 binary로 변환하는 함수
static void convert_binary_to_oct(short *A, int64 *B, short mn);                  // binary를 octet로 변환하는 함수
static void convert_radix_to_binary(int64 *A, short *B, short mn);                // Radix를 binary로 변환하는 함수
static void convert_binary_to_radix(short *A, int64 *B, short mn);                // binary를 Radix로 변환하는 함수
static void rand_generator(short *out, short n);                                  // 랜덤 수를 생성하는 함수
static void modular(int64 *X, int64 *N, short mn);                                // 모듈러 연산을 수행하는 함수
static void convert_mma(int64 *A, int64 *B, int64 *C, int64 *N, short mn);        // 고전적인 모듈러 감소 연산을 수행하는 함수
static void left_to_right_pow(int64 *A, int64 *E, int64 *C, int64 *N, short mn);  // Left to Right 멱승을 수행하는 함수

