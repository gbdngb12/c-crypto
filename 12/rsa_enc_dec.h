#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rsa_std.h"

#define LEN_PS 8  // 패딩 스트링의 크기
#define Char_NUM 8
#define B_S m / Char_NUM
#define DATA_LEN (B_S - LEN_PS - 3)  // 평문 블록 길이
#define hmb mb / 2
#define mpb mp / DHEX
#define mqb mq / DHEX
#define E_LENGTH 16

void RSA_Enc(unsigned char* p_text, unsigned char* result);    // RSA 암호화 함수
void RSA_Dec(unsigned char* c_text, unsigned char* result);    // RSA 복호화 함수
static int get_from_message(unsigned char* msg, short* a, short mn);  // 메시지 버퍼에서 데이터를 읽어서 이진 형태로 저장하는 함수
static void put_to_message(unsigned char* msg, short* a, short mn);   // 이진 형태의 데이터를 메시지 버퍼에 저장하는 함수

// 공개키 파라미터
static INT64 N[mb];  // 모듈러 n (= p * q)
static INT64 E[mb];  // 공개키 e
static INT64 D[mb];  // 비밀키 d

// 서명과 검증에 사용되는 버퍼(이진(binary) 형태)
static short s[m];               // 암호문(암호)
static short h[DATA_LEN * 8];    // 평문
static short v_h[m];             // 복호문(패딩 포함)
static short d_d[DATA_LEN * 8];  // 복호문(패딩 제외)
static short ps[LEN_PS * 8];     // 패딩 스트링

// 암호와 복호에 사용되는 버퍼(Radix와 octet 형태)
static INT64 S[mb];             // 암호문
static INT64 H[mb];             // 복호문(Radix)
static INT64 DATA[DATA_LEN];    // 평문(octet)
static INT64 EB[mb * 4];        // 암호문 블록(8 bit)
static INT64 EB1[mb];           // 암호문 블록(16 bit)
static INT64 D_EB[mb * 4];      // 복호문 블록(8 bit)
static INT64 D_DATA[DATA_LEN];  // 복호 데이터(octet)
static INT64 O_PS[OCT];         // 패딩 스트링(octet)
