#pragma once
#include   <stdio.h>
#include   <stdlib.h>
#include   <string.h>
#include "rsa_std.h"

#define  LEN_PS 91			// 패딩 스트링의 크기
#define  DATA_LEN 53
#define  HASH_LEN 34
#define  Char_NUM 8
#define  B_S  64   
#define  hmb  mb/2
#define  mpb  mp/DHEX
#define  mqb  mq/DHEX

void RSA_Signature();		// RSA 서명 함수
void RSA_Verification();	// RSA 서명 검증 함수
int  get_from_file(FILE* fptr, short *a, short mn);				// 파일로부터 데이터를 읽어 이진형태로 저장하는 함수
void put_to_file(FILE* fptr, short *a, short mn);				// 이진 데이터를 바이트 형태로 변환하여 파일에 저장하는 함수
void put_to_message(unsigned char* msg, short *a, short mn);	// 이진 데이터를 바이트 형태로 변환하여 메시지 버퍼에 저장하는 함수


// 공개키 파라미터
static INT64 N[mb];		// 모듈러 n (= p * q)
static INT64 E[mb];		// 공개키 e
static INT64 D[mb];		// 비밀키 d

// 서명과 검증에 사용되는 버퍼(이진(binary) 형태)
static short  s[m];				// 서명 값
static short  h[HASH_LEN*8];		// 해쉬 값(서명)
static short  v_h[m];				// 해쉬 값(검증)
static short  ps[LEN_PS*8];		// 패딩 스트링

// 서명과 검증에 사용되는 버퍼(Radix와 octet 형태)
static INT64 S[mb];				// 서명 값(서명)
static INT64 V_S[mb];				// 서명 값(검증)
static INT64 H[mb];				// 해쉬 값(Radix)
static INT64 HDATA[HASH_LEN];		// 해쉬 값(octet - 서명)
static INT64 SB[mb*4];				// 서명 블록(8 bit - 서명)
static INT64 SB1[mb];				// 서명 블록(16 bit)
static INT64 V_SB[mb*4];			// 서명 블록(8 bit - 검증)
static INT64 V_HDATA[HASH_LEN];	// 해쉬 값(octet - 검증)		
static INT64 O_PS[LEN_PS*8];		// 패딩 스트링(octet)

// MD5를 나타내는 식별 값
static unsigned char md5_num[18] = {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86,
						 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10};
