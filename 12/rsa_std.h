#pragma once
#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>

#define  DHEX 32
#define  m    1024			// 모듈러 n의 비트 수
#define  mp   512			// 비밀 소수 p의 비트 수
#define  mq   512			// 비밀 소수 q의 비트 수
#define  mb   m/DHEX
#define  rdx  0x100000000
#define  OCT  8
/* 타입 정의 */
typedef unsigned int ULINT; //4
typedef unsigned long INT64;//8
typedef unsigned int INT32;//4

/********************************************************************/
/***********   Function name :  CONV_B_to_R (a,B,mn)       **********/
/***********   Description   :  convert bin. into radix    **********/
/********************************************************************/
static INT64 mask[DHEX]={0x80000000, 0x40000000, 0x20000000, 0x10000000,0x8000000,
				  0x4000000,0x2000000, 0x1000000, 0x800000,0x400000, 0x200000,
				  0x100000, 0x080000,0x040000, 0x020000, 0x010000,
				  0x8000, 0x4000, 0x2000, 0x1000,0x800,
				  0x400,0x200, 0x100, 0x80,0x40, 0x20,
				  0x10, 0x08,0x04, 0x02, 0x01
				 };
static INT64  o_mask[8] = { 0x80,0x40, 0x20, 0x10, 0x08,0x04, 0x02, 0x01};

/* 전역 변수 */
static INT32  LAND=0xFFFFFFFF;
void CONV_B_to_R (short *A,INT64 *B,short mn);

/********************************************************************/
/***********   Function name :  CONV_R_to_B (A,b,mn)       **********/
/***********   Description   :  convert radix into bin.    **********/
/********************************************************************/
void CONV_R_to_B (INT64 *A,short *B,short mn);

/********************************************************************/
/***********   Function name :  rand_g (a,n)               **********/
/***********   Description   : n-bits random               **********/
/***********                   number generator.           **********/
/********************************************************************/
void rand_g(short *out,short n);

/********************************************************************/
/*****     Function name : Modular(C, N mn)                     *****/
/*****     Description   : C = C mod N                          *****/
/********************************************************************/
void Modular (INT64 *X, INT64 *N, short mn);

/********************************************************************/
/*****     Function name : Conv_mma(A,B,C,N,mn) (Conventional)  *****/
/*****     Description   : C= A*B mod N                         *****/
/********************************************************************/
void Conv_mma (INT64 *A,INT64 *B,INT64 *C,INT64 *N, short mn);

/********************************************************************/
/***********   Function name :  CONV_B_to_O (a,B,mn)       **********/
/***********   Description   :  convert bin. into octet    **********/
/********************************************************************/


void CONV_B_to_O (short *A,INT64 *B, short mn);

/********************************************************************/
/***********   Function name :  CONV_O_to_B (A,b,mn)       **********/
/***********   Description   :  convert octet into bin.    **********/
/********************************************************************/
void CONV_O_to_B (INT64 *A,short *B,short mn);

/********************************************************************/
/*****     Function name : WM_Left_Pow(A,E,C,N,mn)              *****/
/*****     Description   : C= A^E mod N                         *****/
/********************************************************************/
void LeftTORight_Pow(INT64 *A, INT64 *E, INT64 *C, INT64 *N, short mn);