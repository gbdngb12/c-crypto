#include "rsa_verify.h"
#include "md-5.h"

int main(int argc, char* argv[])
{
	int select;

	// 서명과 서명 검증 선택
	printf("* 1. RSA 서명	2. RSA 서명 검증\n");
	printf("- 선택하시오 : ");
	scanf("%d", &select);

	// 선택한 항목 실행
	if(select == 1)
		RSA_Signature();
	else if(select == 2)
		RSA_Verification();
	else
		printf("* 잘못 입력 하셨습니다!\n");
}

void RSA_Signature()
{
	int i, j, cnt;
	byte hash_text[HASH_LEN] = {0,};
	char file_name[32] = {0,}, s_file_name[32] = {0,};
	FILE* fptr;

	// 서명에 사용할 비밀키 파일을 연다
	if((fptr = fopen("secret_key.txt", "rb")) == NULL)
	{
		printf("file open failed!!\n");
		exit(1);
	}
	
	// 파일로부터 비밀키 d와 모듈러 n을 저장한다
    for(i=mb-1;i>=0;i--)  fscanf(fptr,"%I64x ",&N[i]);
    for(i=mb-1;i>=0;i--)  fscanf(fptr,"%I64x ",&D[i]);

    fclose(fptr);

	// 서명할 파일명 입력
	printf("* 서명할 파일명을 입력하시오 : ");
	scanf("%s", file_name);

	// 파일 열기
	if((fptr = fopen(file_name, "rb")) == NULL)
	{
		printf("File open failed!\n");
		exit(1);
	}

	md_5(fptr, hash_text);	// MD5 해쉬 

	fclose(fptr);

	// MD5 식별 값을 해쉬 값에 이어서 추가한다
	for(i=0;i<18;i++)
		hash_text[i+16] = md5_num[18-i-1];

	// 해쉬 데이터를 이진 값으로 변환한다
	cnt=HASH_LEN*8-1;
	for(i=0;i<HASH_LEN;i++) {
		for(j=0;j<8;j++) {
			h[cnt] = (hash_text[i]>>j) & 0x01;
			cnt--;
		}
	}

	CONV_B_to_O(h, HDATA, HASH_LEN);	// 이진 데이터를 옥텟으로 변환

	/****************************************************************/
	/******       Compute   S =  h(m)^d  mod n                  *****/
	/****************************************************************/

	/* EMSA-PKCS #1-v1.5 패딩 */
	// [00|01|PS|00|T] (T = 해쉬 알고리즘 식별 값 + 해쉬 값)
	for(i=0;i<mb*4;i++)
		SB[i] = 0xFF;

	SB[mb*4-1] = 0x00;
	SB[mb*4-2] = 0x01;
	SB[HASH_LEN]=0x00;
	
	for(i=HASH_LEN-1;i>=0;i--)
		SB[i] = HDATA[i];
	
	for(i=mb*4-1;i>0;i=i-4)
		SB1[i/4] = (SB[i]<<(DHEX-OCT)) + (SB[i-1]<<(OCT+OCT)) + (SB[i-2]<<OCT) + SB[i-3];
	/* 패딩 과정 종료 */
	
	/*** c = h(m)^d mod n (m-bit) ***/
	LeftTORight_Pow(SB1, D, S, N, mb);		// 최종 메시지에 서명을 한다
	
	CONV_R_to_B (S, s, mb);		// Radix를 이진 데이터로 변환

	// 서명을 저장할 파일 이름 설정 (예 : MONEY.txt -> MONEY.sgn)
	for(i=0;;i++)
	{
		if(file_name[i] == '.')
		{
			s_file_name[i] = '\0';
			strcat(s_file_name, ".sgn");
			break;
		}
		
		s_file_name[i] = file_name[i];
	}

	// 서명 데이터를 저장할 파일 열기
	if((fptr = fopen(s_file_name, "wb")) == NULL)
	{
		printf("File open failed!\n");
		exit(1);
	}

	put_to_file(fptr, s, m/Char_NUM);	// 서명 데이터를 파일로 저장

	printf("\n* The Signature is completed.\n\n");
	fclose(fptr);
}

void RSA_Verification()
{
	int i;
	byte v_text[HASH_LEN] = {0,};
	byte hash_text[16] = {0,};
	char file_name[32] = {0,}, s_file_name[32] = {0,};
	FILE* fptr;

	// 서명자의 공개키 파일 열기
	if((fptr = fopen("public_key.txt", "rb")) == NULL)
	{
		printf("file open failed!!\n");
		exit(1);
	}

	// 파일로부터 공개키 e와 모듈러 n을 저장한다
    for(i=mb-1;i>=0;i--)  fscanf(fptr,"%I64x ",&N[i]);
    for(i=mb-1;i>=0;i--)  fscanf(fptr,"%I64x ",&E[i]);
    
    fclose(fptr);

	// 검증할 파일명 입력
	printf("* 검증할 파일명을 입력하시오 : ");
	scanf("%s", file_name);

	// 파일 열기
	if((fptr = fopen(file_name, "rb")) == NULL)
	{
		printf("File open failed!\n");
		exit(1);
	}

	md_5(fptr, hash_text);		// MD5 해쉬

	fclose(fptr);

	// 서명 파일명 입력
	printf("* 서명 파일명을 입력하시오(.sgn) : ");
	scanf("%s", file_name);

	// 서명 파일 열기
	if((fptr = fopen(file_name, "rb")) == NULL)
	{
		printf("File open failed!\n");
		exit(1);
	}

	get_from_file(fptr, s, m/Char_NUM);		// 파일로부터 서명 데이터를 읽어온다

	/****************************************************************/
	/********            Compute   h(m) =  S^e  mod n         *******/
	/****************************************************************/

	CONV_B_to_R(s, V_S, mb);	// 이진 데이터를 Radix로 변환

	LeftTORight_Pow(V_S, E, H, N, mb);		// 서명 검증
	
	// 데이터 변환 ( Radix -> Binary -> Octet)
	CONV_R_to_B(H, v_h, mb);
	CONV_B_to_O(v_h, V_SB, mb*4);
	
	// 패딩 부분을 제외하고 해쉬 데이터만 추출한다
	for(i=HASH_LEN-1;i>=0;i--)
		V_HDATA[i] = V_SB[i];

	// MD5 식별 값을 제외하고 해쉬 값만 비교하여
	// 검증의 성공 여부를 확인한다
	for(i=0;i<16;i++)
	{
		if(V_HDATA[i] != hash_text[i])
		{
			printf("The Verification is failed!\n");
			return;
		}
	}

	printf("\n* The Verification is completed!\n");
	fclose(fptr);
}

// 파일로부터 데이터를 읽어와 이진 형태로 저장
int get_from_file(FILE* fptr, short *a, short mn)
{
	int i,j;
	short flag=1, cnt=0,mm;
	unsigned char b[m/Char_NUM]={0,};

	mm = mn*Char_NUM;

	for(i=0; i< mm ;i++)
		a[i]=0;

	// 파일에서 한 바이트씩 읽는다
	for(i=0; i< mn ;i++)
	{
		if(fscanf(fptr,"%c",&b[i])==EOF)
		{
			if(i==0)
			{
				flag=-1;
				return(flag);
			}

			flag=0;

			for( ; i<mn ;i++)
				b[i] = '\0';

			break;
		}
	}

	cnt=0;
	// 바이트 단위의 데이터를 이진 형태로 변환
	for (i=mn-1;i>=0;i--)
	{
		for(j=0;j<Char_NUM;j++)
		{
			a[cnt++] =  (b[i]>>j) & 0x01;
		}
	}

	return(flag);
}

// 이진 형태의 데이터를 바이트 단위로 변환하여 파일로 저장
void put_to_file(FILE* fptr, short *a, short mn)
{
	int i,j;
	short cnt=0, mm;
	unsigned char b[m/Char_NUM]={0,};
	unsigned char mask[Char_NUM] = {0x01,0x02,0x04,0x08,
								    0x10,0x20,0x40,0x80};

	mm=mn*Char_NUM;
	cnt=0;
	// 이진 형태의 데이터를 바이트 형태로 변환한다
	for(i=mn-1;i>=0;i--) {
		b[i]=0x00;
		for(j=0;j<Char_NUM;j++)  {
			b[i] = b[i] + a[cnt++] * mask[j];
		}
	}
	// 변환한 데이터를 메시지 버퍼에 저장한다
	for(i=0;i<mn;i++)
		fprintf(fptr, "%c", b[i]);
}

// 이진 형태의 데이터를 바이트 단위로 변환하여 저장
void put_to_message(unsigned char* msg, short *a, short mn)
{
	register i,j;
	short cnt=0, mm;
	unsigned char b[m/Char_NUM]={0,};
	unsigned char mask[Char_NUM] = {0x01,0x02,0x04,0x08,
								    0x10,0x20,0x40,0x80};

	mm=mn*Char_NUM;
	cnt=0;
	// 이진 형태의 데이터를 바이트 형태로 변환한다
	for(i=mn-1;i>=0;i--) {
		b[i]=0x00;
		for(j=0;j<Char_NUM;j++)  {
			b[i] = b[i] + a[cnt++] * mask[j];
		}
	}
	// 변환한 데이터를 메시지 버퍼에 저장한다
	for (i=mn-1;i>=0;i--)
		msg[i] = b[i];
}