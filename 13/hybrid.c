#include "hybrid.h"

void main()
{
	int select;

	// 동작 선택
	printf("* 1. 하이브리드 암호화		2. 하이브리드 복호화\n\n");
	printf("- 선택하시오 : ");
	scanf("%d", &select);

	// 선택에 따라 암호화와 복호화 수행
	if(select == 1)
		hybrid_encryption();		// 하이브리드 암호화
	else if(select == 2)
		hybrid_decryption();		// 하이브리드 복호화
	else
		printf("* 잘못 입력 하셨습니다!\n");
}

void hybrid_encryption()
{
	int i;
	byte p_text[AES_Nb*4] = {0,};
	byte c_text[AES_Nb*4] = {0,};
	byte key[B_S] = {0,}, c_key[B_S] = {0,};
	char f_name[64] = {0,}, f_name2[64] = {0,};
	FILE* fp, *fp2;

	// 암호화 할 파일명 입력
	printf("\n* 암호화 할 파일명을 입력하시오 : ");
	scanf("%s", f_name);

	// 파일 열기
	if((fp = fopen(f_name, "rb")) == NULL)
	{
		printf("* File open failed!\n");
		exit(1);
	}

	// X9.17로 세션키 생성
	des_x9_17_random_generator(key, "ansix917", "security", 16);

	// 암호화된 데이터를 저장할 파일의 이름 설정
	// 확장자를 .enc로 설정함
	for(i=0;;i++)
	{
		if(f_name[i] == '.')
		{
			f_name2[i] = '\0';
			strcat(f_name2, ".enc");
			break;
		}
		f_name2[i] = f_name[i];
	}

	// 암호문을 저장할 파일 열기
	if((fp2 = fopen(f_name2, "wb")) == NULL)
	{
		printf("* File open failed!\n");
		exit(1);
	}

	// 파일의 내용을 암호화 하여 파일로 저장
	while(fread(p_text, sizeof(byte), AES_Nb*4, fp) > 0)
	{
		aes_encrypt(p_text, c_text, key);
		fwrite(c_text, sizeof(byte), AES_Nb*4, fp2);

		memset(p_text, 0, AES_Nb*4);
		memset(c_text, 0, AES_Nb*4);
	}

	RSA_Enc(key, c_key);	// 세션키를 RSA로 암호화

	// 암호화된 파일의 끝에 암호화된 키를 저장
	fwrite(c_key, sizeof(byte), B_S, fp2);

	printf("* Hybrid encryption is completed!\n");

	fclose(fp);
	fclose(fp2);
}

void hybrid_decryption()
{
	int i;
	long n_read = 0, size = 0;
	byte c_text[AES_Nb*4] = {0,};
	byte d_text[AES_Nb*4] = {0,};
	byte key[AES_Nb*4] = {0,}, c_key[B_S] = {0,}, d_key[B_S] = {0,};
	char f_name[64] = {0,}, f_name2[64] = {0,};
	FILE* fp, *fp2;

	// 복호화 할 파일명 입력
	printf("\n* 복호화 할 파일명을 입력하시오 : ");
	scanf("%s", f_name);

	// 파일 열기
	if((fp = fopen(f_name, "rb")) == NULL)
	{
		printf("* File open failed!\n");
		exit(1);
	}

	// 암호화된 데이터를 저장할 파일의 이름 설정
	// 확장자를 .dec로 설정함
	for(i=0;;i++)
	{
		if(f_name[i] == '.')
		{
			f_name2[i] = '\0';
			strcat(f_name2, ".dec");
			break;
		}
		f_name2[i] = f_name[i];
	}

	// 복호문을 저장할 파일 열기
	if((fp2 = fopen(f_name2, "wb")) == NULL)
	{
		printf("* File open failed!\n");
		exit(1);
	}

	// 암호화된 키를 추출하기 위한 파일 포인터 이동
	fseek(fp, -128l, SEEK_END);

	// 암호화된 키 데이터를 읽어온다
	fread(c_key, sizeof(byte), B_S, fp);

	RSA_Dec(c_key, d_key);	// RSA로 세션키를 복호 한다

	strcpy((char*)key, (char*)d_key);

	size = ftell(fp) - 128l;
	fseek(fp, 0, SEEK_SET);

	// 세션키로 암호화된 파일을 복호화 하여 파일로 저장한다
	while((n_read += fread(c_text, sizeof(byte), AES_Nb*4, fp)) < size)
	{
		aes_decrypt(c_text, d_text, key);
		fwrite(d_text, sizeof(byte), AES_Nb*4, fp2);

		memset(c_text, 0, AES_Nb*4);
		memset(d_text, 0, AES_Nb*4);
	}

	printf("* Hybrid decryption is completed!\n");

	fclose(fp);
	fclose(fp2);
}