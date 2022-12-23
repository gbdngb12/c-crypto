#include "rsa_std.c"
#include "md-5.c"

#define  HASH_LEN 34

// 서명과 검증에 사용되는 버퍼(이진(binary) 형태)
static short  s[m];				// 서명 값
static short  h[HASH_LEN*8];		// 해쉬 값(서명)
static short  v_h[m];				// 해쉬 값(검증)
static short  ps[LEN_PS*8];		// 패딩 스트링

// 서명과 검증에 사용되는 버퍼(Radix와 octet 형태)
static int64 S[mb];				// 서명 값(서명)
static int64 V_S[mb];				// 서명 값(검증)
static int64 H[mb];				// 해쉬 값(Radix)
static int64 HDATA[HASH_LEN];		// 해쉬 값(octet - 서명)
static int64 SB[mb*4];				// 서명 블록(8 bit - 서명)
static int64 SB1[mb];				// 서명 블록(16 bit)
static int64 V_SB[mb*4];			// 서명 블록(8 bit - 검증)
static int64 V_HDATA[HASH_LEN];	// 해쉬 값(octet - 검증)		
static int64 O_PS[LEN_PS*8];		// 패딩 스트링(octet)


// MD5를 나타내는 식별 값
unsigned char md5_num[18] = {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86,
						 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10};


void rsa_signature();//RSA 서명 함수
void rsa_verification(); //RSA 서명 검증 함수
int  get_from_file(FILE* fptr, short *a, short mn);				// 파일로부터 데이터를 읽어 이진형태로 저장하는 함수
void put_to_file(FILE* fptr, short *a, short mn);				// 이진 데이터를 바이트 형태로 변환하여 파일에 저장하는 함수
void put_to_message(unsigned char* msg, short *a, short mn);	// 이진 데이터를 바이트 형태로 변환하여 메시지 버퍼에 저장하는 함수

int main() {
    int select;

    printf("1. RSA 서명 2. RSA 서명 검증 \n");
    scanf("%d", &select);

    if(select == 1) {
        rsa_signature();
    } else if(select == 2) {
        rsa_verification();
    } else {
        printf("Invalid Input\n");
    }
}

//RSA 서명 함수
void rsa_signature() {
    int i, j, cnt;
    byte hash_text[HASH_LEN] = { 0 };
    char file_name[32] = { 0 }, s_file_name[32] = { 0 };
    FILE *fptr;

    //서명에 사용할 비밀키 파일을 연다.
    if((fptr = fopen("secret_key.txt", "rb")) == NULL) {
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

    md_5(fptr,hash_text);//MD5 해쉬
    fclose(fptr);
    // MD5 식별 값을 해쉬 값에 이어서 추가한다.
    for(i = 0; i < 18; i++) {
        hash_text[i + 16 /*hash 16바이트값 이후로*/] = md5_num[18 - i - 1];
    }
    
    //해쉬 데이터를 이진 값으로 변환한다.
    cnt = HASH_LEN*8 - 1;
    for(i = 0; i < HASH_LEN; i++) {
        for(j = 0; j < 8; j++) {
            h[cnt] = (hash_text[i] >> j) & 0x01;
            cnt--;
        }
    }

    convert_binary_to_oct(h, HDATA, HASH_LEN); //이진 데이터를 옥텟으로 변환

    //S = h(m)^d mod n(서명)
    //EMSA-PKCD #1-v.15 padding
    //[00|01|PS|00|T](T = 해쉬 알고리즘 식별값 | H)
    //PS는 0xff로 채워짐
    for(i = 0; i < mb * 4; i++) {
        SB[i] = 0xFF;
    }
    
    SB[mb*4 - 1] = 0x00;
    SB[mb*4 - 2] = 0x01;
    SB[HASH_LEN] = 0x00;

    for(i = HASH_LEN - 1; i>= 0; i--) {
        SB[i] = HDATA[i];
    }

    for(i = mb*4 - 1; i > 0; i -= 4) {
        SB1[i/4] = (SB[i]<<(DHEX-OCT)) + (SB[i-1]<<(OCT+OCT)) + (SB[i-2]<<OCT) + SB[i-3];
    }
	/* 패딩 과정 종료 */

    // C = h(m)^d mod n (m-bit)
    left_to_right_pow(SB1, D, S, N, mb); //최종 메시지에 서명을 한다.(개인키 암호화)

    convert_radix_to_binary(S, s, mb);//radix를 이진 데이터로 변환
    
    //서명을 저장할 파일 이름 설정 (예 : MONEY.txt -> MONEY.sgn)
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
//RSA 서명 검증 함수
void rsa_verification() { 
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


    //h(m) = S^e mod n
    convert_binary_to_radix(s, V_S, mb);//이진 데이터를 Radix로 변환
    
    left_to_right_pow(V_S, E, H, N, mb);// 서명 검증
    
    convert_radix_to_binary(H, v_h, mb);
    convert_binary_to_oct(v_h, V_SB, mb* 4);

    //패딩 부분을 제외하고 해쉬 데이터만 추출한다.
    for(i = HASH_LEN - 1; i >= 0; i--) {
        V_HDATA[i] = V_SB[i];
    }

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