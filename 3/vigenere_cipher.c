#include <stdio.h>
#include <string.h>

int main() {
    int i = 0 /*Plain text Index*/,
        j = 0 /*key stream Index*/,
        key_size = 0, str_size = 0, select = 1;
    char str[50] = {0}, key[16] = {0};

    printf("Input Cipher Text / Plain Text\n");
    scanf("%s", str);

    printf("Encrypt : 1, Decrypt : 2\n");
    scanf("%d", &select);
    printf("Input key(lower case)\n");
    scanf("%s", key);

    str_size = strlen(str);
    key_size = strlen(key);

    for (i = 0; i < str_size; i++) {
        j = i % key_size;  // 키 스트림 인덱스 계산

        if (select == 1) {  // 암호화
            if ((str[i] >= 'a') && (str[i] <= 'z')) { //소문자인경우
                // 알파벳을 숫자와 매핑 a->0, b->1, ... z->25
                str[i] -= 'a';
                key[j] -= 'a';
                
                if(str[i] + key[j] < 0) {
                    str[i] += 26; //모듈로값 보정
                } 
                
                str[i] = (str[i] + key[j]) % 26;
                // 숫자를 다시 알파벳으로 복구
                str[i] += 'a';
                key[j] += 'a';
            }
            if((str[i] >= 'A') && (str[i] <= 'Z')) {
                //알파벳을 숫자와 매핑 a->0, b->1, ... z->25
                str[i] -= 'A';
                key[j] -= 'a';

                if(str[i] + key[j] < 0) {
                    str[i] += 26; //모듈로 값 보정
                }

                str[i] = (str[i]+ key[j]) % 26;
                //숫자를 다시 알파벳으로 복구
                str[i] += 'A';
                key[j] += 'a';
            }
        } else if (select == 2) {  // 복호화
            if((str[i] >= 'a') && (str[i] <= 'z')) {
                str[i] -= 'a';
                key[j] -= 'a';

                if(str[i] - key[j] < 0) {
                    str[i] += 26;
                }

                str[i] = (str[i] - key[j]) % 26;
                str[i] += 'a';
                key[j] += 'a';
            }
            if((str[i] >= 'A') && (str[i] <= 'Z')) {
                str[i] -= 'A';
                key[j] -= 'a';

                if(str[i] - key[j] < 0) {
                    str[i] += 26;
                }

                str[i] = (str[i] - key[j]) % 26;
                str[i] += 'A';
                key[j] += 'a';
            }
        }
    }
    printf("\nEncrypt or Decrypt Data : \n");
    puts(str);
    return 0;
}