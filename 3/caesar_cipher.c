#include <stdio.h>
#include <string.h>

int main() {
    int i = 0, key = 0, str_size = 0;
    char str[50] = {0};
    printf("Input Plain Text / Cipher Text\n");
    gets(str);

    printf("Input key\n");
    //key의 범위 key <= |25|
    scanf("%d", &key);

    str_size = strlen(str);

    for(int i = 0; i < str_size; i++) {
        if((str[i] >= 'a') && (str[i] <= 'z')) { //소문자인 경우
            str[i] -= 'a';//표와 매핑 시킨다. a->0, b->1, ... , z->25 
            
            if(str[i] + key <  0) {
                str[i] += 26; //key와 현재 문자를 더했더니 음수인경우 모듈러 연산에 보정을 위해
            }

            str[i] = (str[i] + key) % 26;
            str[i] += 'a';
        }
        if((str[i] >= 'A') && (str[i] <= 'Z')) { //대문자인 경우
            str[i] -= 'A'; //표와 매핑 시킨다. A->0, B->0, ..., Z->25
            
            if(str[i] + key < 0) {
                str[i] += 26;//key와 현재 문자를 더했더니 음수인경우 모듈러 연산에 보정을 위해
            }
            
            str[i] = (str[i] + key) % 26;
            str[i] += 'A';
        }
    }

    printf("\n암호화 또는 복호화된 결과 출력\n");
    printf("%s\n", str);
}