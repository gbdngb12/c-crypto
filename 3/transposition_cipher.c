#include <stdio.h>
#include <string.h>
#define BLOCK_SIZE 6

int main() {
    int i //Block Index
    , j
    , size, block_num;
    int key[64] = {3, 5, 1, 6, 4, 2};// Key
    char p_text[64], c_text[64], d_text[64];

    printf("Input Plain text\n");
    scanf("%s", p_text);

    size = strlen(p_text);

    if(size % BLOCK_SIZE > 0) { //평문이 블록의 크기와 맞지 않으면 임의의 문자 'x'를 추가한다.
        block_num = strlen(p_text) / BLOCK_SIZE + 1;

        for(i = strlen(p_text)/*End of Input String*/; i < block_num * BLOCK_SIZE/*End Of String*/; i++) {
            p_text[i] = 'x';
        }
    } else {
        block_num = strlen(p_text) / BLOCK_SIZE;
    }

    for(i = 0; i < block_num; i++) { //Block Index
        for(j = 0; j < BLOCK_SIZE; j++) { //Cipher Index
            c_text[i*BLOCK_SIZE + j/*암호문의 인덱스*/] = p_text[(key[j] - 1)/*원본 텍스트의 key Index*/ + i * BLOCK_SIZE/*Block Size*/];
        }
    }

    printf("Encrypt Data:\n");
    for(i = 0; i < block_num*BLOCK_SIZE; i++) {
        printf("%c",c_text[i]);
    }
    printf("\n");

    for(i = 0; i < block_num; i++) {
        for(j = 0; j < BLOCK_SIZE; j++) {
            d_text[(key[j] - 1)/*원본 텍스트의 key Index*/ + i * BLOCK_SIZE/*블록의 크기*/] = c_text[i*BLOCK_SIZE + j]/*현재 암호문의 값*/;
        }
    }
    printf("Decrypt Data:\n");
    for(int i = 0; i < size; i++) {
        printf("%c", d_text[i]);
    }
    printf("\n");
    return 0;
}