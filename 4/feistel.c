#include <stdio.h>
#define BLOCK_SIZE 6  // 블록크기(bit)
#define ROUND_NUM 2   // 라운드 수

char f1(char input);            // f, k1 함수
char f2(char input);            // f, k2 함수
char feistel_encrypt(char in);  // feistel 암호화 함수
char feistel_decrypt(char in);  // feistel 복호화 함수

int main() {
    char plain_bit = 0x2B;
    char cipher_bit, decrypt_bit;
    int temp = 0, i = 0;

    printf("* Plain text : ");
    for (i = BLOCK_SIZE - 1; i >= 0; i--) {
        temp = (plain_bit >> i) & 0x01;
        printf("%d ", temp);
    }
    printf("\n");

    cipher_bit = feistel_encrypt(plain_bit);

    printf("* Cipher text : ");
    for (i = BLOCK_SIZE - 1; i >= 0; i--) {
        temp = (cipher_bit >> i) & 0x01;
        printf("%d ", temp);
    }
    printf("\n");

    decrypt_bit = feistel_decrypt(cipher_bit);

    printf("* decrypt text : ");
    for (i = BLOCK_SIZE - 1; i >= 0; i--) {
        temp = (decrypt_bit >> i) & 0x01;
        printf("%d ", temp);
    }
    printf("\n");
    return 0;
}

char feistel_encrypt(char in) {
    int i;
    char temp, left, right;

    left = (in >> 3) & 0x07;
    right = in & 0x07;

    for (i = 0; i < ROUND_NUM; i++) {
        if(i == 0) { //암호화 첫번째 라운드 : f, k1
            left = left ^ f1(right);
        } else if(i == 1) {//암호화 두번째 라운드 : f, k2
            left = left ^ f2(right);
        }
        if(i != ROUND_NUM - 1) {//암호화 마지막 라운드가 아니라면 스왑 수행
            temp = left;
            left = right;
            right = temp;
        }
    }
    return (left << 3) | right;
}

char feistel_decrypt(char in) {
    int i;
    char temp, left, right;

    left = (in >> 3) & 0x07;
    right = in & 0x07;

    for (i = 0; i < ROUND_NUM; i++) {
        if(i == 0) { //복호화 첫번째 라운드 : f, k2
            left = left ^ f2(right);
        } else if(i == 1) {//암호화 두번째 라운드 : f, k1
            left = left ^ f1(right);
        }
        if(i != ROUND_NUM - 1) {//암호화 마지막 라운드가 아니라면 스왑 수행
            temp = left;
            left = right;
            right = temp;
        }
    }
    return (left << 3) | right;
}

char f1(char input) {
    if (input == 0x00) {
        return 0x05;
    } else if (input == 0x01) {
        return 0x02;
    } else if (input == 0x02) {
        return 0x03;
    } else if (input == 0x03) {
        return 0x06;
    } else if (input == 0x04) {
        return 0x04;
    } else if (input == 0x05) {
        return 0x01;
    } else if (input == 0x06) {
        return 0x07;
    } else if (input == 0x07) {
        return 0x00;
    }
    return 0;
}

char f2(char input) {
    if (input == 0x00) {
        return 0x04;
    } else if (input == 0x01) {
        return 0x00;
    } else if (input == 0x02) {
        return 0x03;
    } else if (input == 0x03) {
        return 0x07;
    } else if (input == 0x04) {
        return 0x06;
    } else if (input == 0x05) {
        return 0x05;
    } else if (input == 0x06) {
        return 0x01;
    } else if (input == 0x07) {
        return 0x02;
    }
    return 0;
}